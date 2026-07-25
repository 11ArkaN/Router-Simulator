// Complete OSPF route-generation transfer between the sole OSPF control
// producer and the sole network route-manager consumer. Route arrays remain in
// shared fixed slots while only compact handles cross the two SPSC rings.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/lab_registry.hpp"
#include "router/multi_device_routing.hpp"
#include "router/spsc_ring.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace router::ospf {

struct RouteGeneration {
  // The OSPF owner publishes all instances and areas for one router together.
  // The route manager must reject an older device generation or an incomplete
  // count before replacing its dynamic candidate set.
  lab::DeviceHandle device{};
  std::uint64_t generation{};
  std::array<lab::routing::DynamicInput,
             device_catalog::maximum_dynamic_routes_per_router>
      ipv4{};
  std::array<lab::routing::Ipv6DynamicInput,
             device_catalog::maximum_dynamic_routes_per_router>
      ipv6{};
  std::uint32_t ipv4_count{};
  std::uint32_t ipv6_count{};
};

template <std::size_t Capacity> class RouteGenerationChannel final {
  static_assert(Capacity > 0U);

public:
  using Handle = std::uint32_t;

  struct Writable {
    Handle handle{};
    RouteGeneration *generation{};
  };

  struct Borrowed {
    Handle handle{};
    const RouteGeneration *generation{};
  };

  RouteGenerationChannel() noexcept : available_count_(Capacity) {
    // Producer: OSPF control pthread. Consumer: network route-manager pthread.
    // Two slots allow one published generation and one generation being built.
    // Exhaustion is backpressure: the daemon retries without acknowledging its
    // local route generation as published.
    for (std::size_t index{}; index < Capacity; ++index)
      available_[index] = static_cast<Handle>(Capacity - index - 1U);
  }

  [[nodiscard]] std::optional<Writable> try_acquire() noexcept {
    reclaim();
    if (available_count_ == 0U)
      return std::nullopt;
    const auto handle = available_[--available_count_];
    slots_[handle] = {};
    return Writable{.handle = handle, .generation = &slots_[handle]};
  }

  [[nodiscard]] bool publish(Handle handle) noexcept {
    // Release publication makes every route byte immutable and visible before
    // the consumer observes the handle. Failure leaves ownership with the
    // producer, which must cancel the slot rather than modifying it in place.
    return handle < Capacity && ready_.try_push(handle);
  }

  [[nodiscard]] bool cancel(Handle handle) noexcept {
    if (handle >= Capacity || available_count_ >= Capacity)
      return false;
    available_[available_count_++] = handle;
    return true;
  }

  [[nodiscard]] std::optional<Borrowed> try_receive() noexcept {
    Handle handle{};
    if (!ready_.try_pop(handle))
      return std::nullopt;
    return Borrowed{.handle = handle, .generation = &slots_[handle]};
  }

  [[nodiscard]] bool release(Handle handle) noexcept {
    // The return ring has Capacity usable positions plus the SPSC sentinel.
    // Failure therefore identifies a double release or ownership violation,
    // never ordinary load shedding.
    return handle < Capacity && returned_.try_push(handle);
  }

private:
  void reclaim() noexcept {
    Handle handle{};
    while (returned_.try_pop(handle))
      available_[available_count_++] = handle;
  }

  std::array<RouteGeneration, Capacity> slots_{};
  SpscRing<Handle, Capacity + 1U> ready_;
  SpscRing<Handle, Capacity + 1U> returned_;
  std::array<Handle, Capacity> available_{};
  std::size_t available_count_{};
};

// One slot may be consumed while the next SPF result is assembled. Capacity is
// an inter-thread buffering policy, not a router or protocol scale limit.
using RouteChannel = RouteGenerationChannel<2U>;

} // namespace router::ospf
