// Receipt-enabled local route publication from one protocol owner to one RIB
// owner. Fixed slots carry generations; a returned result acknowledges actual
// installation or explicit refusal. No ring contains a pointer or route table.

#pragma once

#include "router/owned_spsc_channel.hpp"
#include "router/route_generation.hpp"

namespace router::routing {
enum class RouteInstallStatus : std::uint8_t { pending, installed, stale, invalid, capacity, forwarding_failed };
struct RouteInstallReceipt {
  lab::DeviceHandle device{};
  std::uint64_t generation{};
  RouteInstallStatus status{RouteInstallStatus::pending};
};
template <std::size_t Capacity> class RoutePublicationChannel final {
  struct Publication { RouteGeneration routes; RouteInstallStatus status{RouteInstallStatus::pending}; };
  using Channel = protocol::OwnedSpscChannel<Publication, Capacity, true>;
public:
  using Handle = typename Channel::Handle;
  struct Writable { Handle handle{}; RouteGeneration *generation{}; };
  struct Borrowed { Handle handle{}; const RouteGeneration *generation{}; };
  // Exactly one protocol producer and one RIB consumer per channel. FIFO in
  // both directions, Capacity usable slots, release/acquire publication. Full
  // applies backpressure until the producer consumes an installation result.
  // All route storage is fixed and normally heap-owned by the channel aggregate.
  [[nodiscard]] std::optional<Writable> try_acquire() noexcept {
    const auto lease = channel_.acquire();
    return lease ? std::optional{Writable{lease->handle, &lease->value->routes}} : std::nullopt;
  }
  [[nodiscard]] bool publish(Handle handle) noexcept { return channel_.publish(handle); }
  [[nodiscard]] bool cancel(Handle handle) noexcept { return channel_.cancel(handle); }
  [[nodiscard]] std::optional<Borrowed> try_receive() noexcept {
    const auto lease = channel_.receive();
    if (!lease) return std::nullopt;
    borrowed_[lease->handle] = lease->value;
    return Borrowed{lease->handle, &lease->value->routes};
  }
  // Consumer only, after validating the complete generation and finishing the
  // real RIB/FIB transaction. Installed must never mean transfer-ring enqueue.
  // Expected identity guards delayed results across slot reuse. Unknown,
  // duplicate, mismatched or pending completion rejects without credit return.
  // Success ends the consumer's borrowed view and cannot be repeated.
  [[nodiscard]] bool complete(Handle handle, lab::DeviceHandle expected_device,
      std::uint64_t expected_generation, RouteInstallStatus status) noexcept {
    if (handle >= Capacity || !borrowed_[handle] || status == RouteInstallStatus::pending ||
        status > RouteInstallStatus::forwarding_failed) return false;
    auto &publication = *borrowed_[handle];
    if (publication.routes.device != expected_device || publication.routes.generation != expected_generation) return false;
    publication.status = status;
    if (!channel_.release(handle)) return false;
    borrowed_[handle] = nullptr;
    return true;
  }
  // Producer only. Copy the small final result before making the slot reusable;
  // no borrowed route view escapes and no result can be silently reclaimed.
  [[nodiscard]] std::optional<RouteInstallReceipt> try_completion() noexcept {
    const auto result = channel_.completion();
    return result ? std::optional{RouteInstallReceipt{result->value->routes.device,
        result->value->routes.generation, result->value->status}} : std::nullopt;
  }
private:
  Channel channel_;
  std::array<Publication *, Capacity> borrowed_{}; // consumer only
};
using RoutePublication = RoutePublicationChannel<2U>;
} // namespace router::routing
