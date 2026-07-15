// Forwarding-owned physical medium component. It exclusively owns PacketPool,
// TX and RX queues, serialization state and per-direction delivery deadlines.
// Protocol stacks exchange only encoded Frame values through this boundary.

#pragma once

#include "router/bounded_queue.hpp"
#include "router/generated_profile.hpp"
#include "router/link_direction.hpp"
#include "router/network.hpp"
#include "router/packet_pool.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>

namespace router::network_detail {

class LinkFabric final {
public:
  static constexpr std::size_t endpoint_count = network_endpoint_capacity;
  static constexpr std::size_t direction_count = endpoint_count * 2;
  // Direction IDs are compact capture and queue indices. Even values travel
  // toward the router and odd values toward their endpoint on the same link.
  static constexpr std::size_t to_router(std::size_t endpoint) noexcept {
    return endpoint * 2;
  }
  static constexpr std::size_t to_endpoint(std::size_t endpoint) noexcept {
    return endpoint * 2 + 1;
  }

  using FrameObserver = void (*)(void *context, std::size_t direction,
                                 const packet::Frame &frame);

  // false means pool or TX capacity exhausted. The caller converts it into an
  // explicit queue-full drop and must not retry through a direct delivery path.
  [[nodiscard]] bool enqueue(std::size_t direction,
                             const packet::Frame &frame) noexcept;
  // Propagation changes affect later admissions only. Already in-flight frames
  // retain deadlines calculated from the prior circuit value.
  void set_propagation(std::size_t endpoint,
                       std::chrono::nanoseconds value) noexcept;
  // pump_transmit transfers admitted handles from TX into the medium. Observer
  // runs synchronously on forwarding and must not retain frame references.
  void pump_transmit(void *context, FrameObserver observer) noexcept;
  // pump_delivery transfers due handles through RX, calls observer, then
  // releases pool ownership exactly once.
  void pump_delivery(void *context, FrameObserver observer) noexcept;
  // The earliest local medium deadline lets forwarding wait without a global
  // scheduler. nullopt means no direction owns an in-flight frame.
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point>
  next_delivery() const noexcept;

private:
  struct Direction {
    // Handle ownership moves TX -> LinkDirection -> RX. No protocol pointer or
    // mutable frame reference survives a method boundary.
    // TX and RX capacities come from the release profile. Tail drop is visible
    // as queue_full and never bypassed through immediate frame delivery.
    BoundedQueue<PacketHandle, profile::link_queue_capacity> tx;
    LinkDirection link{profile::port_bits_per_second,
                       profile::default_link_propagation};
    BoundedQueue<PacketHandle, profile::link_queue_capacity> rx;
  };

  PacketPool pool_;
  std::array<Direction, direction_count> directions_;
};

} // namespace router::network_detail
