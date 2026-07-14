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
  void set_propagation(std::size_t endpoint,
                       std::chrono::nanoseconds value) noexcept;
  void pump_transmit(void *context, FrameObserver observer) noexcept;
  void pump_delivery(void *context, FrameObserver observer) noexcept;
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point>
  next_delivery() const noexcept;

private:
  struct Direction {
    // Handle ownership moves TX -> LinkDirection -> RX. No protocol pointer or
    // mutable frame reference survives a method boundary.
    BoundedQueue<PacketHandle, 256> tx;
    LinkDirection link{profile::port_bits_per_second,
                       profile::default_link_propagation};
    BoundedQueue<PacketHandle, 256> rx;
  };

  PacketPool pool_;
  std::array<Direction, direction_count> directions_;
};

} // namespace router::network_detail
