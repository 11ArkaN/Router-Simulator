// Per-router control-owned IPv4 RIB and forwarding-owned immutable FIB. Values
// use generated multi-device capacities and contain no pointers into hardware,
// CLI or topology state.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace router::lab::routing {

[[nodiscard]] constexpr std::uint32_t ipv4(std::uint8_t a, std::uint8_t b,
                                           std::uint8_t c,
                                           std::uint8_t d) noexcept {
  return static_cast<std::uint32_t>(a) << 24 |
         static_cast<std::uint32_t>(b) << 16 |
         static_cast<std::uint32_t>(c) << 8 | d;
}

struct Route {
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint16_t port_ordinal{};
  std::uint8_t prefix_length{};
};

struct ConnectedInput {
  // operational already contains hardware, link, port and routed-interface
  // gates. The RIB cannot bypass those dependencies by reading topology itself.
  bool configured{};
  bool operational{};
  std::uint32_t network{};
  std::uint16_t port_ordinal{};
  std::uint8_t prefix_length{};
};

struct StaticInput {
  bool configured{};
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint8_t prefix_length{};
};

struct FibProgram {
  // Generation is compared by the forwarding owner before replacement. A
  // delayed older programming message cannot restore withdrawn routes.
  std::uint64_t generation{};
  std::array<Route, device_catalog::maximum_fib_routes_per_router> routes{};
  std::uint16_t count{};
};

class RouteTable final {
public:
  // false means the selected RIB is byte-for-byte unchanged. Invalid prefix
  // lengths and capacity overflow reject the entire rebuild without mutation.
  [[nodiscard]] bool rebuild(std::span<const ConnectedInput> connected,
                             std::span<const StaticInput> statics) noexcept;
  [[nodiscard]] FibProgram compile(std::uint64_t generation) const noexcept;
  [[nodiscard]] std::span<const Route> routes() const noexcept {
    return {routes_.data(), count_};
  }
  [[nodiscard]] bool last_rebuild_valid() const noexcept {
    return last_rebuild_valid_;
  }

private:
  std::array<Route, device_catalog::maximum_fib_routes_per_router> routes_{};
  std::uint16_t count_{};
  bool last_rebuild_valid_{true};
};

[[nodiscard]] constexpr std::uint32_t prefix_mask(
    std::uint8_t length) noexcept {
  // Shifting a 32-bit value by 32 is undefined, so the default route is an
  // explicit zero mask rather than relying on a compiler-specific result.
  return length ? 0xffffffffU << (32U - length) : 0U;
}

struct HostNextHopInput {
  // Named fields prevent accidentally exchanging destination and gateway in
  // an allocation-free RFC 1122 host route decision.
  std::uint32_t source{};
  std::uint8_t prefix_length{};
  std::uint32_t destination{};
  std::uint32_t gateway{};
};

[[nodiscard]] constexpr std::uint32_t
host_next_hop(HostNextHopInput input) noexcept {
  const auto mask = prefix_mask(input.prefix_length);
  return (input.source & mask) == (input.destination & mask)
             ? input.destination
             : input.gateway;
}

[[nodiscard]] bool lookup(const FibProgram &fib, std::uint32_t destination,
                          Route &selected) noexcept;

} // namespace router::lab::routing
