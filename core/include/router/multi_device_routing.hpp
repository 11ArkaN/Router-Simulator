// Per-router control-owned IPv4 RIB and forwarding-owned immutable FIB. Values
// use generated multi-device capacities and contain no pointers into hardware,
// CLI or topology state.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/interface_identity.hpp"
#include "router/ip_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace router::lab::routing {

// Physical connected inputs occupy their hardware ordinals. The final slot is
// reserved for the router-owned system interface because that interface has no
// card, MDA, port, carrier or ARP adjacency. A named boundary prevents code
// from silently treating the loopback as physical port zero.
inline constexpr std::size_t system_ipv4_connected_index =
    device_catalog::maximum_ports_per_router;
inline constexpr std::size_t maximum_ipv4_connected_inputs =
    device_catalog::maximum_ports_per_router + 1U;

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
  // Preference and metric make equal-cost membership explicit at the
  // control-to-forwarding boundary. Forwarding never reconstructs route
  // selection policy from insertion order.
  std::uint16_t preference{};
  std::uint32_t metric{};
  enum class Source : std::uint8_t { connected, static_route, dynamic } source{};
  // The Base router system interface is a local /32 and has no physical
  // egress. This bit prevents its route from borrowing ordinal zero and being
  // forwarded or used to resolve a static next hop through unrelated hardware.
  bool local_system{};
};

struct ConnectedInput {
  // operational already contains hardware, link, port and routed-interface
  // gates. The RIB cannot bypass those dependencies by reading topology itself.
  bool configured{};
  bool operational{};
  std::uint32_t network{};
  std::uint16_t port_ordinal{};
  std::uint8_t prefix_length{};
  // true identifies the immutable-name `system` loopback. It is operational
  // independently of carrier and must use /32 in the SR OS 26.7 profile.
  bool local_system{};
};

struct StaticInput {
  bool configured{};
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint8_t prefix_length{};
  // SR OS treats a directly connected next hop and an indirect next hop as
  // separate children. An indirect address may be resolved only by a dynamic
  // route, never by another static route.
  bool indirect{};
};

struct DynamicInput {
  // Protocol daemons publish selected adjacency-resolved candidates through
  // this boundary. The protocol remains owner of its database and timers.
  bool configured{};
  bool operational{};
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint16_t port_ordinal{};
  std::uint16_t preference{};
  std::uint32_t metric{};
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
                             std::span<const StaticInput> statics,
                             std::span<const DynamicInput> dynamic = {},
                             std::uint16_t maximum_ecmp_paths = 1U) noexcept;
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
                          Route &selected,
                          std::uint64_t flow_hash = 0U) noexcept;

struct Ipv6Route {
  // The logical interface scopes RFC 4007 state. The physical ordinal selects
  // only the final hardware egress. Keeping both values makes multiple SAPs
  // on one port routable without collapsing their neighbor zones.
  ip::Ipv6 network{};
  ip::Ipv6 next_hop{};
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  std::uint8_t prefix_length{};
  std::uint16_t preference{};
  std::uint32_t metric{};
  Route::Source source{};
};

struct Ipv6ConnectedInput {
  // operational already combines chassis, card, MDA, port, link and interface
  // gates. The route owner cannot inspect another module to repair false input.
  bool configured{};
  bool operational{};
  ip::Ipv6 network{};
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  std::uint8_t prefix_length{};
};

struct Ipv6StaticInput {
  // RFC 4007 requires an explicit zone for link-local next hops. The caller
  // records that zone as an outgoing physical port after resolving the stable
  // interface identity inside the router's own configuration owner.
  bool configured{};
  bool indirect{};
  bool outgoing_interface_set{};
  ip::Ipv6 network{};
  ip::Ipv6 next_hop{};
  std::uint64_t outgoing_interface_id{};
  std::uint8_t prefix_length{};
};

struct Ipv6DynamicInput {
  bool configured{};
  bool operational{};
  ip::Ipv6 network{};
  ip::Ipv6 next_hop{};
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  std::uint16_t preference{};
  std::uint32_t metric{};
  std::uint8_t prefix_length{};
};

struct Ipv6FibProgram {
  std::uint64_t generation{};
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router> routes{};
  std::uint16_t count{};
};

class Ipv6RouteTable final {
public:
  // Rebuild validates the complete candidate before publication. false may
  // mean unchanged or rejected, so callers must inspect last_rebuild_valid()
  // before deciding whether a programming message is required.
  [[nodiscard]] bool
  rebuild(std::span<const Ipv6ConnectedInput> connected,
          std::span<const Ipv6StaticInput> statics,
          std::span<const Ipv6ConnectedInput> additional_connected = {},
          std::span<const Ipv6DynamicInput> dynamic = {},
          std::uint16_t maximum_ecmp_paths = 1U)
      noexcept;
  [[nodiscard]] Ipv6FibProgram compile(std::uint64_t generation) const noexcept;
  [[nodiscard]] std::span<const Ipv6Route> routes() const noexcept {
    return {routes_.data(), count_};
  }
  [[nodiscard]] bool last_rebuild_valid() const noexcept {
    return last_rebuild_valid_;
  }

private:
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router> routes_{};
  std::uint16_t count_{};
  bool last_rebuild_valid_{true};
};

[[nodiscard]] bool lookup(const Ipv6FibProgram &fib,
                          const ip::Ipv6 &destination,
                          Ipv6Route &selected,
                          std::uint64_t flow_hash = 0U) noexcept;

} // namespace router::lab::routing
