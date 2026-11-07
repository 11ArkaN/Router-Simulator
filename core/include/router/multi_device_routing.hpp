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

// The protocol identity crosses the RIB-to-FIB boundary. Collapsing OSPFv2
// and OSPFv3 into a generic dynamic value would make administrative selection,
// route inspection and later policy evaluation depend on hidden side state.
enum class RouteSource : std::uint8_t {
  connected,
  static_route,
  ospf,
  ospf3,
  isis
};

// RFC 2328 section 16.4 defines an ordering between OSPF path classes that is
// independent of the numeric cost. NSSA origins remain explicit so translation
// and route policy never have to infer them from an already flattened metric.
enum class OspfPathType : std::uint8_t {
  none,
  intra_area,
  inter_area,
  external_type_1,
  external_type_2,
  nssa_type_1,
  nssa_type_2
};

// IS-IS provenance remains independent from OSPF path types. The protocol
// owner supplies the normative prefix-distance rank before RIB selection.
enum class IsisPathType : std::uint8_t {
  none, level1_internal, level2_internal, level1_external, level2_external
};

// Pure provenance validation shared by RIB admission and checkpoint decoding.
// No state or allocation. false rejects mixed protocol fields and invalid
// family/level/class ranks before a route generation can be published.
[[nodiscard]] constexpr bool valid_route_path(RouteSource source, OspfPathType ospf,
    IsisPathType isis, std::uint8_t rank, bool ipv6) noexcept {
  if (source == RouteSource::connected || source == RouteSource::static_route)
    return ospf == OspfPathType::none && isis == IsisPathType::none && !rank;
  if (source != RouteSource::isis)
    return (source == RouteSource::ospf || source == RouteSource::ospf3) && ospf != OspfPathType::none &&
        ospf <= OspfPathType::nssa_type_2 && isis == IsisPathType::none && !rank;
  if (ospf != OspfPathType::none || isis == IsisPathType::none ||
      isis > IsisPathType::level2_external) return false;
  const bool level1 = isis == IsisPathType::level1_internal || isis == IsisPathType::level1_external;
  const bool external = isis == IsisPathType::level1_external || isis == IsisPathType::level2_external;
  if (ipv6) return level1 ? rank == 0U || rank == 3U : rank == 1U || rank == 2U;
  return level1 ? rank == 0U || rank == 2U || (external && (rank == 3U || rank == 5U))
                : rank == 1U || (external && rank == 4U);
}

[[nodiscard]] constexpr bool dynamic_source(RouteSource source) noexcept {
  return source == RouteSource::ospf || source == RouteSource::ospf3 || source == RouteSource::isis;
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
  RouteSource source{};
  // The Base router system interface is a local /32 and has no physical
  // egress. This bit prevents its route from borrowing ordinal zero and being
  // forwarded or used to resolve a static next hop through unrelated hardware.
  bool local_system{};
  OspfPathType ospf_path_type{OspfPathType::none};
  std::uint8_t protocol_instance{};

  // Stable logical scope accompanies physical egress, including unnumbered links.
  std::uint64_t interface_id{};
  IsisPathType isis_path_type{IsisPathType::none};
  std::uint8_t isis_rank{};
  std::uint64_t interface_generation{};
  // Complete value equality keeps generation replay checks aligned with every field.
  bool operator==(const Route &) const = default;
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
  std::uint64_t interface_id{};
  std::uint64_t interface_generation{};
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
  RouteSource source{RouteSource::ospf};
  OspfPathType ospf_path_type{OspfPathType::intra_area};
  std::uint32_t internal_metric{};
  std::uint32_t area_id{};
  std::uint32_t tag{};
  std::uint8_t protocol_instance{};
  // RFC 5286 repair next hops are retained outside the normal ECMP set. They
  // become eligible only after forwarding observes that the primary egress is
  // unavailable, so a longer alternate cannot carry ordinary steady traffic.
  bool loop_free_alternate{};
  // Stable logical scope accompanies physical egress, including unnumbered links.
  std::uint64_t interface_id{};
  IsisPathType isis_path_type{IsisPathType::none};
  std::uint8_t isis_rank{};
  std::uint64_t interface_generation{};
};

struct FibProgram {
  // Generation is compared by the forwarding owner before replacement. A
  // delayed older programming message cannot restore withdrawn routes.
  std::uint64_t generation{};
  // Primary routes occupy [0, count); RFC 5286 repair entries immediately
  // follow them. Both classes consume the same generated hardware FIB budget,
  // which avoids inventing a second hidden route resource for backups.
  std::array<Route, device_catalog::maximum_fib_routes_per_router> routes{};
  std::uint16_t count{};
  std::uint16_t loop_free_alternate_count{};
};

class RouteTable final {
public:
  // Both dynamic spans are immutable owner-retained generations and share the
  // generated total route budget. An empty span withdraws only its own input.
  // false means the selected RIB is byte-for-byte unchanged. Invalid prefix
  // lengths and capacity overflow reject the entire rebuild without mutation.
  [[nodiscard]] bool rebuild(std::span<const ConnectedInput> connected,
                             std::span<const StaticInput> statics,
                             std::span<const DynamicInput> dynamic = {},
                             std::uint16_t maximum_ecmp_paths = 1U,
                             std::span<const DynamicInput> additional_dynamic = {}) noexcept;
  [[nodiscard]] FibProgram compile(std::uint64_t generation) const noexcept;
  // Same owner, exclusive caller-owned output. Copies the complete published
  // selection and zeros unused rows without a profile-sized return temporary.
  // No allocation, borrowing, refusal or mutation of the RIB occurs.
  void compile_into(FibProgram &output, std::uint64_t generation) const noexcept;
  [[nodiscard]] std::span<const Route> routes() const noexcept {
    return {routes_.data(), count_};
  }
  // Same-owner comparison of complete active and repair selections.
  [[nodiscard]] bool same_selection(const RouteTable &other) const noexcept;
  [[nodiscard]] bool last_rebuild_valid() const noexcept {
    return last_rebuild_valid_;
  }

private:
  std::array<Route, device_catalog::maximum_fib_routes_per_router> routes_{};
  std::array<Route, device_catalog::maximum_fib_routes_per_router>
      loop_free_alternates_{};
  std::uint16_t count_{};
  std::uint16_t loop_free_alternate_count_{};
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
[[nodiscard]] bool
lookup_loop_free_alternate(const FibProgram &fib, std::uint32_t destination,
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
  RouteSource source{};
  OspfPathType ospf_path_type{OspfPathType::none};
  std::uint8_t protocol_instance{};

  IsisPathType isis_path_type{IsisPathType::none};
  std::uint8_t isis_rank{};
  std::uint64_t interface_generation{};
  // Complete value equality keeps generation replay checks aligned with every field.
  bool operator==(const Ipv6Route &) const = default;
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
  std::uint64_t interface_generation{};
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
  RouteSource source{RouteSource::ospf3};
  OspfPathType ospf_path_type{OspfPathType::intra_area};
  std::uint32_t internal_metric{};
  std::uint32_t area_id{};
  std::uint32_t tag{};
  std::uint8_t protocol_instance{};
  bool loop_free_alternate{};
  IsisPathType isis_path_type{IsisPathType::none};
  std::uint8_t isis_rank{};
  std::uint64_t interface_generation{};
};

struct Ipv6FibProgram {
  std::uint64_t generation{};
  // IPv6 uses the same contiguous primary-then-repair ownership contract as
  // IPv4. Checkpoint and forwarding code can therefore validate one capacity.
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router> routes{};
  std::uint16_t count{};
  std::uint16_t loop_free_alternate_count{};
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
          std::uint16_t maximum_ecmp_paths = 1U,
          std::span<const Ipv6DynamicInput> additional_dynamic = {})
      noexcept;
  [[nodiscard]] Ipv6FibProgram compile(std::uint64_t generation) const noexcept;
  // Same owner and exclusive output, as IPv4 compile_into. Unused rows are
  // cleared so a reused transfer arena cannot expose withdrawn route values.
  void compile_into(Ipv6FibProgram &output, std::uint64_t generation) const noexcept;
  [[nodiscard]] std::span<const Ipv6Route> routes() const noexcept {
    return {routes_.data(), count_};
  }
  // Includes repair paths; staged rebuild history is deliberately irrelevant.
  [[nodiscard]] bool same_selection(const Ipv6RouteTable &other) const noexcept;
  [[nodiscard]] bool last_rebuild_valid() const noexcept {
    return last_rebuild_valid_;
  }

private:
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router> routes_{};
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router>
      loop_free_alternates_{};
  std::uint16_t count_{};
  std::uint16_t loop_free_alternate_count_{};
  bool last_rebuild_valid_{true};
};

[[nodiscard]] bool lookup(const Ipv6FibProgram &fib,
                          const ip::Ipv6 &destination,
                          Ipv6Route &selected,
                          std::uint64_t flow_hash = 0U) noexcept;
[[nodiscard]] bool lookup_loop_free_alternate(
    const Ipv6FibProgram &fib, const ip::Ipv6 &destination,
    Ipv6Route &selected, std::uint64_t flow_hash = 0U) noexcept;

} // namespace router::lab::routing
