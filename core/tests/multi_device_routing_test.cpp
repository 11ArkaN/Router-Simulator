// Multi-device routing tests protect local next-hop resolution, longest-prefix
// lookup, withdrawal and atomic rejection independently from the lab graph.

#include "router/multi_device_routing.hpp"

#include <array>
#include <memory>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  // The module runner reports the first RIB or FIB contract violation.
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void multi_device_routing_tests() {
  using namespace router::lab::routing;
  const std::array connected{
      ConnectedInput{true, true, 0x0a000000U, 4, 24},
      ConnectedInput{true, true, 0x0a000180U, 7, 25}};
  const std::array statics{
      StaticInput{true, 0xc0000200U, 0x0a000001U, 24},
      StaticInput{true, 0xc6336400U, 0x0a000181U, 24},
      StaticInput{true, 0xcb007100U, 0xac100001U, 24}};

  // Route tables deliberately own bounded scratch arrays. Heap allocation in
  // this all-in-one test keeps those production capacities from consuming the
  // small WebAssembly call stack merely because several independent cases
  // remain live in one C++ function.
  auto rib = std::make_unique<RouteTable>();
  require(rib->rebuild(connected, statics) && rib->last_rebuild_valid(),
          "RIB rejected valid connected and static routes");
  const auto fib = rib->compile(9);
  // The third static route remains configured but inactive because no local
  // connected interface can resolve its next-hop address.
  require(fib.generation == 9 && fib.count == 4,
          "RIB programmed unresolved static route");
  Route selected;
  require(lookup(fib, 0xc6336401U, selected) &&
              selected.port_ordinal == 7 &&
              selected.next_hop == 0x0a000181U,
          "static next hop ignored longest connected resolution");
  require(lookup(fib, 0x0a000190U, selected) &&
              selected.port_ordinal == 7 && selected.prefix_length == 25,
          "FIB lookup did not select longest destination prefix");

  // Two direct static candidates for one prefix remain distinct in intent.
  // With ECMP disabled the documented lowest next-hop wins. Enabling width two
  // publishes both and a stable flow hash selects the same member repeatedly.
  const std::array ecmp_connected{
      ConnectedInput{true, true, 0x0a000000U, 4, 24},
      ConnectedInput{true, true, 0x0a000100U, 7, 24}};
  const std::array ecmp_statics{
      StaticInput{true, 0xcb007100U, 0x0a000102U, 24},
      StaticInput{true, 0xcb007100U, 0x0a000002U, 24}};
  auto ecmp_rib = std::make_unique<RouteTable>();
  require(ecmp_rib->rebuild(ecmp_connected, ecmp_statics),
          "disabled ECMP rejected equal static candidates");
  const auto single_path = ecmp_rib->compile(30U);
  require(single_path.count == 3U &&
              lookup(single_path, 0xcb007155U, selected, 9U) &&
              selected.next_hop == 0x0a000002U,
          "disabled ECMP did not keep the lowest static next hop");
  require(ecmp_rib->rebuild(ecmp_connected, ecmp_statics, {}, 2U),
          "enabled ECMP did not change the selected RIB");
  const auto two_paths = ecmp_rib->compile(31U);
  Route first_flow;
  Route second_flow;
  require(two_paths.count == 4U &&
              lookup(two_paths, 0xcb007155U, first_flow, 0U) &&
              lookup(two_paths, 0xcb007155U, second_flow, 1U) &&
              first_flow.next_hop != second_flow.next_hop &&
              lookup(two_paths, 0xcb007155U, selected, 1U) &&
              selected.next_hop == second_flow.next_hop,
          "ECMP did not select stable distinct paths by flow hash");

  // An indirect static route may recurse through dynamic protocol output but
  // never through another static route. Equal dynamic resolvers are expanded
  // into the static destination's own ECMP group.
  const std::array dynamic{
      DynamicInput{true, true, 0x0a00ff00U, 0x0a000002U, 4, 10, 20, 24},
      DynamicInput{true, true, 0x0a00ff00U, 0x0a000102U, 7, 10, 20, 24}};
  const std::array indirect{
      StaticInput{.configured = true,
                  .network = 0xc6336400U,
                  .next_hop = 0x0a00ff01U,
                  .prefix_length = 24U,
                  .indirect = true}};
  auto indirect_rib = std::make_unique<RouteTable>();
  require(indirect_rib->rebuild(ecmp_connected, indirect, dynamic, 2U),
          "indirect static route rejected dynamic resolvers");
  const auto indirect_fib = indirect_rib->compile(32U);
  require(lookup(indirect_fib, 0xc6336401U, first_flow, 0U) &&
              lookup(indirect_fib, 0xc6336401U, second_flow, 1U) &&
              first_flow.next_hop != second_flow.next_hop,
          "indirect static route lost equal dynamic resolver paths");
  require(indirect_rib->rebuild(ecmp_connected, indirect, {}, 2U) &&
              !lookup(indirect_rib->compile(33U), 0xc6336401U, selected),
          "indirect static route resolved without a dynamic protocol route");

  // OSPF path class precedes numeric cost. An intra-area route therefore wins
  // over a numerically cheaper inter-area route. Type 2 external candidates
  // compare their external metric first and internal cost to the ASBR second;
  // only equal winners may form ECMP.
  const std::array ospf_candidates{
      DynamicInput{.configured = true,
                   .operational = true,
                   .network = 0xac100000U,
                   .next_hop = 0x0a000002U,
                   .port_ordinal = 4U,
                   .preference = 10U,
                   .metric = 30U,
                   .prefix_length = 16U,
                   .source = RouteSource::ospf,
                   .ospf_path_type = OspfPathType::intra_area},
      DynamicInput{.configured = true,
                   .operational = true,
                   .network = 0xac100000U,
                   .next_hop = 0x0a000102U,
                   .port_ordinal = 7U,
                   .preference = 10U,
                   .metric = 5U,
                   .prefix_length = 16U,
                   .source = RouteSource::ospf,
                   .ospf_path_type = OspfPathType::inter_area},
      DynamicInput{.configured = true,
                   .operational = true,
                   .network = 0xcb007100U,
                   .next_hop = 0x0a000002U,
                   .port_ordinal = 4U,
                   .preference = 10U,
                   .metric = 50U,
                   .prefix_length = 24U,
                   .source = RouteSource::ospf,
                   .ospf_path_type = OspfPathType::external_type_2,
                   .internal_metric = 20U},
      DynamicInput{.configured = true,
                   .operational = true,
                   .network = 0xcb007100U,
                   .next_hop = 0x0a000102U,
                   .port_ordinal = 7U,
                   .preference = 10U,
                   .metric = 50U,
                   .prefix_length = 24U,
                   .source = RouteSource::ospf,
                   .ospf_path_type = OspfPathType::external_type_2,
                   .internal_metric = 10U}};
  auto ospf_rib = std::make_unique<RouteTable>();
  require(ospf_rib->rebuild(ecmp_connected, {}, ospf_candidates, 2U),
          "RIB rejected valid OSPF route candidates");
  const auto ospf_fib = ospf_rib->compile(34U);
  require(lookup(ospf_fib, 0xac100001U, selected) &&
              selected.ospf_path_type == OspfPathType::intra_area &&
              selected.metric == 30U &&
              lookup(ospf_fib, 0xcb007101U, selected) &&
              selected.next_hop == 0x0a000102U,
          "RIB violated OSPF path or Type 2 selection order");

  // A longer RFC 5286 repair remains outside the primary ECMP set. The
  // contiguous FIB image records it only after the selected primary entries,
  // and an explicit repair lookup is required to make it eligible.
  const std::array protected_ospf{
      DynamicInput{.configured = true,
                   .operational = true,
                   .network = 0xc6120000U,
                   .next_hop = 0x0a000002U,
                   .port_ordinal = 4U,
                   .preference = 10U,
                   .metric = 20U,
                   .prefix_length = 16U,
                   .source = RouteSource::ospf,
                   .ospf_path_type = OspfPathType::intra_area},
      DynamicInput{.configured = true,
                   .operational = true,
                   .network = 0xc6120000U,
                   .next_hop = 0x0a000102U,
                   .port_ordinal = 7U,
                   .preference = 10U,
                   .metric = 30U,
                   .prefix_length = 16U,
                   .source = RouteSource::ospf,
                   .ospf_path_type = OspfPathType::intra_area,
                   .loop_free_alternate = true}};
  auto protected_rib = std::make_unique<RouteTable>();
  require(protected_rib->rebuild(ecmp_connected, {}, protected_ospf, 2U),
          "RIB rejected an OSPF route with a loop-free repair");
  const auto protected_fib = protected_rib->compile(35U);
  Route repair;
  require(protected_fib.loop_free_alternate_count == 1U &&
              lookup(protected_fib, 0xc6120001U, selected) &&
              selected.next_hop == 0x0a000002U &&
              lookup_loop_free_alternate(protected_fib, 0xc6120001U,
                                         repair) &&
              repair.next_hop == 0x0a000102U,
          "LFA entered primary ECMP or was absent from its repair table");

  auto failed = connected;
  failed[1].operational = false;
  require(rib->rebuild(failed, statics),
          "RIB did not withdraw routes after local interface failure");
  const auto withdrawn = rib->compile(10);
  require(withdrawn.count == 2 &&
              !lookup(withdrawn, 0xc6336401U, selected),
          "failed local interface retained dependent static route");

  const std::array invalid{ConnectedInput{true, true, 0, 0, 33}};
  const auto before = rib->compile(10);
  require(!rib->rebuild(invalid, std::span<const StaticInput>{}) &&
              !rib->last_rebuild_valid() &&
              rib->compile(11).count == before.count,
          "invalid rebuild partially mutated selected RIB");

  // The system interface contributes one local host route without consuming a
  // physical ordinal. It must not resolve a static next hop, because doing so
  // would invent an Ethernet adjacency for a router-local address.
  const std::array system_connected{
      ConnectedInput{.configured = true,
                     .operational = true,
                     .network = 0x0a00ff01U,
                     .prefix_length = 32U,
                     .local_system = true}};
  const std::array through_system{
      StaticInput{.configured = true,
                  .network = 0xcb007100U,
                  .next_hop = 0x0a00ff01U,
                  .prefix_length = 24U}};
  auto system_rib = std::make_unique<RouteTable>();
  require(system_rib->rebuild(system_connected, through_system) &&
              system_rib->last_rebuild_valid(),
          "system /32 was rejected as a local connected input");
  const auto system_fib = system_rib->compile(12U);
  require(system_fib.count == 1U &&
              lookup(system_fib, 0x0a00ff01U, selected) &&
              selected.local_system && selected.prefix_length == 32U,
          "system interface did not compile as a local /32");
  auto invalid_system = system_connected;
  invalid_system[0].prefix_length = 31U;
  require(!system_rib->rebuild(invalid_system, through_system) &&
              !system_rib->last_rebuild_valid(),
          "system interface accepted a non-host prefix");

  const auto address = [](const char *text) {
    const auto parsed = router::ip::parse_ipv6(text);
    if (!parsed)
      throw std::runtime_error("IPv6 routing test address is invalid");
    return *parsed;
  };
  const std::array connected6{
      Ipv6ConnectedInput{.configured = true,
                         .operational = true,
                         .network = address("2001:db8:1::"),
                         .interface_id = 50'004U,
                         .physical_port_ordinal = 4,
                         .prefix_length = 64},
      Ipv6ConnectedInput{.configured = true,
                         .operational = true,
                         .network = address("2001:db8:1:1::"),
                         .interface_id = 50'007U,
                         .physical_port_ordinal = 7,
                         .prefix_length = 64}};
  const std::array statics6{
      Ipv6StaticInput{.configured = true,
                      .network = address("2001:db8:100::"),
                      .next_hop = address("2001:db8:1::2"),
                      .prefix_length = 64},
      Ipv6StaticInput{.configured = true,
                      .outgoing_interface_set = true,
                      .network = address("::"),
                      .next_hop = address("fe80::2"),
                      .outgoing_interface_id = 50'007U,
                      .prefix_length = 0},
      Ipv6StaticInput{.configured = true,
                      .network = address("2001:db8:200::"),
                      .next_hop = address("2001:db8:ffff::1"),
                      .prefix_length = 64}};

  auto rib6 = std::make_unique<Ipv6RouteTable>();
  require(rib6->rebuild(connected6, statics6) && rib6->last_rebuild_valid(),
          "IPv6 RIB rejected valid connected and static routes");
  const auto fib6 = rib6->compile(19);
  require(fib6.generation == 19 && fib6.count == 4,
          "IPv6 RIB programmed unresolved static route");
  Ipv6Route selected6;
  require(lookup(fib6, address("2001:db8:100::55"), selected6) &&
              selected6.interface_id == 50'004U &&
              selected6.physical_port_ordinal == 4 &&
              selected6.next_hop == address("2001:db8:1::2"),
          "IPv6 static next hop did not use local connected resolution");
  require(lookup(fib6, address("2001:db8:ffff::55"), selected6) &&
              selected6.interface_id == 50'007U &&
              selected6.physical_port_ordinal == 7 &&
              selected6.next_hop == address("fe80::2") &&
              selected6.prefix_length == 0,
          "IPv6 default route lost its link-local scope");

  const std::array ecmp_statics6{
      Ipv6StaticInput{.configured = true,
                      .network = address("2001:db8:300::"),
                      .next_hop = address("2001:db8:1::2"),
                      .prefix_length = 64},
      Ipv6StaticInput{.configured = true,
                      .network = address("2001:db8:300::"),
                      .next_hop = address("2001:db8:1:1::2"),
                      .prefix_length = 64}};
  auto ecmp_rib6 = std::make_unique<Ipv6RouteTable>();
  require(ecmp_rib6->rebuild(connected6, ecmp_statics6, {}, {}, 2U),
          "IPv6 ECMP rejected equal static candidates");
  const auto ecmp_fib6 = ecmp_rib6->compile(34U);
  Ipv6Route first_flow6;
  Ipv6Route second_flow6;
  require(lookup(ecmp_fib6, address("2001:db8:300::1"), first_flow6, 0U) &&
              lookup(ecmp_fib6, address("2001:db8:300::1"), second_flow6, 1U) &&
              first_flow6.next_hop != second_flow6.next_hop,
          "IPv6 ECMP did not expose both flow-selected next hops");

  auto invalid_link_local = statics6;
  invalid_link_local[1].outgoing_interface_set = false;
  const auto before6 = rib6->compile(19);
  require(!rib6->rebuild(connected6, invalid_link_local) &&
              !rib6->last_rebuild_valid() &&
              rib6->compile(20).count == before6.count,
          "unscoped IPv6 link-local next hop mutated the RIB");

  auto failed6 = connected6;
  failed6[0].operational = false;
  require(rib6->rebuild(failed6, statics6),
          "IPv6 RIB did not react to local interface failure");
  const auto withdrawn6 = rib6->compile(21);
  require(lookup(withdrawn6, address("2001:db8:100::55"), selected6) &&
              selected6.prefix_length == 0 &&
              selected6.next_hop == address("fe80::2"),
          "IPv6 interface failure did not withdraw to the default route");
}
