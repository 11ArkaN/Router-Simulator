// The router-owned RIB prunes IS-IS distance classes before comparing protocol
// preferences. Fixtures own resolved values and verify complete scoped results;
// no packet, adjacency or foreign-router shortcut is manufactured by the RIB.

#include "router/multi_device_routing.hpp"
#include "router/isis_rib_input.hpp"
#include "router/route_input_store.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
using namespace router;
using namespace router::lab::routing;
void require(bool value) {
  if (!value) throw std::runtime_error("IS-IS shared RIB selection invariant failed");
}
DynamicInput route4() {
  return {.configured = true, .operational = true, .network = 0xc6336400U,
      .next_hop = 0xc0000202U, .port_ordinal = 1U, .preference = 15U,
      .metric = 10U, .prefix_length = 24U, .source = RouteSource::isis,
      .ospf_path_type = OspfPathType::none, .interface_id = 42U,
      .isis_path_type = IsisPathType::level1_internal, .isis_rank = 0U,
      .interface_generation = 17U};
}
Ipv6DynamicInput route6() {
  return {.configured = true, .operational = true, .network = *ip::parse_ipv6("2001:db8:1::"),
      .next_hop = *ip::parse_ipv6("fe80::2"), .interface_id = 42U,
      .physical_port_ordinal = 1U, .preference = 15U, .metric = 10U,
      .prefix_length = 64U, .source = RouteSource::isis, .ospf_path_type = OspfPathType::none,
      .isis_path_type = IsisPathType::level1_internal, .isis_rank = 0U,
      .interface_generation = 17U};
}
}
void isis_rib_tests() {
  ::router::routing::RouteInputStore<DynamicInput> retained;
  std::array initial_first{route4()};
  std::array initial_second{route4(), route4()};
  initial_second[0U].metric = 17U;
  initial_second[1U].metric = 18U;
  require(retained.replace_first(initial_first) && retained.replace_second(initial_second));
  std::array larger_first{route4(), route4(), route4()};
  require(retained.replace_first(larger_first) && retained.first().size() == 3U &&
      retained.second().size() == 2U && retained.second()[0U].metric == 17U && retained.second()[1U].metric == 18U);
  require(retained.replace_first(initial_first) && retained.first().size() == 1U &&
      retained.second()[0U].metric == 17U && retained.second()[1U].metric == 18U);
  std::vector<DynamicInput> oversized(device_catalog::maximum_dynamic_routes_per_router);
  require(!retained.replace_first(oversized) && !retained.replace_second(oversized) &&
      retained.first().size() == 1U && retained.second().size() == 2U && retained.second()[1U].metric == 18U);
  require(retained.replace_first({}) && retained.first().empty() && retained.second()[0U].metric == 17U);
  require(retained.replace_second({}) && retained.first().empty() && retained.second().empty());
  isis::PrefixRouteCandidate candidate;
  candidate.destination = *ip::parse_ip_prefix("2001:db8:1::/64");
  candidate.distance = {2U, 42U, 0U};
  candidate.next_hop = {{42U, 17U, 1U}, {}, *ip::parse_ip_address("fe80::2"), 2U};
  candidate.down = candidate.external = true;
  const auto mapped = isis::make_ipv6_rib_input(candidate, 127U, 255U);
  require(mapped && mapped->source == RouteSource::isis && mapped->isis_path_type == IsisPathType::level2_external &&
      mapped->isis_rank == 2U && mapped->metric == 42U && mapped->interface_id == 42U &&
      mapped->interface_generation == 17U && mapped->protocol_instance == 127U && mapped->preference == 255U);
  require(!isis::make_ipv6_rib_input(candidate, 128U, 15U) &&
      !isis::make_ipv6_rib_input(candidate, 0U, 0U) && !isis::make_ipv6_rib_input(candidate, 0U, 256U));
  candidate.down = false;
  require(!isis::make_ipv6_rib_input(candidate, 0U, 15U));
  candidate.down = true;
  candidate.next_hop.address = *ip::parse_ip_address("2001:db8::2");
  require(!isis::make_ipv6_rib_input(candidate, 0U, 15U));
  candidate.destination = *ip::parse_ip_prefix("198.51.100.0/24");
  candidate.next_hop.address = *ip::parse_ip_address("192.0.2.2");
  candidate.next_hop.level = 1U;
  candidate.distance = {5U, 63U, 1023U};
  const auto narrow = isis::make_ipv4_rib_input(candidate, 7U, 160U);
  require(narrow && narrow->metric == 63U && narrow->internal_metric == 1023U &&
      narrow->isis_path_type == IsisPathType::level1_external && narrow->isis_rank == 5U);
  candidate.distance.metric = 64U;
  require(!isis::make_ipv4_rib_input(candidate, 7U, 160U));
  candidate.distance.metric = 63U;
  candidate.next_hop.interface.configuration_generation = 0U;
  require(!isis::make_ipv4_rib_input(candidate, 7U, 160U));
  auto ipv4 = std::make_unique<RouteTable>();
  auto ipv6 = std::make_unique<Ipv6RouteTable>();
  auto fib4 = std::make_unique<FibProgram>();
  auto fib6 = std::make_unique<Ipv6FibProgram>();
  std::array paths4{route4(), route4()};
  paths4[1U].interface_id = 43U;
  paths4[1U].interface_generation = 18U;
  require(ipv4->rebuild({}, {}, paths4, 2U));
  ipv4->compile_into(*fib4, 1U);
  require(fib4->count == 2U && fib4->routes[0U].source == RouteSource::isis &&
      fib4->routes[0U].ospf_path_type == OspfPathType::none &&
      fib4->routes[0U].interface_id == 42U && fib4->routes[1U].interface_id == 43U &&
      fib4->routes[1U].interface_generation == 18U);
  // A malformed second input cannot replace the prior complete scoped FIB.
  paths4[1U].interface_generation = 0U;
  require(!ipv4->rebuild({}, {}, paths4, 2U) && !ipv4->last_rebuild_valid());
  ipv4->compile_into(*fib4, 1U);
  require(fib4->count == 2U && fib4->routes[1U].interface_generation == 18U);
  paths4[1U] = route4();
  paths4[1U].isis_rank = 3U;
  require(!ipv4->rebuild({}, {}, paths4) && !ipv4->last_rebuild_valid());
  paths4[1U] = route4();
  paths4[1U].source = RouteSource::ospf;
  paths4[1U].ospf_path_type = OspfPathType::intra_area;
  require(!ipv4->rebuild({}, {}, paths4) && !ipv4->last_rebuild_valid());

  // The pinned IS-IS model admits preferences 1 through 255, including 255.
  for (const auto preference : {0U, 256U}) {
    auto invalid4 = route4();
    auto invalid6 = route6();
    invalid4.preference = static_cast<std::uint16_t>(preference);
    invalid6.preference = static_cast<std::uint16_t>(preference);
    require(!ipv4->rebuild({}, {}, std::span{&invalid4, 1U}) && !ipv4->last_rebuild_valid());
    require(!ipv6->rebuild({}, {}, {}, std::span{&invalid6, 1U}) && !ipv6->last_rebuild_valid());
  }
  auto maximum4 = route4();
  auto maximum6 = route6();
  maximum4.preference = maximum6.preference = 255U;
  (void)ipv4->rebuild({}, {}, std::span{&maximum4, 1U});
  (void)ipv6->rebuild({}, {}, {}, std::span{&maximum6, 1U});
  require(ipv4->last_rebuild_valid() && ipv6->last_rebuild_valid());

  // Independent protocol arenas share admission and can withdraw separately.
  auto ospf4 = route4();
  ospf4.network = 0xcb007100U;
  ospf4.source = RouteSource::ospf;
  ospf4.ospf_path_type = OspfPathType::intra_area;
  ospf4.isis_path_type = IsisPathType::none;
  ospf4.isis_rank = 0U;
  auto isis4 = route4();
  require(ipv4->rebuild({}, {}, std::span{&ospf4, 1U}, 1U, std::span{&isis4, 1U}));
  require(ipv4->routes().size() == 2U);
  require(ipv4->rebuild({}, {}, std::span{&ospf4, 1U}, 1U, {}));
  require(ipv4->routes().size() == 1U && ipv4->routes()[0U].source == RouteSource::ospf);
  require(ipv4->rebuild({}, {}, {}, 1U, std::span{&isis4, 1U}));
  require(ipv4->routes().size() == 1U && ipv4->routes()[0U].source == RouteSource::isis);
  auto ospf6 = route6();
  ospf6.network = *ip::parse_ipv6("2001:db8:2::");
  ospf6.source = RouteSource::ospf3;
  ospf6.ospf_path_type = OspfPathType::intra_area;
  ospf6.isis_path_type = IsisPathType::none;
  auto isis6 = route6();
  require(ipv6->rebuild({}, {}, {}, std::span{&ospf6, 1U}, 1U, std::span{&isis6, 1U}));
  require(ipv6->routes().size() == 2U);
  require(ipv6->rebuild({}, {}, {}, std::span{&ospf6, 1U}, 1U, {}));
  require(ipv6->routes().size() == 1U && ipv6->routes()[0U].source == RouteSource::ospf3);
  require(ipv6->rebuild({}, {}, {}, {}, 1U, std::span{&isis6, 1U}));
  require(ipv6->routes().size() == 1U && ipv6->routes()[0U].source == RouteSource::isis);
  // Each arena is legal alone; together they exceed the one shared budget.
  std::vector<DynamicInput> full4(device_catalog::maximum_dynamic_routes_per_router);
  std::vector<Ipv6DynamicInput> full6(device_catalog::maximum_dynamic_routes_per_router);
  require(!ipv4->rebuild({}, {}, full4, 1U, std::span{&isis4, 1U}) && !ipv4->last_rebuild_valid());
  require(!ipv6->rebuild({}, {}, {}, full6, 1U, std::span{&isis6, 1U}) && !ipv6->last_rebuild_valid());
  require(ipv4->routes().size() == 1U && ipv4->routes()[0U].source == RouteSource::isis);
  require(ipv6->routes().size() == 1U && ipv6->routes()[0U].source == RouteSource::isis);

  // Normative level/down ordering precedes even a lower global preference.
  paths4 = {route4(), route4()};
  paths4[0U].isis_rank = 2U;
  paths4[0U].preference = 1U;
  paths4[0U].metric = 1U;
  paths4[1U].isis_path_type = IsisPathType::level2_internal;
  paths4[1U].isis_rank = 1U;
  paths4[1U].preference = 18U;
  paths4[1U].metric = 100U;
  require(ipv4->rebuild({}, {}, paths4));
  ipv4->compile_into(*fib4, 2U);
  require(fib4->count == 1U && fib4->routes[0U].isis_rank == 1U && fib4->routes[0U].metric == 100U);
  std::array paths6{route6(), route6()};
  paths6[0U].isis_rank = 3U;
  paths6[0U].preference = 1U;
  paths6[0U].metric = 1U;
  paths6[1U].isis_path_type = IsisPathType::level2_internal;
  paths6[1U].isis_rank = 1U;
  paths6[1U].preference = 18U;
  paths6[1U].metric = 100U;
  require(ipv6->rebuild({}, {}, {}, paths6));
  ipv6->compile_into(*fib6, 2U);
  require(fib6->count == 1U && fib6->routes[0U].isis_rank == 1U &&
      fib6->routes[0U].metric == 100U && fib6->routes[0U].interface_generation == 17U);

  // Same configured preference across protocols uses the default table,
  // independent of enum order or incomparable numerical protocol costs.
  auto isis = route4();
  isis.preference = 100U;
  isis.metric = 100U;
  auto ospf = isis;
  ospf.source = RouteSource::ospf;
  ospf.ospf_path_type = OspfPathType::external_type_1;
  ospf.isis_path_type = IsisPathType::none;
  ospf.isis_rank = 0U;
  ospf.metric = 1U;
  std::array tied{isis, ospf};
  require(ipv4->rebuild({}, {}, tied));
  ipv4->compile_into(*fib4, 3U);
  require(fib4->count == 1U && fib4->routes[0U].source == RouteSource::isis);

  // An indirect static uses the same selected protocol and retains its scope.
  const std::array indirect{StaticInput{true, 0x0a000000U, 0xc6336409U, 24U, true}};
  require(ipv4->rebuild({}, indirect, tied));
  ipv4->compile_into(*fib4, 4U);
  const auto indirect_route = std::find_if(fib4->routes.begin(), fib4->routes.begin() + fib4->count,
      [](const auto &route) { return route.source == RouteSource::static_route; });
  require(indirect_route != fib4->routes.begin() + fib4->count &&
      indirect_route->interface_id == 42U && indirect_route->interface_generation == 17U &&
      indirect_route->isis_path_type == IsisPathType::none);

  // Narrow external metric ties compare internal cost after external cost.
  paths4 = {route4(), route4()};
  for (auto &route : paths4) {
    route.isis_path_type = IsisPathType::level1_external;
    route.isis_rank = 3U;
    route.preference = 160U;
    route.metric = 5U;
    route.internal_metric = 20U;
  }
  paths4[1U].internal_metric = 30U;
  paths4[1U].port_ordinal = 2U;
  paths4[1U].interface_id = 43U;
  require(ipv4->rebuild({}, {}, paths4, 2U));
  ipv4->compile_into(*fib4, 5U);
  require(fib4->count == 1U && fib4->routes[0U].port_ordinal == 1U);
  paths4[1U].internal_metric = 20U;
  require(ipv4->rebuild({}, {}, paths4, 2U));
  ipv4->compile_into(*fib4, 6U);
  require(fib4->count == 2U);

  // A comparator mixing intra-protocol and cross-protocol rules can cycle
  // for these three inputs. Every permutation must select the same protocol.
  auto external = route4();
  external.preference = 100U;
  external.isis_path_type = IsisPathType::level1_external;
  auto level2 = route4();
  level2.preference = 100U;
  level2.metric = 1U;
  level2.protocol_instance = 1U;
  level2.isis_path_type = IsisPathType::level2_internal;
  level2.isis_rank = 1U;
  const std::array protocol_paths{external, level2, ospf};
  std::array<std::size_t, 3U> order{0U, 1U, 2U};
  do {
    const std::array shuffled{protocol_paths[order[0U]], protocol_paths[order[1U]], protocol_paths[order[2U]]};
    static_cast<void>(ipv4->rebuild({}, {}, shuffled));
    require(ipv4->last_rebuild_valid());
    ipv4->compile_into(*fib4, 7U);
    require(fib4->count == 1U && fib4->routes[0U].source == RouteSource::ospf);
  } while (std::next_permutation(order.begin(), order.end()));
}
