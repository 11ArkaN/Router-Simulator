// Multi-device routing tests protect local next-hop resolution, longest-prefix
// lookup, withdrawal and atomic rejection independently from the lab graph.

#include "router/multi_device_routing.hpp"

#include <array>
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

  RouteTable rib;
  require(rib.rebuild(connected, statics) && rib.last_rebuild_valid(),
          "RIB rejected valid connected and static routes");
  const auto fib = rib.compile(9);
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

  auto failed = connected;
  failed[1].operational = false;
  require(rib.rebuild(failed, statics),
          "RIB did not withdraw routes after local interface failure");
  const auto withdrawn = rib.compile(10);
  require(withdrawn.count == 2 &&
              !lookup(withdrawn, 0xc6336401U, selected),
          "failed local interface retained dependent static route");

  const std::array invalid{ConnectedInput{true, true, 0, 0, 33}};
  const auto before = rib.compile(10);
  require(!rib.rebuild(invalid, std::span<const StaticInput>{}) &&
              !rib.last_rebuild_valid() && rib.compile(11).count == before.count,
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
  RouteTable system_rib;
  require(system_rib.rebuild(system_connected, through_system) &&
              system_rib.last_rebuild_valid(),
          "system /32 was rejected as a local connected input");
  const auto system_fib = system_rib.compile(12U);
  require(system_fib.count == 1U &&
              lookup(system_fib, 0x0a00ff01U, selected) &&
              selected.local_system && selected.prefix_length == 32U,
          "system interface did not compile as a local /32");
  auto invalid_system = system_connected;
  invalid_system[0].prefix_length = 31U;
  require(!system_rib.rebuild(invalid_system, through_system) &&
              !system_rib.last_rebuild_valid(),
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

  Ipv6RouteTable rib6;
  require(rib6.rebuild(connected6, statics6) && rib6.last_rebuild_valid(),
          "IPv6 RIB rejected valid connected and static routes");
  const auto fib6 = rib6.compile(19);
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

  auto invalid_link_local = statics6;
  invalid_link_local[1].outgoing_interface_set = false;
  const auto before6 = rib6.compile(19);
  require(!rib6.rebuild(connected6, invalid_link_local) &&
              !rib6.last_rebuild_valid() &&
              rib6.compile(20).count == before6.count,
          "unscoped IPv6 link-local next hop mutated the RIB");

  auto failed6 = connected6;
  failed6[0].operational = false;
  require(rib6.rebuild(failed6, statics6),
          "IPv6 RIB did not react to local interface failure");
  const auto withdrawn6 = rib6.compile(21);
  require(lookup(withdrawn6, address("2001:db8:100::55"), selected6) &&
              selected6.prefix_length == 0 &&
              selected6.next_hop == address("fe80::2"),
          "IPv6 interface failure did not withdraw to the default route");
}
