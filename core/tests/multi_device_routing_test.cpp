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
}
