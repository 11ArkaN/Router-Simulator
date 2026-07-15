// Device to routing projection. This translation keeps ConnectedRib independent
// of the broad aggregate root while preserving allocation-free rebuilds.

#include "router/device_routing.hpp"

namespace router {

// Copies only route-relevant value fields out of the control aggregate. RIB
// code cannot observe CLI session, alarms, counters or hardware type pointers.
routing::RibInput make_rib_input(const DeviceState &device) noexcept {
  routing::RibInput input;
  const auto &running = device.configuration.running;
  input.connected_count = running.interface_count;
  for (std::size_t index = 0; index < running.interface_count; ++index) {
    // Hardware, port and interface gates are resolved before the route manager
    // receives one connected prefix value.
    const auto &interface = running.interfaces[index];
    input.connected[index] = {.valid = interface.valid,
                              .operational =
                                  device.interface_operational(index),
                              .network = interface.network,
                              .prefix_length = interface.prefix_length,
                              .port_index = interface.port_index};
  }
  for (std::size_t index = 0; index < running.static_routes.size(); ++index) {
    // Copy validity markers and values in fixed order without allocation.
    const auto &route = running.static_routes[index];
    input.statics[index] = {.valid = route.valid,
                            .network = route.network,
                            .next_hop = route.next_hop,
                            .prefix_length = route.prefix_length};
  }
  return input;
}

} // namespace router
