// Device to routing projection. This translation keeps ConnectedRib independent
// of the broad aggregate root while preserving allocation-free rebuilds.

#include "router/device_routing.hpp"

namespace router {

routing::RibInput make_rib_input(const DeviceState &device) noexcept {
  routing::RibInput input;
  const auto &running = device.configuration.running;
  input.connected_count = running.interface_count;
  for (std::size_t index = 0; index < running.interface_count; ++index) {
    const auto &interface = running.interfaces[index];
    input.connected[index] = {.valid = interface.valid,
                              .operational =
                                  device.interface_operational(index),
                              .network = interface.network,
                              .prefix_length = interface.prefix_length,
                              .port_index = interface.port_index};
  }
  for (std::size_t index = 0; index < running.static_routes.size(); ++index) {
    const auto &route = running.static_routes[index];
    input.statics[index] = {.valid = route.valid,
                            .network = route.network,
                            .next_hop = route.next_hop,
                            .prefix_length = route.prefix_length};
  }
  return input;
}

} // namespace router
