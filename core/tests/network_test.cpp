// Direct forwarding boundary tests. A topology moved away from ports 0 and 1
// proves packet delivery is driven by endpoint bindings rather than path enums.

#include "router/network.hpp"

#include <stdexcept>

void network_tests() {
  router::NetworkConfiguration configuration;
  constexpr std::array<std::uint8_t, 2> ports{4, 7};
  for (std::size_t index = 0; index < configuration.endpoints.size(); ++index) {
    configuration.endpoints[index] = {
        .connected = true,
        .router_port = ports[index],
        .endpoint_mac = router::profile::host_macs[index],
        .endpoint_address = router::profile::host_addresses[index],
        .endpoint_prefix_length = router::profile::host_prefix_lengths[index],
        .endpoint_gateway = router::profile::host_gateways[index],
        .router_mac = router::profile::router_macs[index],
        .router_address = router::profile::router_addresses[index],
        .propagation = std::chrono::nanoseconds(100)};
  }
  router::routing::FibProgram fib{.generation = 1, .count = 2};
  for (std::size_t index = 0; index < ports.size(); ++index) {
    fib.entries[index] = {router::profile::router_networks[index],
                          router::profile::host_prefix_lengths[index],
                          ports[index], 0};
    fib.port_operational[ports[index]] = true;
  }

  router::LabNetwork network;
  network.configure(configuration);
  network.install_fib(fib);
  const auto result =
      network.ping(router::PingOrigin::endpoint, 1, nullptr, nullptr);
  if (!result.success || !result.router_arp[ports[0]].valid ||
      !result.router_arp[ports[1]].valid || result.rx_delta[ports[0]] == 0 ||
      result.rx_delta[ports[1]] == 0 || result.tx_delta[ports[0]] == 0 ||
      result.tx_delta[ports[1]] == 0) {
    throw std::runtime_error(
        "Generic endpoint bindings did not route encoded ICMP frames");
  }

  fib.generation = 2;
  fib.port_operational[ports[1]] = false;
  network.install_fib(fib);
  const auto failed =
      network.ping(router::PingOrigin::endpoint, 2, nullptr, nullptr);
  if (failed.success || failed.drop != router::NetworkDrop::route_miss) {
    throw std::runtime_error(
        "Bound port failure did not withdraw only its data-plane path");
  }
}
