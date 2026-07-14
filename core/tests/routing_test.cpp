#include "router/routing.hpp"

#include <stdexcept>

void routing_tests() {
  using namespace router::routing;
  FibProgram fib{.generation = 7, .count = 3};
  fib.entries[0] = {ipv4(0, 0, 0, 0), 0, 7};
  fib.entries[1] = {ipv4(192, 0, 2, 0), 24, 3};
  fib.entries[2] = {ipv4(192, 0, 2, 0), 30, 1};
  std::uint8_t port{};
  if (!lookup(fib, ipv4(192, 0, 2, 2), port) || port != 1) {
    throw std::runtime_error("FIB did not select the longest matching prefix");
  }
  if (!lookup(fib, ipv4(203, 0, 113, 9), port) || port != 7) {
    throw std::runtime_error("FIB did not use the default route");
  }

  // Host routing must choose the protocol address that ARP will resolve. These
  // assertions prevent the endpoint stack from always using its gateway as a
  // shortcut, which would incorrectly make an on-link destination routable.
  const auto source = ipv4(192, 0, 2, 2);
  const auto gateway = ipv4(192, 0, 2, 1);
  if (host_next_hop(source, 24, ipv4(192, 0, 2, 99), gateway) !=
          ipv4(192, 0, 2, 99) ||
      host_next_hop(source, 24, ipv4(198, 51, 100, 2), gateway) != gateway) {
    throw std::runtime_error("Host local or remote next-hop selection is invalid");
  }

  router::DeviceState device;
  ConnectedRib rib;
  if (rib.rebuild(device) || !rib.entries().empty()) {
    throw std::runtime_error("Down interfaces installed connected routes");
  }
  device.card_present = true;
  device.mda_present = true;
  device.card_provisioned = true;
  device.mda_provisioned = true;
  device.card_lifecycle = router::EquipmentLifecycle::ready;
  device.mda_lifecycle = router::EquipmentLifecycle::ready;
  if (!rib.rebuild(device) || rib.entries().size() != 2) {
    throw std::runtime_error("Operational interfaces did not install connected routes");
  }
}
