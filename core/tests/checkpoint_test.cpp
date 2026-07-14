// Direct structural codec tests. They validate value round-trip and fail-closed
// corruption handling without starting pthreads or forwarding queues.

#include "router/checkpoint.hpp"

#include <stdexcept>

void checkpoint_tests() {
  router::DeviceState device;
  router::CliSession session;
  device.configuration.running.card_provisioned = true;
  device.configuration.running.ports[4].mtu = 1400;
  device.configuration.candidate = device.configuration.running;
  device.configuration.candidate.system_name = {'e', 'd', 'g', 'e', '\0'};
  device.hardware.card.present = true;
  device.hardware.card.lifecycle = router::EquipmentLifecycle::initializing;
  device.hardware.link_signal[4] = true;
  device.project.links[0].router_port = 4;
  device.project.links[0].propagation = std::chrono::nanoseconds(777);
  device.operational.port_counters[4].rx_packets = 19;
  device.operational.arp[4] = {.valid = true,
                               .address = router::profile::host_addresses[0],
                               .mac = router::profile::host_macs[0],
                               .port_index = 4};
  session.candidate_dirty = true;
  const auto now = std::chrono::steady_clock::time_point{};
  device.hardware.card.deadline = now + std::chrono::milliseconds(50);
  auto bytes = router::checkpoint::encode(device, session, 41, now);
  const auto restored = router::checkpoint::decode(bytes);
  if (!restored || restored->fib_generation != 41 ||
      restored->device.configuration.running.ports[4].mtu != 1400 ||
      restored->device.project.links[0].router_port != 4 ||
      restored->device.project.links[0].propagation !=
          std::chrono::nanoseconds(777) ||
      restored->device.operational.port_counters[4].rx_packets != 19 ||
      !restored->device.operational.arp[4].valid ||
      restored->card_remaining_ns != 50000000 ||
      !restored->session.candidate_dirty) {
    throw std::runtime_error(
        "Structural checkpoint codec lost modular device state");
  }
  bytes.pop_back();
  if (router::checkpoint::decode(bytes)) {
    throw std::runtime_error(
        "Checkpoint codec accepted a corrupted terminal field");
  }
}
