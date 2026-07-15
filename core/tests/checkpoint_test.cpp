// Direct structural codec tests. They validate value round-trip and fail-closed
// corruption handling without starting pthreads or forwarding queues.

#include "router/checkpoint.hpp"

#include <stdexcept>

void checkpoint_tests() {
  // Populate values from separate ownership domains. A successful round-trip
  // must preserve configuration, hardware, project, operational and CLI state.
  router::DeviceState device;
  router::CliSession session;
  router::profile_card(device.configuration.running).type =
      router::profile::line_card_type;
  device.configuration.running.ports[4].mtu = 1400;
  device.configuration.candidate = device.configuration.running;
  device.configuration.candidate.system_name = {'e', 'd', 'g', 'e', '\0'};
  router::profile_card(device.hardware).type = router::profile::line_card_type;
  router::profile_card(device.hardware).equipment.lifecycle =
      router::EquipmentLifecycle::initializing;
  device.hardware.link_signal[4] = true;
  device.project.links[0].router_port = 4;
  device.project.links[0].propagation = std::chrono::nanoseconds(777);
  device.operational.port_counters[4].rx_packets = 19;
  // Use a non-zero monotonic origin so active time points remain distinct from
  // the default-constructed sentinel in both source and restored images.
  const auto now =
      std::chrono::steady_clock::time_point{} + std::chrono::seconds{100};
  device.operational.arp[4] = {.valid = true,
                               .address = router::profile::host_addresses[0],
                               .mac = router::profile::host_macs[0],
                               .port_index = 4,
                               .expires_at = now + std::chrono::seconds{30}};
  device.operational.connected_route_since[0] = now - std::chrono::seconds{5};
  session.candidate_dirty = true;

  // Absolute steady-clock time is process-local and must not enter the file.
  // The codec stores the remaining duration relative to this explicit origin.
  router::profile_card(device.hardware).equipment.deadline =
      now + std::chrono::milliseconds(50);
  auto bytes = router::checkpoint::encode(device, session, 41, now);
  const auto restored = router::checkpoint::decode(bytes, now);

  // Check representative fields from every serialized module, including a
  // non-default port index, so array order and fixed-slot assumptions are seen.
  if (!restored || restored->fib_generation != 41 ||
      restored->device.configuration.running.ports[4].mtu != 1400 ||
      restored->device.project.links[0].router_port != 4 ||
      restored->device.project.links[0].propagation !=
          std::chrono::nanoseconds(777) ||
      restored->device.operational.port_counters[4].rx_packets != 19 ||
      !restored->device.operational.arp[4].valid ||
      restored->device.operational.arp[4].expires_at !=
          now + std::chrono::seconds{30} ||
      restored->device.operational.connected_route_since[0] !=
          now - std::chrono::seconds{5} ||
      restored->card_remaining_ns[router::profile::line_card_index] !=
          50000000 ||
      !restored->session.candidate_dirty) {
    throw std::runtime_error(
        "Structural checkpoint codec lost modular device state");
  }

  // Truncating the final field represents an interrupted or corrupted write.
  // Decode must fail atomically rather than returning partial device state.
  bytes.pop_back();
  if (router::checkpoint::decode(bytes, now)) {
    throw std::runtime_error(
        "Checkpoint codec accepted a corrupted terminal field");
  }
}
