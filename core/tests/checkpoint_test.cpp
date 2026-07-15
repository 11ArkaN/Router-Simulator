// Direct structural codec tests. They validate value round-trip and fail-closed
// corruption handling without starting pthreads or forwarding queues.

#include "router/checkpoint.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <thread>

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
  router::NetworkCheckpointState forwarding;
  // One frame is already on the medium and another waits for router ARP. Wire
  // bytes and queue stages must survive, while pool handles are intentionally
  // recreated by the destination LabNetwork instance.
  const auto probe = router::packet::icmp_echo(
      router::profile::host_macs[0], router::profile::router_macs[0],
      router::profile::host_addresses[0],
      router::profile::host_addresses[1], false, 77, 64,
      router::profile::default_ping_payload_octets, false);
  forwarding.transmitter_remaining_ns[1] = 800000;
  forwarding.frames.push_back(
      {.stage = router::NetworkFrameStage::fabric_in_flight,
       .direction = 1,
       .remaining_ns = 2000000,
       .frame = probe});
  forwarding.arp_requests[0] = true;
  forwarding.frames.push_back(
      {.stage = router::NetworkFrameStage::router_pending,
       .direction = 0,
       .routed = true,
       .next_hop = router::profile::host_addresses[0],
       .frame = probe});
  // Reassembly storage is neither a fabric queue nor an endpoint pending echo.
  // Give it its own stage so ABI round-trip covers a partially accumulated IP
  // datagram whose length is nonzero but may be shorter than an Ethernet wire
  // frame after padding.
  forwarding.endpoints[1].reassembly_active = true;
  forwarding.endpoints[1].reassembly_source =
      router::profile::host_addresses[0];
  forwarding.endpoints[1].reassembly_destination =
      router::profile::host_addresses[1];
  forwarding.endpoints[1].reassembly_identification = 77;
  forwarding.endpoints[1].reassembly_payload_octets =
      static_cast<std::uint16_t>(probe.length - 34U);
  forwarding.frames.push_back(
      {.stage = router::NetworkFrameStage::endpoint_reassembly,
       .direction = 1,
       .frame = probe});

  // Absolute steady-clock time is process-local and must not enter the file.
  // The codec stores the remaining duration relative to this explicit origin.
  router::profile_card(device.hardware).equipment.deadline =
      now + std::chrono::milliseconds(50);
  auto bytes =
      router::checkpoint::encode(device, session, 41, forwarding, now);
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
      restored->forwarding.frames.size() != 3 ||
      restored->forwarding.frames[0].stage !=
          router::NetworkFrameStage::fabric_in_flight ||
      restored->forwarding.frames[0].remaining_ns != 2000000 ||
      !restored->forwarding.arp_requests[0] ||
      !restored->session.candidate_dirty) {
    throw std::runtime_error(
        "Structural checkpoint codec lost modular device state");
  }

  router::LabNetwork restored_network;
  if (!restored_network.restore(restored->forwarding))
    throw std::runtime_error(
        "Forwarding checkpoint could not rebuild fresh packet ownership");
  const auto rebuilt = restored_network.checkpoint();
  const auto in_flight = std::find_if(
      rebuilt.frames.begin(), rebuilt.frames.end(), [](const auto &stored) {
        return stored.stage == router::NetworkFrameStage::fabric_in_flight;
      });
  if (in_flight == rebuilt.frames.end() ||
      in_flight->frame.size() != probe.size() ||
      !std::equal(in_flight->frame.view().begin(),
                  in_flight->frame.view().end(), probe.view().begin()) ||
      in_flight->remaining_ns > 2000000 || !rebuilt.arp_requests[0]) {
    throw std::runtime_error(
        "Forwarding restore lost an in-flight packet or relative deadline");
  }

  // Restored physical state must make progress independently of a later ping.
  // Waiting uses the real monotonic deadline encoded above, then a nonblocking
  // forwarding service pass must remove the delivered handle from the medium.
  std::this_thread::sleep_for(std::chrono::milliseconds{3});
  restored_network.service();
  const auto progressed = restored_network.checkpoint();
  if (std::any_of(progressed.frames.begin(), progressed.frames.end(),
                  [](const auto &stored) {
                    return stored.stage ==
                           router::NetworkFrameStage::fabric_in_flight;
                  })) {
    throw std::runtime_error(
        "Restored link deadline did not continue without a new operation");
  }

  // Truncating the final field represents an interrupted or corrupted write.
  // Decode must fail atomically rather than returning partial device state.
  bytes.pop_back();
  if (router::checkpoint::decode(bytes, now)) {
    throw std::runtime_error(
        "Checkpoint codec accepted a corrupted terminal field");
  }

  // Deterministic mutation fuzzing covers the entire structural codec rather
  // than packet parsers alone. A mutated image may occasionally remain a valid
  // alternative value, but decoding must either return that complete value or
  // reject it without an out-of-bounds read or partial live-state mutation.
  auto seed = router::checkpoint::encode(device, session, 41, forwarding, now);
  std::uint32_t random = 0x43ec91d5U;
  // Reuse one 64 MiB packet arena across accepted candidates. Reconstructing
  // that fixed arena for every iteration would benchmark allocation rather
  // than increase codec coverage.
  router::LabNetwork fuzz_target;
  for (std::uint32_t iteration = 0; iteration < 1000; ++iteration) {
    auto candidate = seed;
    random ^= random << 13;
    random ^= random >> 17;
    random ^= random << 5;
    const auto offset = static_cast<std::size_t>(random) % candidate.size();
    candidate[offset] ^= static_cast<std::uint8_t>((random >> 8) | 1U);
    const auto decoded = router::checkpoint::decode(candidate, now);
    if (decoded) {
      // A successful decode is still treated as untrusted structural input.
      // Restore performs independent capacities and ownership validation.
      static_cast<void>(fuzz_target.restore(decoded->forwarding));
    }
  }
}
