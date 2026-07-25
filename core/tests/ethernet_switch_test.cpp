// Bridge tests use encoded Ethernet bytes and prove learning, unknown unicast
// flooding, known unicast filtering, multicast replication and FDB aging.

#include "router/ethernet_switch.hpp"

#include <chrono>
#include <stdexcept>

namespace {

router::packet::Frame frame(const router::packet::Mac &destination,
                            const router::packet::Mac &source) {
  router::packet::Frame value{};
  value.length = router::packet::ethernet_minimum_without_fcs;
  std::copy(destination.begin(), destination.end(), value.bytes.begin());
  std::copy(source.begin(), source.end(), value.bytes.begin() + 6U);
  return value;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ethernet_switch_tests() {
  using namespace router;
  using namespace router::lab;
  PacketPool pool;
  EthernetSwitch bridge{device_catalog::ethernet_switch_profiles[0U], pool};
  const SwitchPortConfiguration up{
      .speed_mbps =
          device_catalog::ethernet_switch_profiles[0U].default_speed_mbps,
      .mtu = 1500U,
      .admin_enabled = true,
      .carrier = true};
  require(bridge.configure_port(0U, up) &&
              bridge.configure_port(1U, up) &&
              bridge.configure_port(2U, up),
          "switch profile rejected valid active ports");

  constexpr packet::Mac first{{0x02U, 0U, 0U, 0U, 0U, 1U}};
  constexpr packet::Mac second{{0x02U, 0U, 0U, 0U, 0U, 2U}};
  constexpr packet::Mac unknown{{0x02U, 0U, 0U, 0U, 0U, 3U}};
  constexpr packet::Mac multicast{{0x01U, 0U, 0x5eU, 0U, 0U, 5U}};
  const auto now =
      EthernetSwitch::Clock::time_point{std::chrono::seconds{100U}};

  const auto flooded = bridge.ingress(0U, frame(unknown, first), now);
  require(flooded.learned_source && flooded.admitted_egresses == 2U &&
              bridge.learned_addresses() == 1U,
          "unknown unicast did not learn and flood");
  for (const auto port : {1U, 2U}) {
    const auto output = bridge.dequeue(static_cast<std::uint16_t>(port));
    require(output.has_value(), "flooded egress was absent");
    bridge.release(output->handle);
  }

  const auto known = bridge.ingress(1U, frame(first, second), now);
  const auto known_output = bridge.dequeue(0U);
  require(known.admitted_egresses == 1U &&
              known_output.has_value() && !bridge.dequeue(2U).has_value(),
          "known unicast was not filtered to learned port");
  bridge.release(known_output->handle);
  const auto same_port = bridge.ingress(0U, frame(first, unknown), now);
  require(same_port.admitted_egresses == 0U &&
              !bridge.dequeue(1U).has_value() &&
              !bridge.dequeue(2U).has_value(),
          "same-port learned destination was flooded instead of filtered");
  const auto multicast_result =
      bridge.ingress(1U, frame(multicast, second), now);
  require(multicast_result.admitted_egresses == 2U,
          "multicast did not replicate to the broadcast domain");
  for (const auto port : {0U, 2U}) {
    const auto output = bridge.dequeue(static_cast<std::uint16_t>(port));
    require(output.has_value(), "multicast egress was absent");
    bridge.release(output->handle);
  }

  // Preserve one queued frame and one learned address across a continuity
  // image. Restore uses remaining durations, so the entry must survive until
  // exactly the original aging deadline in the new monotonic epoch.
  require(bridge.ingress(0U, frame(multicast, first), now)
                  .admitted_egresses == 2U,
          "checkpoint fixture was not admitted");
  const auto checkpoint = bridge.checkpoint(now);
  PacketPool restored_pool;
  EthernetSwitch restored{device_catalog::ethernet_switch_profiles[0U],
                          restored_pool};
  const auto restored_now =
      EthernetSwitch::Clock::time_point{std::chrono::seconds{1000U}};
  require(restored.restore(checkpoint, restored_now) &&
              restored.learned_addresses() == bridge.learned_addresses(),
          "switch continuity image did not restore FDB and egress order");
  const auto restored_frame = restored.dequeue(1U);
  require(restored_frame.has_value(),
          "switch continuity image lost queued egress frame");
  restored.release(restored_frame->handle);

  bridge.age(now + device_catalog::ethernet_switch_profiles[0U].fdb_aging);
  require(bridge.learned_addresses() == 0U,
          "FDB record survived its monotonic aging deadline");
}
