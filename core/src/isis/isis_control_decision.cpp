// The IS-IS pthread consumes its own decision revisions and accepted circuit
// snapshots. This experimental wide MT0 projection publishes no RIB or FIB
// entries and has no access to editor topology or another router's state.

// Source: iso.10589.2002.lsdb_link_graph

#include "router/isis_control_worker.hpp"

#include <algorithm>
#include <limits>

namespace router::isis {
void ControlWorker::service_p2p_decision(OwnedInstance &instance, const DeviceState &device,
    std::size_t index, RuntimeClock::time_point now, std::size_t &budget) noexcept {
  if (!instance.configuration.decision) return;
  const auto &interfaces = *instance.configuration.origination->neighbors;
  std::array<P2pSpfSeed, device_catalog::maximum_ecmp_paths> seeds{};
  for (std::size_t level{}; level < 2U && budget; ++level) {
    if (!instance.decisions[level] || instance.consumed_decision_revision[level] == instance.decision_revisions[level]) continue;
    std::size_t count{};
    for (const auto &owned : device.circuits) {
      if (owned.identity.instance != index) continue;
      const auto protocol = instance.configuration.decision->protocol;
      if (protocol) {
        const auto &local = owned.circuit.configuration().protocols;
        if (std::find(local.begin(), local.end(), *protocol) == local.end()) continue;
        bool peer_supports{};
        packet::isis::TlvCursor attributes(owned.circuit.peer_attributes());
        while (const auto option = attributes.next()) if (option->code == 129U)
          peer_supports = peer_supports || packet::isis::supports_protocol(*option, *protocol);
        if (!attributes.valid() || !peer_supports) continue;
      }
      const auto adjacency = owned.circuit.adjacency();
      if (!adjacency.iso_up || !(static_cast<std::uint8_t>(adjacency.usage) & (1U << level))) continue;
      const auto found = std::lower_bound(interfaces.begin(), interfaces.end(), owned.identity.interface_id,
          [](const auto &entry, auto id) { return entry.interface_id < id; });
      if (found == interfaces.end() || found->interface_id != owned.identity.interface_id || !found->levels[level]) continue;
      if (found->levels[level]->wide == packet::isis::maximum_link_metric) continue;
      seeds[count++] = {adjacency.neighbor_system, found->levels[level]->wide,
          static_cast<std::uint16_t>(found - interfaces.begin())};
    }
    packet::isis::LanId root{};
    std::copy(instance.configuration.local.begin(), instance.configuration.local.end(), root.begin());
    instance.decision_status[level] = instance.decisions[level]->calculate(
        instance.process->level(level)->database().database(), {root, 0U, instance.configuration.decision->protocol, GraphMetricStyle::wide},
        std::span{seeds}.first(count), static_cast<std::uint16_t>(interfaces.size()), now);
    instance.consumed_decision_revision[level] = instance.decision_revisions[level];
    if (instance.decision_runs[level] != std::numeric_limits<std::uint64_t>::max()) ++instance.decision_runs[level];
    --budget;
  }
}
} // namespace router::isis
