// The instance pthread builds complete same-level catalogs from accepted P2P
// and LAN adjacencies. Calculation reads only its own LSDB; exact token bindings
// commit with each successful family/level decision, without packet-time copies.
// Source: iso.10589.2002.lsdb_link_graph

#include "router/isis_control_worker.hpp"
#include "router/isis_area_attachment.hpp"

#include <algorithm>
#include <limits>

namespace router::isis {
std::optional<std::size_t> ControlWorker::catalog_budget(const LocalOriginProgram &origin) noexcept {
  auto count = origin.neighbors ? origin.neighbors->size() : 0U;
  const auto maximum = routing::ShortestPaths::maximum_first_hops;
  if (count > maximum) return std::nullopt;
  if (origin.broadcast_neighbors) for (const auto &entry : *origin.broadcast_neighbors) {
    if (entry.maximum_neighbors > maximum - count) return std::nullopt;
    count += entry.maximum_neighbors;
  }
  return count;
}

DecisionStatus ControlWorker::prepare_decision_input(OwnedInstance &instance, const DeviceState &device,
    std::size_t index, std::size_t level, std::optional<std::uint8_t> protocol) noexcept {
  auto &input = instance.decision_input;
  input.seeds.clear(); input.lans.clear(); input.bindings.clear();
  const auto &origin = *instance.configuration.origination;
  const auto family = protocol == packet::isis::ipv6_nlpid ? ip::AddressFamily::ipv6 : ip::AddressFamily::ipv4;
  const auto supports = [&](std::span<const std::uint8_t> local, std::span<const std::uint8_t> attributes) {
    if (!protocol) return true;
    if (std::find(local.begin(), local.end(), *protocol) == local.end()) return false;
    bool found{};
    packet::isis::TlvCursor options(attributes);
    while (const auto option = options.next()) if (option->code == 129U)
      found = found || packet::isis::supports_protocol(*option, *protocol);
    return options.valid() && found;
  };
  const auto append = [&](packet::isis::SystemId peer, std::uint32_t metric,
      std::optional<AdjacencyNextHop> binding) {
    if (input.seeds.size() == input.seeds.capacity() || input.bindings.size() == input.bindings.capacity()) return false;
    input.seeds.push_back({peer, metric, static_cast<std::uint16_t>(input.bindings.size())});
    input.bindings.push_back(binding);
    return true;
  };
  const auto find = [&](auto id) {
    return std::find_if(device.circuits.begin(), device.circuits.end(), [&](const auto &owned) {
      return owned.identity.instance == index && owned.identity.interface_id == id;
    });
  };
  if (origin.neighbors) for (const auto &entry : *origin.neighbors) {
    if (!entry.levels[level] || entry.levels[level]->wide == packet::isis::maximum_link_metric) continue;
    const auto owned = find(entry.interface_id);
    if (owned == device.circuits.end() || owned->lan()) continue;
    const auto &circuit = owned->p2p();
    if (family == ip::AddressFamily::ipv6 && protocol && !circuit.configuration().ipv6_addresses_ready) continue;
    const auto peer = circuit.adjacency();
    if (!peer.iso_up || !(static_cast<std::uint8_t>(peer.usage) & (1U << level)) ||
        !supports(circuit.configuration().protocols, circuit.peer_attributes())) continue;
    const NextHopInterface scope{owned->identity.interface_id, owned->identity.configuration_generation,
        owned->identity.physical_port_ordinal};
    const auto binding = protocol ? select_p2p_next_hop(peer, circuit.peer_attributes(),
        circuit.configuration().protocols, scope, static_cast<std::uint8_t>(level + 1U), family) : std::nullopt;
    if (!append(peer.neighbor_system, entry.levels[level]->wide, binding)) return DecisionStatus::capacity;
  }
  if (origin.broadcast_neighbors) for (const auto &entry : *origin.broadcast_neighbors) {
    if (!entry.levels[level] || entry.levels[level]->wide == packet::isis::maximum_link_metric) continue;
    const auto owned = find(entry.interface_id);
    const auto *broadcast = owned == device.circuits.end() ? nullptr : owned->lan();
    const auto *circuit = broadcast ? broadcast->at(level) : nullptr;
    if (!circuit || !circuit->operational()) continue;
    if (family == ip::AddressFamily::ipv6 && protocol && !circuit->configuration().ipv6_addresses_ready) continue;
    const auto role = circuit->designated();
    std::optional<std::uint16_t> designated;
    const NextHopInterface scope{owned->identity.interface_id, owned->identity.configuration_generation,
        owned->identity.physical_port_ordinal};
    for (std::size_t peer_index{}; peer_index < circuit->neighbors().size(); ++peer_index) {
      const auto peer = *circuit->neighbors().at(peer_index);
      if (peer.adjacency.state != LanState::up || !supports(circuit->configuration().protocols, peer.attributes)) continue;
      const auto token = static_cast<std::uint16_t>(input.bindings.size());
      const auto binding = protocol ? select_lan_next_hop(peer, circuit->configuration().protocols, scope, family) : std::nullopt;
      if (!append(peer.adjacency.system, entry.levels[level]->wide, binding)) return DecisionStatus::capacity;
      if (role && !role->local && role->mac == peer.adjacency.mac && role->system == peer.adjacency.system)
        designated = token;
    }
    if (role && role->lan[6U]) {
      if (input.lans.size() == input.lans.capacity()) return DecisionStatus::capacity;
      input.lans.push_back({entry.interface_id, role->lan, entry.levels[level]->wide, designated});
    }
  }
  return DecisionStatus::applied;
}

void ControlWorker::service_p2p_decision(OwnedInstance &instance, const DeviceState &device,
    std::size_t index, RuntimeClock::time_point now, std::size_t &budget) noexcept {
  if (!instance.configuration.origination ||
      (!instance.configuration.origination->neighbors && !instance.configuration.origination->broadcast_neighbors)) return;
  std::array<bool, 2U> ready{true, true};
  for (std::size_t level{}; level < 2U; ++level) if (instance.spf[level] && instance.level_decisions_pending(level)) {
    auto &timer = *instance.spf[level];
    if (!timer.deadline() && !timer.changed(now)) { instance.status = UpdateStatus::epoch_exhausted; return; }
    ready[level] = timer.due(now);
  }
  bool area_calculated{};
  const auto calculate = [&](const P2pDecisionProgram &program, auto &decisions, auto &consumed, auto &status,
      std::array<std::uint64_t, 2U> *runs,
      std::array<std::vector<std::optional<AdjacencyNextHop>>, 2U> *bindings) {
    for (std::size_t level{}; level < 2U && budget; ++level) {
      if (!ready[level] || !decisions[level] || consumed[level] == instance.decision_revisions[level]) continue;
      status[level] = prepare_decision_input(instance, device, index, level, program.protocol);
      if (status[level] == DecisionStatus::applied) {
        packet::isis::LanId root{};
        std::copy(instance.configuration.local.begin(), instance.configuration.local.end(), root.begin());
        const auto &input = instance.decision_input;
        status[level] = decisions[level]->calculate(instance.process->level(level)->database().database(),
            {root, 0U, program.protocol, GraphMetricStyle::wide}, input.seeds,
            static_cast<std::uint16_t>(input.bindings.size()), now, input.lans);
        if (status[level] == DecisionStatus::applied && bindings)
          (*bindings)[level].assign(input.bindings.begin(), input.bindings.end());
      }
      if (runs && status[level] == DecisionStatus::applied) area_calculated = true;
      consumed[level] = instance.decision_revisions[level];
      if (runs && (*runs)[level] != std::numeric_limits<std::uint64_t>::max()) ++(*runs)[level];
      --budget;
    }
  };
  if (instance.configuration.decision)
    calculate(*instance.configuration.decision, instance.decisions, instance.consumed_decision_revision,
        instance.decision_status, &instance.decision_runs, nullptr);
  for (std::size_t family{}; family < instance.configuration.routing.size(); ++family)
    if (instance.configuration.routing[family]) {
      auto &owned = instance.route_families[family];
      calculate(instance.configuration.routing[family]->calculation, owned.decisions, owned.consumed, owned.status,
          nullptr, &owned.bindings);
    }
  auto &origin = *instance.configuration.origination;
  if (area_calculated && origin.automatic_area_attachment && instance.decisions[0U] && instance.decisions[1U] &&
      instance.decision_status[0U] == DecisionStatus::applied &&
      instance.consumed_decision_revision[0U] == instance.decision_revisions[0U] &&
      instance.decision_status[1U] == DecisionStatus::applied &&
      instance.consumed_decision_revision[1U] == instance.decision_revisions[1U]) {
    auto root = std::find_if(origin.content.records.begin(), origin.content.records.end(), [](const auto &record) {
      return !record.level && !record.id[6U] && !record.id[7U];
    });
    if (root == origin.content.records.end()) { instance.status = UpdateStatus::invalid_configuration; return; }
    const auto attached = derive_area_attachment(instance.process->level(0U)->database().database(),
        *instance.decisions[0U], instance.process->level(1U)->database().database(), *instance.decisions[1U],
        instance.configuration.maximum_areas, origin.suppress_attached_bit, now);
    if (!attached) { instance.status = UpdateStatus::invalid_configuration; return; }
    const auto flags = static_cast<std::uint8_t>((root->flags & ~8U) | (*attached ? 8U : 0U));
    if (flags != root->flags) { root->flags = flags; instance.local_roots_dirty[0U] = true; }
  }
  // All configured families in a level share one SPF hold. Bounded partial
  // quanta retain the same ready deadline until every revision is consumed.
  for (std::size_t level{}; level < 2U; ++level)
    if (instance.spf[level] && instance.spf[level]->deadline() && ready[level] && !instance.level_decisions_pending(level))
      if (!instance.spf[level]->complete(now)) instance.status = UpdateStatus::epoch_exhausted;
}
} // namespace router::isis
