// The instance control owner derives root LAN links and reserved pseudonodes
// from its own Up adjacencies and DIS election. ISO 10589 7.3.8/7.3.10 supplies
// zero-cost pseudonode edges; no remote state or synthetic P2P peer is used.

#include "router/isis_control_worker.hpp"
#include "router/isis_lan_origination.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>

namespace router::isis {
namespace {
packet::isis::LspId pseudonode_id(packet::isis::SystemId local, std::uint8_t circuit) noexcept {
  packet::isis::LspId id{};
  std::copy(local.begin(), local.end(), id.begin());
  id[6U] = circuit;
  return id;
}
bool accepted(LocalContentResult result) noexcept {
  return result == LocalContentResult::changed || result == LocalContentResult::unchanged;
}
}
ControlError ControlWorker::prepare_lan_origination(UpdateInstanceProgram &program) noexcept {
  auto &origin = *program.origination;
  // Automatic ownership accepts no caller-supplied pseudonode records.
  if (std::any_of(origin.content.records.begin(), origin.content.records.end(), [](const auto &record) { return record.id[6U] != 0U; }))
    return ControlError::invalid_argument;
  if (!origin.broadcast_neighbors) return ControlError::none;
  auto &interfaces = *origin.broadcast_neighbors;
  const auto p2p_count = origin.neighbors ? origin.neighbors->size() : 0U;
  if (p2p_count > program.maximum_circuits || interfaces.size() > program.maximum_circuits - p2p_count)
    return ControlError::capacity;
  std::sort(interfaces.begin(), interfaces.end(), [](const auto &a, const auto &b) { return a.interface_id < b.interface_id; });
  try {
    auto records = origin.content.records;
    std::array<std::size_t, 2U> counts{};
    for (const auto &record : records) {
      if (record.level > 1U) return ControlError::invalid_argument;
      ++counts[record.level];
    }
    for (std::size_t index{}; index < interfaces.size(); ++index) {
      const auto &entry = interfaces[index];
      if (!entry.interface_id || !entry.circuit || !entry.maximum_neighbors ||
          (!entry.levels[0U] && !entry.levels[1U]) ||
          (index && interfaces[index - 1U].interface_id == entry.interface_id)) return ControlError::invalid_argument;
      for (std::size_t previous{}; previous < index; ++previous)
        if (interfaces[previous].circuit == entry.circuit) return ControlError::already_exists;
      if (origin.neighbors && std::any_of(origin.neighbors->begin(), origin.neighbors->end(),
          [&](const auto &other) { return other.interface_id == entry.interface_id; })) return ControlError::already_exists;
      for (std::size_t level{}; level < 2U; ++level) if (entry.levels[level]) {
        const auto link = p2p_origin_option_octets(*entry.levels[level]);
        const auto space = lan_pseudonode_option_octets(entry.maximum_neighbors, entry.levels[level]->narrow.has_value());
        if (!link || !space || !program.levels[level] || !origin.content.levels[level]) return ControlError::invalid_argument;
        const auto &limit = *origin.content.levels[level];
        if (limit.maximum_pdu_octets <= packet::isis::lsp_header_octets) return ControlError::capacity;
        const auto edge = *lan_pseudonode_option_octets(0U, entry.levels[level]->narrow.has_value());
        const auto per_fragment = (limit.maximum_pdu_octets - packet::isis::lsp_header_octets) / edge;
        if (!per_fragment) return ControlError::capacity;
        const auto fragments = ((*space / edge) - 1U) / per_fragment + 1U;
        if (fragments > 256U || counts[level] > program.levels[level]->database.records ||
            fragments > program.levels[level]->database.records - counts[level]) return ControlError::capacity;
        counts[level] += fragments;
        const auto root = std::find_if(records.begin(), records.end(), [&](const auto &record) {
          return record.level == level && !record.id[6U] && !record.id[7U];
        });
        if (root == records.end()) return ControlError::invalid_argument;
        const auto flags = static_cast<std::uint8_t>(root->flags & 3U);
        for (std::size_t fragment{}; fragment < fragments; ++fragment) {
          auto id = pseudonode_id(program.local, entry.circuit);
          id[7U] = static_cast<std::uint8_t>(fragment);
          records.push_back({static_cast<std::uint8_t>(level), id, flags, {}, false});
        }
      }
    }
    origin.content.records.swap(records);
    return ControlError::none;
  } catch (const std::bad_alloc &) { return ControlError::capacity; }
    catch (const std::length_error &) { return ControlError::capacity; }
}

bool ControlWorker::compose_lan_pseudonodes(OwnedInstance &instance, const DeviceState &device,
    std::size_t index, std::size_t level, LocalLspSet &target, RuntimeClock::time_point now) noexcept {
  const auto &origin = *instance.configuration.origination;
  if (!origin.broadcast_neighbors) return true;
  if (!instance.fragment_workspace) { instance.status = UpdateStatus::invalid_configuration; return false; }
  for (const auto &entry : *origin.broadcast_neighbors) if (entry.levels[level]) {
    instance.lan_projection.clear();
    const auto found = std::find_if(device.circuits.begin(), device.circuits.end(), [&](const auto &owned) {
      return owned.identity.instance == index && owned.identity.interface_id == entry.interface_id;
    });
    const auto *broadcast = found == device.circuits.end() ? nullptr : found->lan();
    const auto *circuit = broadcast ? broadcast->at(level) : nullptr;
    if (circuit && circuit->operational()) for (std::size_t peer{}; peer < circuit->neighbors().size(); ++peer) {
      const auto value = circuit->neighbors().at(peer)->adjacency;
      if (value.state != LanState::up) continue;
      if (instance.lan_projection.size() == instance.lan_projection.capacity()) {
        instance.status = UpdateStatus::capacity; return false;
      }
      instance.lan_projection.push_back(value.system);
    }
    std::sort(instance.lan_projection.begin(), instance.lan_projection.end());
    const auto end = std::unique(instance.lan_projection.begin(), instance.lan_projection.end());
    const auto peers = std::span<const packet::isis::SystemId>(instance.lan_projection.begin(), end);
    const auto role = circuit ? circuit->designated() : std::nullopt;
    const auto id = pseudonode_id(instance.configuration.local, entry.circuit);
    const auto reserved = std::find_if(origin.content.records.begin(), origin.content.records.end(),
        [&](const auto &record) { return record.level == level && record.id == id; });
    if (reserved == origin.content.records.end()) { instance.status = UpdateStatus::invalid_configuration; return false; }
    auto &workspace = *instance.fragment_workspace;
    workspace.reset();
    packet::isis::LanId source{};
    std::copy_n(id.begin(), source.size(), source.begin());
    bool valid{true};
    if (!peers.empty() && role && role->local) {
      const auto append = [&](const packet::isis::SystemId &peer) {
        std::uint64_t key{};
        for (const auto octet : peer) key = (key << 8U) | octet;
        packet::isis::LanId neighbor{};
        std::copy(peer.begin(), peer.end(), neighbor.begin());
        return workspace.add_pseudonode_link({3U, key}, peer, entry.levels[level]->narrow.has_value(),
            OriginFragmentWorkspace::previous_link(target, level, source, neighbor, 256U));
      };
      valid = append(instance.configuration.local);
      for (const auto &peer : peers) valid = append(peer) && valid;
    }
    std::array<std::uint8_t, 256U> slot_scratch{};
    const auto slots = local_fragment_slots(origin.content, level, source, slot_scratch);
    if (!valid || !accepted(workspace.compose(target, level, source, reserved->flags, slots,
        origin.content.levels[level]->maximum_pdu_octets - packet::isis::lsp_header_octets, now))) {
      instance.status = UpdateStatus::invalid_configuration; return false;
    }
  }
  return true;
}

bool ControlWorker::append_lan_links(const OwnedInstance &instance, const DeviceState &device,
    std::size_t index, std::size_t level, OriginFragmentWorkspace &workspace, const LocalLspSet &target) noexcept {
  const auto &origin = *instance.configuration.origination;
  if (!origin.broadcast_neighbors) return true;
  for (const auto &entry : *origin.broadcast_neighbors) if (entry.levels[level]) {
    const auto found = std::find_if(device.circuits.begin(), device.circuits.end(), [&](const auto &owned) {
      return owned.identity.instance == index && owned.identity.interface_id == entry.interface_id;
    });
    const auto *broadcast = found == device.circuits.end() ? nullptr : found->lan();
    const auto *circuit = broadcast ? broadcast->at(level) : nullptr;
    const auto role = circuit && circuit->operational() ? circuit->designated() : std::nullopt;
    packet::isis::LanId source{};
    std::copy(instance.configuration.local.begin(), instance.configuration.local.end(), source.begin());
    if (role && role->lan[6U] && !workspace.add_link({2U, entry.interface_id}, role->lan, *entry.levels[level],
        OriginFragmentWorkspace::previous_link(target, level, source, role->lan, 256U))) return false;
  }
  return true;
}
RuntimeClock::time_point ControlWorker::service_previous_pseudonodes(OwnedCircuit &owned,
    RuntimeClock::time_point now, std::size_t &budget) noexcept {
  auto deadline = RuntimeClock::time_point::max();
  if (!owned.update || owned.update->status != UpdateStatus::applied) return deadline;
  for (std::size_t level{}; level < 2U; ++level) {
    auto &previous = owned.previous_dis[level];
    if (!previous.remote || previous.fragment == 256U) continue;
    const auto *circuit = owned.lan()->at(level);
    const auto role = circuit ? circuit->designated() : std::nullopt;
    if (!role || !role->local) { previous.fragment = 256U; continue; }
    if (previous.retry > now) { deadline = std::min(deadline, previous.retry); continue; }
    while (previous.fragment < 256U) {
      if (!budget) return std::min(deadline, now);
      --budget;
      packet::isis::LspId id{};
      std::copy(previous.remote->begin(), previous.remote->end(), id.begin());
      id[7U] = static_cast<std::uint8_t>(previous.fragment);
      // Experimental runtime admission excludes authentication selection. The
      // future key owner must supply its current outbound lease here explicitly.
      const auto result = owned.update->process->purge_previous_pseudonode(level, *previous.remote, id,
          {false, std::nullopt}, now, scratch_.options, scratch_.pdu, owned.update->observer());
      if (result.status == UpdateStatus::applied || result.status == UpdateStatus::inactive) { ++previous.fragment; continue; }
      if (result.status == UpdateStatus::authentication || result.status == UpdateStatus::capacity ||
          result.origin.install == LspInstallResult::capacity_exhausted) {
        previous.retry = now + owned.update_egress->program.pacing_period;
        deadline = std::min(deadline, previous.retry);
        break;
      }
      owned.update->status = result.status;
      return RuntimeClock::time_point::max();
    }
  }
  return deadline;
}
} // namespace router::isis
