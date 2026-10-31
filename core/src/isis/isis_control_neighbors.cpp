// The instance pthread composes MT0 P2P links from its own accepted adjacency
// snapshots. Configuration owns base options and explicit metrics; no topology
// editor, foreign database or transport owner is consulted during composition.

// Source: iso.10589.2002.p2p_neighbor_origination

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
ControlError ControlWorker::prepare_neighbor_origination(UpdateInstanceProgram &program) noexcept {
  if (!program.origination || !program.origination->neighbors) return ControlError::none;
  if (program.format != packet::isis::InstanceFormat::standard || program.wire_instance)
    return ControlError::unsupported_update_instance;
  auto &interfaces = *program.origination->neighbors;
  if (interfaces.size() > program.maximum_circuits) return ControlError::capacity;
  std::sort(interfaces.begin(), interfaces.end(), [](const auto &a, const auto &b) {
    return a.interface_id < b.interface_id;
  });
  std::array<std::size_t, 2U> required{};
  for (std::size_t index{}; index < interfaces.size(); ++index) {
    const auto &entry = interfaces[index];
    if (!entry.interface_id || (index && interfaces[index - 1U].interface_id == entry.interface_id) ||
        (!entry.levels[0U] && !entry.levels[1U])) return ControlError::invalid_argument;
    for (std::size_t level{}; level < 2U; ++level) if (entry.levels[level]) {
      const auto size = p2p_origin_option_octets(*entry.levels[level]);
      if (!size || !program.levels[level]) return ControlError::invalid_argument;
      // Bound before addition, independent of a possibly hostile input count.
      if (*size > packet::maximum_frame_octets - required[level]) return ControlError::capacity;
      required[level] += *size;
    }
  }
  std::array<bool, 2U> roots{};
  for (const auto &record : program.origination->content.records) {
    if (record.level > 1U || record.id[6U]) return ControlError::invalid_argument;
    packet::isis::TlvCursor cursor(record.options);
    while (const auto option = cursor.next())
      if (option->code == 2U || option->code == 22U || option->code == 222U)
        return ControlError::invalid_argument;
    if (!cursor.valid()) return ControlError::invalid_argument;
    if (record.id[7U]) continue;
    const auto &level = program.origination->content.levels[record.level];
    if (!level || !record.active || level->maximum_pdu_octets > packet::maximum_frame_octets ||
        level->maximum_pdu_octets < packet::isis::lsp_header_octets)
      return ControlError::invalid_argument;
    const auto capacity = level->maximum_pdu_octets - packet::isis::lsp_header_octets;
    if (required[record.level] > capacity || record.options.size() > capacity - required[record.level])
      return ControlError::capacity;
    roots[record.level] = true;
  }
  for (std::size_t level{}; level < 2U; ++level)
    if (program.levels[level] && !roots[level]) return ControlError::invalid_argument;
  return ControlError::none;
}
bool ControlWorker::compose_local_neighbors(OwnedInstance &instance, const DeviceState &device,
    std::size_t index, LocalLspSet &target, RuntimeClock::time_point now, std::size_t &budget) noexcept {
  const auto &origin = *instance.configuration.origination;
  if (!origin.neighbors) return true;
  for (std::size_t level{}; level < 2U; ++level)
    if (!origin.content.levels[level]) instance.local_roots_dirty[level] = false;
  if (!instance.local_roots_dirty[0U] && !instance.local_roots_dirty[1U]) return true;
  if (!budget) return false;
  std::fill(instance.neighbor_projection.begin(), instance.neighbor_projection.end(), OwnedInstance::NeighborProjection{});
  const auto &interfaces = *origin.neighbors;
  for (const auto &owned : device.circuits) {
    if (owned.identity.instance != index) continue;
    const auto found = std::lower_bound(interfaces.begin(), interfaces.end(), owned.identity.interface_id,
        [](const auto &entry, auto id) { return entry.interface_id < id; });
    if (found == interfaces.end() || found->interface_id != owned.identity.interface_id) continue;
    const auto adjacency = owned.circuit.adjacency();
    instance.neighbor_projection[static_cast<std::size_t>(found - interfaces.begin())] =
        {adjacency.neighbor_system, adjacency.usage, adjacency.iso_up};
  }
  const auto first = instance.first_root_level;
  for (std::size_t offset{}; offset < 2U && budget; ++offset) {
    const auto level = (first + offset) % 2U;
    if (!instance.local_roots_dirty[level]) continue;
    const auto root = std::find_if(origin.content.records.begin(), origin.content.records.end(), [&](const auto &record) {
      return record.level == level && !record.id[6U] && !record.id[7U];
    });
    if (root == origin.content.records.end()) { instance.status = UpdateStatus::invalid_configuration; return false; }
    packet::isis::TlvWriter writer(std::span{scratch_.options}.first(
        origin.content.levels[level]->maximum_pdu_octets - packet::isis::lsp_header_octets));
    packet::isis::TlvCursor cursor(root->options);
    bool valid = true;
    while (const auto option = cursor.next()) valid = writer.append(option->code, option->value) && valid;
    for (std::size_t slot{}; slot < interfaces.size(); ++slot) {
      const auto &peer = instance.neighbor_projection[slot];
      if (peer.up && (static_cast<std::uint8_t>(peer.usage) & (1U << level)) && interfaces[slot].levels[level])
        valid = append_p2p_origin_neighbor(writer, peer.peer, *interfaces[slot].levels[level]) && valid;
    }
    const auto replaced = valid && cursor.valid() ? target.replace(level, root->id, root->flags, writer.bytes(), now) :
        LocalContentResult::capacity;
    if (replaced != LocalContentResult::changed && replaced != LocalContentResult::unchanged) {
      instance.status = UpdateStatus::invalid_configuration;
      return false;
    }
    instance.local_roots_dirty[level] = false;
    instance.first_root_level = (level + 1U) % 2U;
    --budget;
  }
  return !instance.local_roots_dirty[0U] && !instance.local_roots_dirty[1U];
}
} // namespace router::isis
