// The instance pthread composes MT0 links from its own accepted circuit
// snapshots. Configuration owns base options and explicit metrics; no topology
// editor, foreign database or transport owner is consulted during composition.

// Source: iso.10589.2002.p2p_neighbor_origination

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
ControlError ControlWorker::prepare_neighbor_origination(UpdateInstanceProgram &program) noexcept {
  if (!program.origination || !program.origination->automatic_roots())
    return ControlError::none;
  if (program.format != packet::isis::InstanceFormat::standard || program.wire_instance)
    return ControlError::unsupported_update_instance;
  std::span<P2pOriginInterface> interfaces;
  if (program.origination->neighbors) interfaces = std::span{*program.origination->neighbors};
  if (interfaces.size() > program.maximum_circuits) return ControlError::capacity;
  std::sort(interfaces.begin(), interfaces.end(), [](const auto &a, const auto &b) {
    return a.interface_id < b.interface_id;
  });
  for (std::size_t index{}; index < interfaces.size(); ++index) {
    const auto &entry = interfaces[index];
    if (!entry.interface_id || (index && interfaces[index - 1U].interface_id == entry.interface_id) ||
        (!entry.levels[0U] && !entry.levels[1U])) return ControlError::invalid_argument;
    for (std::size_t level{}; level < 2U; ++level) if (entry.levels[level]) {
      const auto size = p2p_origin_option_octets(*entry.levels[level]);
      if (!size || !program.levels[level]) return ControlError::invalid_argument;
    }
  }
  const auto lan_error = prepare_lan_origination(program);
  if (lan_error != ControlError::none) return lan_error;
  std::array<bool, 2U> roots{};
  for (const auto &record : program.origination->content.records) {
    if (record.level > 1U) return ControlError::invalid_argument;
    if (record.id[6U]) continue;
    packet::isis::TlvCursor cursor(record.options);
    while (const auto option = cursor.next())
      if (option->code == 2U || option->code == 22U || option->code == 222U ||
          (program.origination->prefixes &&
           (option->code == 128U || option->code == 130U || option->code == 135U || option->code == 236U)))
        return ControlError::invalid_argument;
    if (!cursor.valid()) return ControlError::invalid_argument;
    if (record.id[7U]) continue;
    const auto &level = program.origination->content.levels[record.level];
    if (!level || !record.active || level->maximum_pdu_octets > packet::maximum_frame_octets ||
        level->maximum_pdu_octets < packet::isis::lsp_header_octets)
      return ControlError::invalid_argument;
    const auto capacity = level->maximum_pdu_octets - packet::isis::lsp_header_octets;
    if (record.options.size() > capacity)
      return ControlError::capacity;
    roots[record.level] = true;
  }
  for (std::size_t level{}; level < 2U; ++level)
    if (program.levels[level] && !roots[level]) return ControlError::invalid_argument;
  return prepare_fragment_origination(program);
}
bool ControlWorker::compose_local_neighbors(OwnedInstance &instance, const DeviceState &device,
    std::size_t index, LocalLspSet &target, RuntimeClock::time_point now, std::size_t &budget) noexcept {
  const auto &origin = *instance.configuration.origination;
  if (!origin.automatic_roots()) return true;
  for (std::size_t level{}; level < 2U; ++level)
    if (!origin.content.levels[level]) instance.local_roots_dirty[level] = false;
  if (!instance.local_roots_dirty[0U] && !instance.local_roots_dirty[1U]) return true;
  if (!budget) return false;
  std::fill(instance.neighbor_projection.begin(), instance.neighbor_projection.end(), OwnedInstance::NeighborProjection{});
  const auto interfaces = origin.neighbors ? std::span<const P2pOriginInterface>{*origin.neighbors} :
      std::span<const P2pOriginInterface>{};
  for (const auto &owned : device.circuits) {
    if (owned.identity.instance != index || owned.lan()) continue;
    const auto found = std::lower_bound(interfaces.begin(), interfaces.end(), owned.identity.interface_id,
        [](const auto &entry, auto id) { return entry.interface_id < id; });
    if (found == interfaces.end() || found->interface_id != owned.identity.interface_id) continue;
    const auto adjacency = owned.p2p().adjacency();
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
    if (!compose_lan_pseudonodes(instance, device, index, level, target, now)) return false;
    if (!instance.fragment_workspace) { instance.status = UpdateStatus::invalid_configuration; return false; }
    auto &workspace = *instance.fragment_workspace;
    workspace.reset();
    std::array<std::uint8_t, 257U> area_bytes{};
    std::optional<std::span<const std::uint8_t>> area_override;
    if (level == 1U && instance.areas) {
      const auto size = encode_area_set_options(instance.areas->effective(), area_bytes);
      if (!size) { instance.status = UpdateStatus::invalid_configuration; return false; }
      area_override = std::span<const std::uint8_t>{area_bytes}.first(*size);
    }
    bool valid = workspace.add_root_options(origin.content, level, area_override);
    if (origin.prefixes) {
      valid = (origin.ipv6_addresses
          ? append_local_af_prefixes(workspace, *origin.prefixes, *origin.ipv6_addresses, level)
          : append_local_prefix_catalog(workspace, *origin.prefixes, level)) && valid;
      if (origin.ipv6_addresses)
        valid = append_local_ipv6_addresses(workspace, *origin.ipv6_addresses, *origin.prefixes) && valid;
    }
    packet::isis::LanId source{};
    std::copy_n(root->id.begin(), source.size(), source.begin());
    for (std::size_t slot{}; slot < interfaces.size(); ++slot) {
      const auto &peer = instance.neighbor_projection[slot];
      if (peer.up && (static_cast<std::uint8_t>(peer.usage) & (1U << level)) && interfaces[slot].levels[level]) {
        packet::isis::LanId neighbor{};
        std::copy(peer.peer.begin(), peer.peer.end(), neighbor.begin());
        valid = workspace.add_link({1U, interfaces[slot].interface_id}, neighbor, *interfaces[slot].levels[level],
            OriginFragmentWorkspace::previous_link(target, level, source, neighbor, 256U)) && valid;
      }
    }
    valid = append_lan_links(instance, device, index, level, workspace, target) && valid;
    std::array<std::uint8_t, 256U> slot_scratch{};
    const auto slots = local_fragment_slots(origin.content, level, source, slot_scratch);
    const auto replaced = valid ? workspace.compose(target, level, source, root->flags, slots,
        origin.content.levels[level]->maximum_pdu_octets - packet::isis::lsp_header_octets, now) : LocalContentResult::capacity;
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
