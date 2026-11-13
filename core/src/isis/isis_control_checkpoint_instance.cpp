// Detached instance restoration retains stable heap ownership and last complete
// decisions. Normal admission validates desired policy; mutable child snapshots
// restore separately. No callback, origination or route publication is invoked.

#include "router/isis_control_checkpoint.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
std::unique_ptr<ControlWorker::OwnedInstance> ControlWorker::restore_checkpoint_instance(
    const ControlInstanceCheckpoint &saved, RuntimeClock::time_point now) const noexcept {
  if (saved.instance > device_catalog::isis_instance_last || saved.first_root_level > 1U ||
      saved.status > UpdateStatus::adjacency || (!saved.process && (saved.local || saved.status == UpdateStatus::applied ||
          !saved.configuration.origination))) return nullptr;
  try {
    auto configuration = saved.configuration;
    const bool automatic = configuration.origination && configuration.origination->automatic_roots();
    if (automatic) std::erase_if(configuration.origination->content.records, [](const auto &record) { return record.id[6U] != 0U; });
    if (validate_update_program(configuration) != ControlError::none) return nullptr;
    if (automatic) for (auto &record : configuration.origination->content.records) if (record.id[6U]) {
      const auto &original = saved.configuration.origination->content.records;
      const auto found = std::find_if(original.begin(), original.end(), [&](const auto &value) {
        return value.level == record.level && value.id == record.id;
      });
      if (found == original.end() || found->active || !found->options.empty() ||
          ((found->flags & 3U) != 1U && (found->flags & 3U) != 3U) || (found->level && (found->flags & 3U) != 3U)) return nullptr;
      // Root edits can leave a reserved pseudonode's original type flags in
      // desired policy. Preserve that valid value rather than regenerate it.
      record.flags = found->flags;
    }
    if (configuration != saved.configuration) return nullptr;
    const auto selector = UpdateInstanceSelector{configuration.format, configuration.wire_instance};
    if (!saved.process) {
      // A removed process has no child image to validate level storage policy.
      // Construct and destroy only a cold empty repository; no PDU is emitted.
      auto validation = std::make_unique<InstanceUpdateProcess>(configuration.local, configuration.maximum_areas,
          configuration.levels, std::span<const UpdateCircuitConfiguration>{}, selector, configuration.maximum_circuits);
      static_cast<void>(validation);
    }
    auto result = std::make_unique<OwnedInstance>(std::move(configuration), std::span<const UpdateCircuitConfiguration>{},
        std::uint64_t{1U}, true);
    const auto &policy = result->configuration;
    if (saved.process) {
      const auto &source = *saved.process;
      std::vector<UpdateCircuitConfiguration> slots;
      slots.reserve(source.circuits.size());
      for (const auto &slot : source.circuits) slots.push_back(slot.configuration);
      const InstanceUpdateConfiguration expected{policy.local, policy.maximum_areas, policy.levels, selector,
          policy.maximum_circuits, source.configuration.initial_synchronization_epoch};
      result->process = InstanceUpdateProcess::restore_checkpoint(source, expected, slots, now);
      if (!result->process) return nullptr;
    }
    result->local.reset();
    if (saved.local.has_value() != (policy.origination.has_value() && saved.process.has_value())) return nullptr;
    if (saved.local) {
      result->local = LocalLspSet::restore_checkpoint(*saved.local, policy.local, policy.maximum_areas, selector,
          policy.origination->content, now);
      if (!result->local || !result->local->reserve_publication(*result->process)) return nullptr;
    }
    const auto restore_decision = [](const auto &image, const auto &program) {
      return P2pRouteDecision::restore_checkpoint(image,
          {program.nodes, program.links, program.pending, MetricStyle::wide, program.prefixes});
    };
    for (std::size_t level{}; level < 2U; ++level) {
      const bool diagnostic = policy.decision.has_value() && policy.levels[level].has_value();
      if (saved.decisions[level].has_value() != diagnostic || saved.decision_status[level] > DecisionStatus::calculation_failed ||
          saved.consumed_decision_revision[level] > saved.decision_revisions[level] ||
          saved.validation[level].has_value() != result->validation[level].has_value()) return nullptr;
      result->decisions[level].reset();
      if (saved.decisions[level]) {
        result->decisions[level] = restore_decision(*saved.decisions[level], *policy.decision);
        if (!result->decisions[level]) return nullptr;
      }
      if (saved.validation[level] && !result->validation[level]->restore(*saved.validation[level], now)) return nullptr;
      const auto &blocked = saved.expiration_blocked[level];
      if (blocked.size() > result->expiration_blocked[level].capacity()) return nullptr;
      auto ordered = blocked;
      std::sort(ordered.begin(), ordered.end());
      if (std::adjacent_find(ordered.begin(), ordered.end()) != ordered.end()) return nullptr;
      result->expiration_blocked[level].assign(blocked.begin(), blocked.end());
      for (std::size_t family{}; family < result->route_families.size(); ++family) {
        auto &target = result->route_families[family];
        const auto &source = saved.families[family];
        const bool enabled = policy.routing[family].has_value() && policy.levels[level].has_value();
        if (source.decisions[level].has_value() != enabled || source.status[level] > DecisionStatus::calculation_failed ||
            source.consumed[level] > saved.decision_revisions[level] ||
            source.bindings[level].size() > target.bindings[level].capacity()) return nullptr;
        target.decisions[level].reset();
        if (source.decisions[level]) {
          target.decisions[level] = restore_decision(*source.decisions[level], policy.routing[family]->calculation);
          if (!target.decisions[level] || (!source.decisions[level]->identities.empty() &&
              source.decisions[level]->paths.first_hop_count != source.bindings[level].size())) return nullptr;
        }
        for (const auto &binding : source.bindings[level]) if (binding) {
          const auto &address = binding->address;
          if (binding->level != level + 1U || !binding->interface.interface_id || !binding->interface.configuration_generation ||
              binding->interface.physical_port_ordinal >= device_catalog::maximum_ports_per_router ||
              address.family != (family ? ip::AddressFamily::ipv6 : ip::AddressFamily::ipv4)) return nullptr;
          if (!family && (address.bytes[0U] == 0U || address.bytes[0U] == 127U || address.bytes[0U] >= 224U ||
              std::any_of(address.bytes.begin() + 4, address.bytes.end(), [](auto byte) { return byte != 0U; }))) return nullptr;
          if (family && (address.bytes[0U] == 0xffU ||
              std::all_of(address.bytes.begin(), address.bytes.end(), [](auto byte) { return byte == 0U; }))) return nullptr;
        }
        // These are the last successful decision's bindings, which can name a
        // retired interface. Rechecking against today's adjacency would lose
        // a legitimate installed generation while withdrawal is still pending.
        target.bindings[level].assign(source.bindings[level].begin(), source.bindings[level].end());
        target.consumed[level] = source.consumed[level];
        target.status[level] = source.status[level];
      }
    }
    result->consumed_decision_revision = saved.consumed_decision_revision;
    result->decision_runs = saved.decision_runs;
    result->decision_status = saved.decision_status;
    result->local_roots_dirty = saved.local_roots_dirty;
    result->first_root_level = saved.first_root_level;
    result->database_validations = saved.database_validations;
    result->decision_revisions = saved.decision_revisions;
    result->revision = saved.revision;
    result->expiration_revision = saved.expiration_revision;
    result->corrupted_lsp = saved.corrupted_lsp;
    result->status = saved.status;
    result->admin_enabled = saved.admin_enabled;
    for (std::size_t level{}; level < 2U; ++level) {
      if (static_cast<bool>(result->spf[level]) != saved.spf[level].has_value()) return nullptr;
      if (saved.spf[level] && (!result->spf[level]->restore(*saved.spf[level], now) ||
          (saved.spf[level]->pending_nanoseconds && !result->level_decisions_pending(level)))) return nullptr;
    }
    return result;
  } catch (const std::exception &) { return nullptr; }
}
} // namespace router::isis
