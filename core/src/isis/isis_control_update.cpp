// Instance databases belong to the IS-IS pthread. Stable heap owners bind local
// authenticated circuit projections to level update processes; no other router
// state enters this module. Parent-owned fences outlive deleted instances.

// Source: iso.10589.2002.runtime_update

#include "router/isis_control_worker.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>

namespace router::isis {
namespace {
bool valid_transmission(const UpdateTransmissionProgram &program) noexcept {
  return program.partial_seconds && program.retransmit_seconds && program.transit_seconds &&
      program.pacing_period.count() > 0 && program.pacing_period <= std::chrono::milliseconds{65535} &&
      program.maximum_pdu_octets >= packet::isis::csnp_header_octets;
}
bool valid_origination(const UpdateInstanceProgram &program) noexcept {
  if (!program.origination) return true;
  const auto &local = program.origination->content;
  for (std::size_t level{}; level < program.levels.size(); ++level) {
    if (static_cast<bool>(local.levels[level]) != static_cast<bool>(program.levels[level])) return false;
    if (!local.levels[level]) continue;
    if (local.levels[level]->maximum_age != program.levels[level]->maximum_age ||
        static_cast<std::size_t>(std::count_if(local.records.begin(), local.records.end(),
            [&](const auto &entry) { return entry.level == level; })) > program.levels[level]->database.records) return false;
  }
  return true;
}
}
ControlWorker::UpdateEgress::UpdateEgress(const OwnedInstance &instance, std::uint64_t seed)
    : random(seed ? seed : 1U) {
  std::size_t capacity{};
  for (const auto &level : instance.configuration.levels) if (level) {
    if (level->database.records > retries.max_size() - capacity)
      throw std::length_error("IS-IS retry metadata capacity exceeds its owner budget");
    capacity += level->database.records;
  }
  retries.reserve(capacity);
}

bool ControlWorker::matches_update_instance(const UpdateInstanceProgram &instance,
    const P2pCircuitConfiguration &circuit) noexcept {
  if (circuit.local.system != instance.local || circuit.maximum_area_addresses != instance.maximum_areas ||
      circuit.wire_instance != instance.wire_instance ||
      circuit.instance_format.value_or(packet::isis::InstanceFormat::standard) != instance.format) return false;
  if (instance.format == packet::isis::InstanceFormat::legacy_2009 && !circuit.instance_topologies.empty()) return false;
  if (instance.format == packet::isis::InstanceFormat::standard && !instance.wire_instance && circuit.emit_instance &&
      (!circuit.physical_point_to_point || !circuit.instance_topologies.empty())) return false;
  if (instance.format == packet::isis::InstanceFormat::standard && instance.wire_instance &&
      (circuit.instance_topologies.size() != 1U || circuit.instance_topologies[0U] != 0U)) return false;
  for (std::size_t level{}; level < 2U; ++level)
    if ((static_cast<std::uint8_t>(circuit.local.levels) & (1U << level)) && !instance.levels[level]) return false;
  return true;
}

void ControlWorker::OwnedInstance::level_event(void *context, const LevelEvent &event) noexcept {
  auto &instance = *static_cast<OwnedInstance *>(context);
  const auto index = event.level == packet::isis::PduType::lsp_l2 ? 1U : 0U;
  if (event.kind == LevelEventKind::database_corrupted) { instance.corrupted_lsp = event.id; return; }
  if (event.kind == LevelEventKind::database_changed || event.kind == LevelEventKind::circuit_changed ||
      event.kind == LevelEventKind::validation_completed) {
    if (instance.decision_revisions[index] == std::numeric_limits<std::uint64_t>::max())
      instance.status = UpdateStatus::epoch_exhausted;
    else ++instance.decision_revisions[index];
  }
  if (event.kind == LevelEventKind::validation_completed) {
    if (instance.database_validations[index] != std::numeric_limits<std::uint64_t>::max())
      ++instance.database_validations[index];
    return;
  }
  if (instance.revision[index] == std::numeric_limits<std::uint64_t>::max())
    instance.status = UpdateStatus::epoch_exhausted;
  else ++instance.revision[index];
  if (instance.local && (event.kind == LevelEventKind::overload_entered || event.kind == LevelEventKind::overload_recovered))
    static_cast<void>(instance.local->waiting_overload(index, event.kind == LevelEventKind::overload_entered, RuntimeClock::now()));
}

UpdateCircuitConfiguration ControlWorker::update_configuration(const OwnedCircuit &owned) noexcept {
  // RFC 5309 permits AllISs, AllL1ISs or AllL2ISs for logical P2P PDUs.
  // This experimental transport supplies its explicitly selected multicast
  // group for both levels; production per-level group selection is separate.
  return {owned.identity.configuration_generation, owned.circuit.configuration().local.levels,
      owned.physical_point_to_point, owned.format, owned.wire_instance,
      {owned.destination, owned.destination}};
}

ControlError ControlWorker::add_update_instance(ControlCommand &command, DeviceState &device) noexcept {
  const auto index = command.identity.instance;
  if (!command.update || !command.update->maximum_circuits ||
      command.update->maximum_circuits > maximum_circuits_ ||
      !valid_transmission(command.update->transmission) ||
      !valid_origination(*command.update) ||
      command.update->format > packet::isis::InstanceFormat::standard) return ControlError::invalid_argument;
  if (device.instances[index]) return ControlError::already_exists;
  const auto now = RuntimeClock::now();
  const auto &previous_recovery = device.sequence_recovery[index];
  if (previous_recovery && previous_recovery->disabled() && !previous_recovery->ready(now))
    return ControlError::sequence_cooldown;
  // Nonzero update instances need their per-level multicast projection first.
  // Hello transport alone must not silently enable an incomplete MI database.
  if (command.update->wire_instance) return ControlError::unsupported_update_instance;
  if (device.update_fences[index] == std::numeric_limits<std::uint64_t>::max()) return ControlError::epoch_exhausted;
  for (const auto &level : command.update->levels)
    if (level && (level->authenticate_lsp || level->authenticate_csnp || level->authenticate_psnp))
      return ControlError::unsupported_authentication;
  try {
    std::unique_ptr<SequenceRecovery> recovery;
    if (command.update->origination) {
      std::array<std::optional<SequenceLevelLifetime>, 2U> lifetimes;
      for (std::size_t level{}; level < lifetimes.size(); ++level)
        if (command.update->levels[level]) lifetimes[level] = SequenceLevelLifetime{
            command.update->levels[level]->maximum_age,
            static_cast<std::uint16_t>(command.update->levels[level]->purge_retention.count())};
      recovery = std::make_unique<SequenceRecovery>(lifetimes, command.update->origination->resource_retry);
    }
    std::vector<UpdateCircuitConfiguration> slots;
    std::vector<std::size_t> bindings;
    for (std::size_t ordinal{}; ordinal < device.circuits.size(); ++ordinal) {
      const auto &owned = device.circuits[ordinal];
      if (owned.identity.instance != index) continue;
      const auto &configuration = owned.circuit.configuration();
      if (!matches_update_instance(*command.update, configuration))
        return ControlError::invalid_argument;
      for (const auto previous : bindings)
        if (device.circuits[previous].circuit.configuration().local.extended_circuit ==
            configuration.local.extended_circuit) return ControlError::already_exists;
      slots.push_back(update_configuration(owned));
      bindings.push_back(ordinal);
    }
    auto instance = std::make_unique<OwnedInstance>(std::move(*command.update), slots,
        device.update_fences[index] + 1U);
    if (instance->local) {
      auto budget = instance->configuration.origination->content.active_records();
      const auto generated = instance->local->service(*instance->process, {}, RuntimeClock::now(),
          scratch_, instance->observer(), budget);
      if (generated.published != instance->configuration.origination->content.active_records() || generated.blocked ||
          generated.terminal != GenerationStatus::waiting) return ControlError::update_refused;
    }
    std::vector<std::unique_ptr<UpdateEgress>> egress;
    egress.reserve(bindings.size());
    for (const auto binding : bindings)
      egress.push_back(std::make_unique<UpdateEgress>(*instance, device.circuits[binding].random_state));
    for (std::size_t slot{}; slot < bindings.size(); ++slot) {
      const auto &owned = device.circuits[bindings[slot]];
      const auto adjacency = owned.circuit.adjacency();
      if (!adjacency.iso_up) continue;
      // This is the same owner's already authenticated local projection,
      // never topology-derived peer information or an inter-router shortcut.
      P2pCircuitEvent event{};
      event.after = adjacency;
      event.transition.outcome = P2pOutcome::up;
      if (instance->process->p2p(slot, owned.identity.configuration_generation,
          event, instance->observer()) != UpdateStatus::applied) return ControlError::update_refused;
    }
    for (std::size_t slot{}; slot < bindings.size(); ++slot) {
      auto &owned = device.circuits[bindings[slot]];
      owned.update = instance.get();
      owned.update_slot = slot;
      owned.update_egress = std::move(egress[slot]);
      if (!owned.circuit.operational()) static_cast<void>(owned.circuit.up(RuntimeClock::now()));
    }
    device.instances[index] = std::move(instance);
    device.sequence_recovery[index] = std::move(recovery);
    device.instance_order[device.instance_count++] = index;
    return ControlError::none;
  } catch (const std::bad_alloc &) { return ControlError::capacity; }
    catch (const std::exception &) { return ControlError::construction_failed; }
}

ControlError ControlWorker::attach_update_circuit(DeviceState &device, OwnedCircuit &owned) noexcept {
  auto &instance = device.instances[owned.identity.instance];
  if (!instance) return ControlError::none;
  if (instance->status != UpdateStatus::applied && !requires_reconstruction(instance->status))
    return ControlError::update_refused;
  const auto &configuration = owned.circuit.configuration();
  if (!matches_update_instance(instance->configuration, configuration))
    return ControlError::invalid_argument;
  for (const auto &other : device.circuits)
    if (&other != &owned && other.identity.instance == owned.identity.instance &&
        other.circuit.configuration().local.extended_circuit == configuration.local.extended_circuit)
      return ControlError::already_exists;
  if (requires_reconstruction(instance->status)) {
    const auto count = std::count_if(device.circuits.begin(), device.circuits.end(), [&](const auto &other) {
      return other.identity.instance == owned.identity.instance;
    });
    // The caller already appended this candidate to the device vector.
    if (static_cast<std::size_t>(count) > instance->configuration.maximum_circuits) return ControlError::capacity;
    owned.update = instance.get();
    static_cast<void>(owned.circuit.down(&owned, event));
    return ControlError::none;
  }
  if (!instance->process) return ControlError::update_refused;
  std::unique_ptr<UpdateEgress> egress;
  try { egress = std::make_unique<UpdateEgress>(*instance, owned.random_state); }
  catch (const std::bad_alloc &) { return ControlError::capacity; }
  catch (const std::exception &) { return ControlError::invalid_argument; }
  const auto admission = instance->process->admit_circuit(update_configuration(owned));
  if (admission.status != UpdateStatus::applied)
    return admission.status == UpdateStatus::capacity ? ControlError::capacity : ControlError::update_refused;
  owned.update = instance.get();
  owned.update_slot = *admission.index;
  owned.update_egress = std::move(egress);
  return ControlError::none;
}

void ControlWorker::remove_update_instance(DeviceState &device, std::size_t index) noexcept {
  auto &instance = device.instances[index];
  if (!instance) return;
  for (auto &owned : device.circuits) if (owned.update == instance.get()) {
    owned.transmission.cancel();
    static_cast<void>(owned.circuit.down(&owned, event));
    owned.update = nullptr;
    owned.update_egress.reset();
  }
  if (instance->process)
    device.update_fences[index] = std::max(device.update_fences[index],
        instance->process->maximum_synchronization_epoch());
  instance.reset();
  const auto end = device.instance_order.begin() + device.instance_count;
  const auto position = std::find(device.instance_order.begin(), end, static_cast<std::uint8_t>(index));
  if (position == end) std::terminate();
  *position = device.instance_order[--device.instance_count];
  if (device.first_instance >= device.instance_count) device.first_instance = 0U;
}
} // namespace router::isis
