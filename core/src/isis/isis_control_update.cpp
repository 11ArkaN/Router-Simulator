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
bool ControlWorker::valid_transmission(const UpdateTransmissionProgram &program) noexcept {
  const auto maximum = std::chrono::milliseconds{65535};
  if (program.broadcast && (program.broadcast->lsp_scan_interval < std::chrono::microseconds::zero() ||
      program.broadcast->lsp_scan_interval > maximum || program.broadcast->csnp_separation <= std::chrono::microseconds::zero() ||
      program.broadcast->csnp_separation > maximum)) return false;
  return program.partial_seconds && program.retransmit_seconds && program.transit_seconds &&
      program.pacing_period.count() > 0 && program.pacing_period <= std::chrono::milliseconds{65535} &&
      program.maximum_pdu_octets >= packet::isis::csnp_header_octets;
}

bool ControlWorker::valid_medium_transmission(const UpdateTransmissionProgram &program,
    CircuitUpdateView circuit) noexcept {
  return valid_transmission(program) && program.broadcast.has_value() == circuit.broadcast &&
      (!circuit.broadcast || program.complete_seconds);
}

ControlWorker::UpdateEgress::UpdateEgress(const OwnedInstance &instance, std::uint64_t seed,
    const std::optional<UpdateTransmissionProgram> &override_program)
    : program(override_program.value_or(instance.configuration.transmission)), random(seed ? seed : 1U) {
  if (program.broadcast) {
    auto scan_seed = random ^ 0x4c414eU;
    if (!scan_seed) scan_seed = random;
    if (program.broadcast->lsp_scan_interval.count())
      broadcast_scan.emplace(program.broadcast->lsp_scan_interval, scan_seed, RuntimeClock::now());
    return;
  }
  std::size_t capacity{};
  for (const auto &level : instance.configuration.levels) if (level) {
    if (level->database.records > retries.max_size() - capacity)
      throw std::length_error("IS-IS retry metadata capacity exceeds its owner budget");
    capacity += level->database.records;
  }
  retries.reserve(capacity);
}

bool ControlWorker::matches_update_instance(const UpdateInstanceProgram &instance,
    CircuitUpdateView view, std::uint64_t interface_id) noexcept {
  const auto &circuit = view.hello;
  if (view.system != instance.local || circuit.maximum_area_addresses != instance.maximum_areas ||
      circuit.wire_instance != instance.wire_instance ||
      circuit.instance_format.value_or(packet::isis::InstanceFormat::standard) != instance.format) return false;
  if (instance.format == packet::isis::InstanceFormat::legacy_2009 && !circuit.instance_topologies.empty()) return false;
  if (instance.format == packet::isis::InstanceFormat::standard && !instance.wire_instance && circuit.emit_instance &&
      (!view.physical_point_to_point || !circuit.instance_topologies.empty())) return false;
  if (instance.format == packet::isis::InstanceFormat::standard && instance.wire_instance &&
      (circuit.instance_topologies.size() != 1U || circuit.instance_topologies[0U] != 0U)) return false;
  for (std::size_t level{}; level < 2U; ++level)
    if ((static_cast<std::uint8_t>(view.levels) & (1U << level)) && !instance.levels[level]) return false;
  if (view.broadcast && instance.origination &&
      (instance.origination->neighbors || instance.origination->broadcast_neighbors)) {
    if (!instance.origination->broadcast_neighbors) return false;
    const auto &interfaces = *instance.origination->broadcast_neighbors;
    const auto found = std::lower_bound(interfaces.begin(), interfaces.end(), interface_id,
        [](const auto &entry, auto id) { return entry.interface_id < id; });
    if (found == interfaces.end() || found->interface_id != interface_id || found->circuit != view.circuit_id ||
        found->maximum_neighbors < view.neighbor_capacity) return false;
    for (std::size_t level{}; level < 2U; ++level)
      if ((static_cast<std::uint8_t>(view.levels) & (1U << level)) && !found->levels[level]) return false;
    if (std::any_of(circuit.topologies.begin(), circuit.topologies.end(), [](const auto &entry) { return entry.id != 0U; })) return false;
    return true;
  }
  if (!view.broadcast && instance.origination && instance.origination->broadcast_neighbors && !instance.origination->neighbors)
    return false;
  if (instance.origination && instance.origination->neighbors) {
    // This composer owns MT0 only. A common nonzero topology must not make an
    // adjacency eligible for a fabricated MT0 advertisement.
    if (std::any_of(circuit.topologies.begin(), circuit.topologies.end(), [](const auto &entry) { return entry.id != 0U; }) ||
        std::any_of(circuit.instance_topologies.begin(), circuit.instance_topologies.end(), [](auto id) { return id != 0U; }))
      return false;
    const auto &interfaces = *instance.origination->neighbors;
    const auto found = std::lower_bound(interfaces.begin(), interfaces.end(), interface_id,
        [](const auto &entry, auto id) { return entry.interface_id < id; });
    if (found == interfaces.end() || found->interface_id != interface_id) return false;
    for (std::size_t level{}; level < 2U; ++level)
      if ((static_cast<std::uint8_t>(view.levels) & (1U << level)) && !found->levels[level]) return false;
  }
  return true;
}

void ControlWorker::OwnedInstance::level_event(void *context, const LevelEvent &event) noexcept {
  auto &instance = *static_cast<OwnedInstance *>(context);
  const auto index = event.level == packet::isis::PduType::lsp_l2 ? 1U : 0U;
  if (event.kind == LevelEventKind::circuit_changed) instance.local_roots_dirty[index] = true;
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
  const auto view = owned.update_view();
  return {owned.identity.configuration_generation, view.levels,
      view.physical_point_to_point, owned.format, owned.wire_instance, owned.destinations.levels,
      view.broadcast, view.neighbor_capacity};
}

ControlError ControlWorker::validate_update_program(UpdateInstanceProgram &program) const noexcept {
  if (!program.maximum_circuits || program.maximum_circuits > maximum_circuits_ || !valid_transmission(program.transmission) ||
      !valid_origination(program) || (program.spf_delay && !valid_spf_delay_policy(*program.spf_delay)) ||
      program.format > packet::isis::InstanceFormat::standard) return ControlError::invalid_argument;
  if (program.wire_instance) return ControlError::unsupported_update_instance;
  for (const auto &level : program.levels)
    if (level && (level->authenticate_lsp || level->authenticate_csnp || level->authenticate_psnp))
      return ControlError::unsupported_authentication;
  if (program.origination && program.origination->automatic_area_set &&
      (!program.levels[0U] || !program.decision || program.decision->protocol || program.decision->prefixes ||
          program.maximum_areas > configuration_profile::area_addresses_maximum)) return ControlError::invalid_argument;
  if (program.origination && program.origination->automatic_area_attachment &&
      (!program.origination->automatic_area_set || !program.levels[0U] || !program.levels[1U] || !program.decision ||
          program.decision->protocol || program.decision->prefixes)) return ControlError::invalid_argument;
  const bool routing = std::any_of(program.routing.begin(), program.routing.end(),
      [](const auto &family) { return family.has_value(); });
  if ((program.decision || routing) && (!program.origination ||
      (!program.origination->neighbors && !program.origination->broadcast_neighbors)))
    return ControlError::unsupported_origination;
  if (program.decision) {
    const auto protocol = program.decision->protocol;
    if ((protocol && *protocol != packet::isis::ipv4_nlpid && *protocol != packet::isis::ipv6_nlpid) ||
        (program.decision->prefixes && !protocol)) return ControlError::invalid_argument;
  }
  for (std::size_t family{}; family < program.routing.size(); ++family)
    if (program.routing[family]) {
      const auto &routing_program = *program.routing[family];
      const auto protocol = family ? packet::isis::ipv6_nlpid : packet::isis::ipv4_nlpid;
      if (routing_program.calculation.protocol != protocol || !routing_program.calculation.prefixes)
        return ControlError::invalid_argument;
      for (std::size_t level{}; level < routing_program.preferences.size(); ++level) if (program.levels[level]) {
        const auto &preference = routing_program.preferences[level];
        if (!preference.internal || preference.internal > 255U || !preference.external || preference.external > 255U)
          return ControlError::invalid_argument;
      }
    }
  const auto neighbor_error = prepare_neighbor_origination(program);
  if (neighbor_error != ControlError::none) return neighbor_error;
  if ((program.decision || routing) && !catalog_budget(*program.origination)) return ControlError::capacity;
  return ControlError::none;
}

ControlError ControlWorker::add_update_instance(ControlCommand &command, DeviceState &device,
    const OwnedInstance *sequence_source) noexcept {
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
  const auto valid_program = validate_update_program(*command.update);
  if (valid_program != ControlError::none) return valid_program;
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
      const auto view = owned.update_view();
      if (!valid_medium_transmission(owned.update_transmission.value_or(command.update->transmission), view))
        return ControlError::unsupported_update_medium;
      if (!matches_update_instance(*command.update, owned.update_view(), owned.identity.interface_id))
        return ControlError::invalid_argument;
      for (const auto previous : bindings)
        if (const auto other = device.circuits[previous].update_view();
            other.broadcast == view.broadcast && other.circuit_id == view.circuit_id) return ControlError::already_exists;
      slots.push_back(update_configuration(owned));
      bindings.push_back(ordinal);
    }
    auto instance = std::make_unique<OwnedInstance>(std::move(*command.update), slots,
        device.update_fences[index] + 1U);
    instance->admin_enabled = command.admin_enabled;
    if (instance->local) {
      // The detached owner has not published or consumed a spacing deadline.
      // Carry matching own-ID floors before its first generation, without
      // copying the LSDB or any received peer state into the new entity.
      if (sequence_source && sequence_source->configuration.local == instance->configuration.local)
        for (const auto &record : instance->configuration.origination->content.records) {
          auto floor = sequence_source->local ? sequence_source->local->sequence_floor(record.level, record.id).value_or(0U) : 0U;
          if (sequence_source->process) if (const auto *source_level = sequence_source->process->level(record.level))
            if (const auto stored = source_level->database().database().find(record.id, now))
              floor = std::max(floor, stored->header.sequence);
          if (floor && !instance->local->require_after(record.level, record.id, floor, now)) return ControlError::update_refused;
        }
      std::size_t composition_budget{2U};
      if (!compose_local_neighbors(*instance, device, index, *instance->local, now, composition_budget))
        return ControlError::update_refused;
      const auto expected = static_cast<std::size_t>(std::count_if(instance->configuration.origination->content.records.begin(),
          instance->configuration.origination->content.records.end(), [&](const auto &record) {
            return instance->local->contains(record.level, record.id);
          }));
      auto budget = expected;
      const auto generated = instance->local->service(*instance->process, {}, RuntimeClock::now(),
          scratch_, instance->observer(), budget);
      if (generated.published != expected || generated.blocked ||
          generated.terminal != GenerationStatus::waiting) return ControlError::update_refused;
    }
    std::vector<std::unique_ptr<UpdateEgress>> egress;
    egress.reserve(bindings.size());
    for (const auto binding : bindings)
      egress.push_back(std::make_unique<UpdateEgress>(*instance, device.circuits[binding].random_state, device.circuits[binding].update_transmission));
    for (std::size_t slot{}; slot < bindings.size(); ++slot) {
      auto &owned = device.circuits[bindings[slot]];
      // A disabled detached owner does not import a transport-only Up peer.
      // Leave the live medium untouched until every fallible projection passed.
      if (!instance->admin_enabled) continue;
      if (auto *broadcast = owned.lan()) {
        for (std::size_t level{}; level < 2U; ++level) if (broadcast->at(level) &&
            project_lan(owned, *instance, slot, level) != UpdateStatus::applied) return ControlError::update_refused;
        continue;
      }
      const auto adjacency = owned.p2p().adjacency();
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
      if (!instance->admin_enabled) circuit_down(owned);
      owned.update = instance.get();
      owned.update_slot = slot;
      owned.update_egress = std::move(egress[slot]);
      circuit_up(owned, RuntimeClock::now());
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
  const auto view = owned.update_view();
  if (!valid_medium_transmission(owned.update_transmission.value_or(instance->configuration.transmission), view))
    return ControlError::unsupported_update_medium;
  if (!matches_update_instance(instance->configuration, owned.update_view(), owned.identity.interface_id))
    return ControlError::invalid_argument;
  for (const auto &other : device.circuits)
    if (&other != &owned && other.identity.instance == owned.identity.instance &&
        other.update_view().broadcast == view.broadcast && other.update_view().circuit_id == view.circuit_id)
      return ControlError::already_exists;
  if (requires_reconstruction(instance->status)) {
    const auto count = std::count_if(device.circuits.begin(), device.circuits.end(), [&](const auto &other) {
      return other.identity.instance == owned.identity.instance;
    });
    // The caller already appended this candidate to the device vector.
    if (static_cast<std::size_t>(count) > instance->configuration.maximum_circuits) return ControlError::capacity;
    owned.update = instance.get();
    circuit_down(owned);
    return ControlError::none;
  }
  if (!instance->process) return ControlError::update_refused;
  std::unique_ptr<UpdateEgress> egress;
  try { egress = std::make_unique<UpdateEgress>(*instance, owned.random_state, owned.update_transmission); }
  catch (const std::bad_alloc &) { return ControlError::capacity; }
  catch (const std::exception &) { return ControlError::invalid_argument; }
  const auto admission = instance->process->admit_circuit(update_configuration(owned));
  if (admission.status != UpdateStatus::applied)
    return admission.status == UpdateStatus::capacity ? ControlError::capacity : ControlError::update_refused;
  if (!instance->admin_enabled) circuit_down(owned);
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
    circuit_down(owned);
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
