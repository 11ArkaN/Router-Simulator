// The IS-IS pthread publishes current local LSPs and owns entity-wide sequence
// recovery. Parent gates survive instance deletion. A stable shell releases old
// LSDB storage before reconstruction; no network information bypasses a port.
// Source: iso.10589.2002.local_lsp_generation

#include "router/isis_control_worker.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace router::isis {
ControlError ControlWorker::edit_local_content(ControlCommand &command, OwnedInstance &instance,
    ControlResult &result) noexcept {
  if (!command.local_content) return ControlError::invalid_argument;
  if (instance.status != UpdateStatus::applied || !instance.local) return ControlError::update_refused;
  auto &value = *command.local_content;
  auto &records = instance.configuration.origination->content.records;
  const auto desired = std::find_if(records.begin(), records.end(), [&](const auto &record) {
    return record.level == value.level && record.id == value.id;
  });
  if (desired == records.end()) return ControlError::not_found;
  const bool withdrawing = command.kind == ControlCommandKind::withdraw_local_content;
  result.local_content_result = withdrawing ? instance.local->withdraw(value.level, value.id) :
      instance.local->replace(value.level, value.id, value.flags, value.options, RuntimeClock::now());
  switch (result.local_content_result) {
  case LocalContentResult::missing: return ControlError::not_found;
  case LocalContentResult::invalid: return ControlError::invalid_argument;
  case LocalContentResult::capacity: return ControlError::capacity;
  case LocalContentResult::changed:
  case LocalContentResult::unchanged: break;
  }
  // Local replacement cannot allocate. The transferred command already owns
  // the desired bytes, so committing the reconstruction program is a no-throw
  // swap after validation. A rejected edit changes neither semantic owner.
  desired->active = !withdrawing;
  if (!withdrawing) {
    desired->flags = value.flags;
    desired->options.swap(value.options);
  }
  return ControlError::none;
}
RuntimeClock::time_point ControlWorker::service_local_instance(DeviceState &device, std::size_t index,
    RuntimeClock::time_point now, std::size_t &budget) noexcept {
  auto &instance = *device.instances[index];
  auto &gate = device.sequence_recovery[index];
  const auto never = RuntimeClock::time_point::max();
  if (requires_reconstruction(instance.status)) {
    if (!gate) { instance.status = UpdateStatus::invalid_configuration; return never; }
    if (!gate->ready(now)) return gate->deadline().value_or(never);
    // Prepared generations borrow process slots. Their commit/abort command
    // wakes this owner; waiting for that event must not poll an expired timer.
    if (prepared_ && prepared_->device == device.handle) return never;
    return rebuild_local_instance(device, index, now);
  }
  if (instance.status != UpdateStatus::applied || !instance.local) return never;
  if (!instance.process || !gate) { instance.status = UpdateStatus::invalid_configuration; return never; }
  auto validation_deadline = never;
  for (std::size_t level{}; level < instance.validation.size(); ++level) {
    if (!instance.validation[level]) continue;
    const auto *owner = instance.process->level(level);
    const auto checked = instance.validation[level]->service(owner->database().database(), now, budget);
    const auto type = level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1;
    if (checked.status == DatabaseValidationStatus::corrupted) {
      OwnedInstance::level_event(&instance, {LevelEventKind::database_corrupted, type, checked.corrupted});
      // Conservatively use the existing full lifetime cooldown before starting
      // fresh counters. No potentially corrupt database is used for forwarding
      // or flooding while correction and reacquisition are pending.
      return stop_local_instance(device, index, UpdateStatus::database_corrupted);
    }
    if (checked.status == DatabaseValidationStatus::complete)
      OwnedInstance::level_event(&instance, {LevelEventKind::validation_completed, type, std::nullopt});
    validation_deadline = std::min(validation_deadline, instance.validation[level]->deadline().value_or(never));
  }
  if (instance.status != UpdateStatus::applied)
    return stop_local_instance(device, index, instance.status);
  // Runtime authentication selection is not admitted yet. No unsigned output
  // may replace this explicit transmit policy when key leases are integrated.
  const auto generated = instance.local->service(*instance.process, {}, now, scratch_, instance.observer(), budget);
  if (generated.terminal == GenerationStatus::waiting)
    return std::min(validation_deadline, generated.deadline.value_or(never));
  return stop_local_instance(device, index, generated.terminal == GenerationStatus::sequence_exhausted ?
      UpdateStatus::sequence_exhausted : UpdateStatus::epoch_exhausted);
}
RuntimeClock::time_point ControlWorker::stop_local_instance(DeviceState &device, std::size_t index,
    UpdateStatus reason) noexcept {
  auto &instance = *device.instances[index];
  const auto never = RuntimeClock::time_point::max();
  // Down must reach the old process while it still accepts its local circuit
  // events. No process reservation survives the stopped entity's restart.
  for (auto &owned : device.circuits) if (owned.update == &instance) {
    owned.transmission.cancel();
    static_cast<void>(owned.circuit.down(&owned, event));
  }
  device.update_fences[index] = std::max(device.update_fences[index], instance.process->maximum_synchronization_epoch());
  instance.status = reason;
  if (!requires_reconstruction(reason)) return never;
  // Anchor after all Down callbacks, so their execution cannot shorten the
  // minimum interval for which the complete entity must remain disabled.
  auto &gate = device.sequence_recovery[index];
  if (!gate || !gate->begin(RuntimeClock::now())) {
    instance.status = UpdateStatus::invalid_event;
    return never;
  }
  return gate->deadline().value_or(never);
}
RuntimeClock::time_point ControlWorker::rebuild_local_instance(DeviceState &device, std::size_t index,
    RuntimeClock::time_point now) noexcept {
  auto &instance = *device.instances[index];
  auto &gate = *device.sequence_recovery[index];
  const auto never = RuntimeClock::time_point::max();
  if (device.update_fences[index] == std::numeric_limits<std::uint64_t>::max()) {
    instance.status = UpdateStatus::epoch_exhausted;
    return never;
  }
  for (auto &owned : device.circuits) if (owned.identity.instance == index) {
    owned.transmission.cancel();
    static_cast<void>(owned.circuit.down(&owned, event));
    owned.update_egress.reset();
  }
  // The old entity is disabled and no prepared admission borrows it. Free
  // payloads and metadata before allocating a replacement, rather than needing
  // memory for two complete databases. Desired configuration stays in the shell.
  instance.local.reset();
  instance.process.reset();
  instance.revision.fill(0U);
  instance.expiration_revision.fill(0U);
  for (auto &blocked : instance.expiration_blocked) blocked.clear();
  try {
    std::vector<UpdateCircuitConfiguration> slots;
    std::vector<std::size_t> bindings;
    for (std::size_t ordinal{}; ordinal < device.circuits.size(); ++ordinal) {
      const auto &owned = device.circuits[ordinal];
      if (owned.identity.instance != index) continue;
      if (!matches_update_instance(instance.configuration, owned.circuit.configuration()))
        throw std::invalid_argument("IS-IS recovery circuit does not match its entity");
      slots.push_back(update_configuration(owned));
      bindings.push_back(ordinal);
    }
    const auto &configuration = instance.configuration;
    auto process = std::make_unique<InstanceUpdateProcess>(configuration.local, configuration.maximum_areas,
        configuration.levels, slots, UpdateInstanceSelector{configuration.format, configuration.wire_instance},
        configuration.maximum_circuits, device.update_fences[index] + 1U);
    auto local = std::make_unique<LocalLspSet>(configuration.local, configuration.maximum_areas,
        UpdateInstanceSelector{configuration.format, configuration.wire_instance}, configuration.origination->content, now);
    std::vector<std::unique_ptr<UpdateEgress>> egress;
    egress.reserve(bindings.size());
    for (const auto binding : bindings)
      egress.push_back(std::make_unique<UpdateEgress>(instance, device.circuits[binding].random_state));
    auto budget = configuration.origination->content.active_records();
    const auto generated = local->service(*process, {}, now, scratch_, instance.observer(), budget);
    if (generated.blocked || generated.published != configuration.origination->content.active_records() ||
        generated.terminal != GenerationStatus::waiting) {
      static_cast<void>(gate.resource_failed(RuntimeClock::now()));
      return gate.deadline().value_or(never);
    }
    // Initial publication notifies this stable shell. Counter exhaustion in
    // that observer is terminal and must not be overwritten by activation.
    if (!requires_reconstruction(instance.status)) return never;
    instance.reset_validation(now);
    if (!gate.recovered(now)) { instance.status = UpdateStatus::invalid_event; return never; }
    instance.process = std::move(process);
    instance.local = std::move(local);
    instance.status = UpdateStatus::applied;
    instance.corrupted_lsp.reset();
    for (std::size_t slot{}; slot < bindings.size(); ++slot) {
      auto &owned = device.circuits[bindings[slot]];
      owned.update = &instance;
      owned.update_slot = slot;
      owned.update_egress = std::move(egress[slot]);
      static_cast<void>(owned.circuit.up(RuntimeClock::now()));
    }
    // Initial roots are installed, and the next loop schedules their ordinary
    // refresh deadlines along with Hello and update transmission work.
    return now;
  } catch (const std::bad_alloc &) {
    static_cast<void>(gate.resource_failed(RuntimeClock::now()));
    return gate.deadline().value_or(never);
  } catch (const std::exception &) {
    instance.status = UpdateStatus::invalid_configuration;
    return never;
  }
}
} // namespace router::isis
