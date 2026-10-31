// The IS-IS pthread publishes current local LSPs and owns entity-wide sequence
// recovery. Parent gates survive instance deletion. A stable shell releases old
// LSDB storage before reconstruction; no network information bypasses a port.
// Source: iso.10589.2002.local_lsp_generation

#include "router/isis_control_worker.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace router::isis {
RuntimeClock::time_point ControlWorker::service_local_instance(DeviceState &device, std::size_t index,
    RuntimeClock::time_point now, std::size_t &budget) noexcept {
  auto &instance = *device.instances[index];
  auto &gate = device.sequence_recovery[index];
  const auto never = RuntimeClock::time_point::max();
  if (instance.status == UpdateStatus::sequence_exhausted) {
    if (!gate) { instance.status = UpdateStatus::invalid_configuration; return never; }
    if (!gate->ready(now)) return gate->deadline().value_or(never);
    // Prepared generations borrow process slots. Their commit/abort command
    // wakes this owner; waiting for that event must not poll an expired timer.
    if (prepared_ && prepared_->device == device.handle) return never;
    return rebuild_local_instance(device, index, now);
  }
  if (instance.status != UpdateStatus::applied || !instance.local) return never;
  if (!instance.process || !gate) { instance.status = UpdateStatus::invalid_configuration; return never; }
  // Runtime authentication selection is not admitted yet. No unsigned output
  // may replace this explicit transmit policy when key leases are integrated.
  const auto generated = instance.local->service(*instance.process, {}, now, scratch_, instance.observer(), budget);
  if (generated.terminal == GenerationStatus::waiting) return generated.deadline.value_or(never);
  // Down must reach the old process while it still accepts its local circuit
  // events. No process reservation survives the stopped entity's restart.
  for (auto &owned : device.circuits) if (owned.update == &instance) {
    owned.transmission.cancel();
    static_cast<void>(owned.circuit.down(&owned, event));
  }
  device.update_fences[index] = std::max(device.update_fences[index], instance.process->maximum_synchronization_epoch());
  if (generated.terminal != GenerationStatus::sequence_exhausted) {
    instance.status = UpdateStatus::epoch_exhausted;
    return never;
  }
  instance.status = UpdateStatus::sequence_exhausted;
  // Anchor after all Down callbacks, so their execution cannot shorten the
  // minimum interval for which the complete entity must remain disabled.
  if (!gate->begin(RuntimeClock::now())) {
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
    auto budget = configuration.origination->content.current.size();
    const auto generated = local->service(*process, {}, now, scratch_, instance.observer(), budget);
    if (generated.blocked || generated.published != configuration.origination->content.current.size() ||
        generated.terminal != GenerationStatus::waiting) {
      static_cast<void>(gate.resource_failed(RuntimeClock::now()));
      return gate.deadline().value_or(never);
    }
    if (!gate.recovered(now)) { instance.status = UpdateStatus::invalid_event; return never; }
    instance.process = std::move(process);
    instance.local = std::move(local);
    instance.status = UpdateStatus::applied;
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
