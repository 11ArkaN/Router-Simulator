// Control command ownership, circuit timers and encoded frame handoff for the
// dedicated IS-IS pthread. No topology-editor or other router state is read.
// Device and configuration generations guard every ingress and completion.

#include "router/isis_control_worker.hpp"
#include "router/isis_control_checkpoint.hpp"
#include "router/isis_operational.hpp"

#include <algorithm>
#include <new>
#include <limits>
#include <stdexcept>
#include <utility>
#include <type_traits>

namespace router::isis {
namespace {
bool same_circuit(const CircuitIdentity &left, const CircuitIdentity &right) noexcept {
  return left.device == right.device && left.interface_id == right.interface_id && left.instance == right.instance;
}
}

ControlWorker::ControlWorker(ControlChannels &channels, std::size_t forwarding_shards,
    std::size_t maximum_circuits)
    : channels_(channels), forwarding_shards_(forwarding_shards), maximum_circuits_(maximum_circuits) {
  if (!forwarding_shards || forwarding_shards > channels_.ingress.size() || !maximum_circuits)
    throw std::invalid_argument("Invalid IS-IS control worker resources");
  thread_ = std::thread([this] { run(); });
}

ControlWorker::~ControlWorker() { stop(); }

void ControlWorker::stop() noexcept {
  stop_.store(true, std::memory_order_release);
  notify();
  if (thread_.joinable()) thread_.join();
}

bool ControlWorker::submit(ControlCommand &&command) noexcept {
  if (stop_.load(std::memory_order_acquire)) return false;
  const auto lease = commands_.acquire();
  if (!lease) return false;
  *lease->value = std::move(command);
  if (!commands_.publish(lease->handle)) {
    command = std::move(*lease->value);
    static_cast<void>(commands_.cancel(lease->handle));
    return false;
  }
  notify();
  return true;
}

bool ControlWorker::read(ControlResult &result) noexcept {
  const bool consumed = results_.try_pop(result);
  if (consumed) notify();
  return consumed;
}

void ControlWorker::notify() noexcept {
  work_.store(true, std::memory_order_release);
  { std::lock_guard lock(wait_mutex_); }
  wait_condition_.notify_one();
}

void ControlWorker::event(void *context, const P2pCircuitEvent &value) noexcept {
  auto &owned = *static_cast<OwnedCircuit *>(context);
  if (owned.update_egress && value.transition.outcome == P2pOutcome::up)
    owned.update_egress->synchronize = true;
  if (owned.update_egress && value.transition.outcome == P2pOutcome::down) {
    owned.update_egress->epochs.fill(0U);
    owned.update_egress->retries.clear();
  }
  if (owned.update && owned.update->status == UpdateStatus::applied) {
    const auto status = owned.update->process->p2p(owned.update_slot,
        owned.identity.configuration_generation, value, owned.update->observer());
    if (status != UpdateStatus::applied) owned.update->status = status;
  }
  if (value.transition.forwarding_readiness_changed && value.after.iso_up) ++owned.counters.adjacency_up;
  if (value.transition.outcome == P2pOutcome::down) ++owned.counters.adjacency_down;
}

ControlWorker::PreparedGeneration::~PreparedGeneration() {
  if (!committed) for (auto index = update_reservations.size(); index; --index) {
    auto &reservation = update_reservations[index - 1U];
    if (!reservation.instance->process->cancel_circuit_admission(reservation.admission)) std::terminate();
  }
}

ControlError ControlWorker::prepare_generation(ControlCommand &command, DeviceState &device) noexcept {
  const auto &definitions = command.circuits;
  if (definitions.size() > maximum_circuits_ ||
      active_circuits_ - device.circuits.size() > maximum_circuits_ - definitions.size()) return ControlError::capacity;
  if (std::any_of(device.instances.begin(), device.instances.end(), [](const auto &instance) {
      return instance && instance->status != UpdateStatus::applied && !requires_reconstruction(instance->status);
    })) return ControlError::update_refused;
  for (std::size_t ordinal{}; ordinal < command.retired_instances.size(); ++ordinal) {
    const auto index = command.retired_instances[ordinal];
    if (index >= device.instances.size() || (ordinal && command.retired_instances[ordinal - 1U] >= index))
      return ControlError::invalid_argument;
    if (!device.instances[index]) return ControlError::not_found;
    const auto replacement = std::find_if(command.new_instances.begin(), command.new_instances.end(),
        [index](const auto &entry) { return entry.instance == index; });
    const bool replacing = replacement != command.new_instances.end() && replacement->replace_existing;
    if ((replacement != command.new_instances.end() && !replacing) ||
        (!replacing && std::any_of(definitions.begin(), definitions.end(),
        [index](const auto &entry) { return entry.identity.instance == index; }))) return ControlError::invalid_argument;
  }
  for (std::size_t ordinal{}; ordinal < command.administrative.size(); ++ordinal) {
    const auto index = command.administrative[ordinal].instance;
    if (index >= device.instances.size() || !device.instances[index] ||
        (ordinal && command.administrative[ordinal - 1U].instance >= index) ||
        std::binary_search(command.retired_instances.begin(), command.retired_instances.end(), index))
      return ControlError::invalid_argument;
  }
  for (std::size_t ordinal{}; ordinal < command.adjacency_policies.size(); ++ordinal) {
    const auto index = command.adjacency_policies[ordinal].instance;
    if (index >= device.instances.size() || !device.instances[index] ||
        (ordinal && command.adjacency_policies[ordinal - 1U].instance >= index) ||
        std::binary_search(command.retired_instances.begin(), command.retired_instances.end(), index))
      return ControlError::invalid_argument;
  }
  for (std::size_t ordinal{}; ordinal < command.prefix_catalogs.size(); ++ordinal) {
    const auto index = command.prefix_catalogs[ordinal].instance;
    if (index >= device.instances.size() || !device.instances[index] || !device.instances[index]->configuration.origination ||
        (ordinal && command.prefix_catalogs[ordinal - 1U].instance >= index) ||
        std::binary_search(command.retired_instances.begin(), command.retired_instances.end(), index))
      return ControlError::invalid_argument;
  }
  const auto route_floor = std::max(device.route_generation, command.route_generation_floor);
  if (!command.administrative.empty() && route_floor == std::numeric_limits<std::uint64_t>::max())
    return ControlError::epoch_exhausted;
  std::unique_ptr<DeviceState> additions;
  if (!command.new_instances.empty()) {
    if (command.new_instances.size() > device.instances.size() ||
        static_cast<std::size_t>(std::count_if(command.new_instances.begin(), command.new_instances.end(),
            [](const auto &entry) { return !entry.replace_existing; })) > device.instances.size() - device.instance_count)
      return ControlError::capacity;
    try {
      additions = std::make_unique<DeviceState>();
      additions->handle = device.handle;
      additions->active = true;
      additions->update_fences = device.update_fences;
      std::optional<std::uint8_t> previous;
      for (auto &entry : command.new_instances) {
        const auto index = entry.instance;
        if (index >= device.instances.size() || (previous && index <= *previous)) return ControlError::invalid_argument;
        previous = index;
        const auto &current = device.instances[index];
        if (entry.replace_existing) {
          if (!current || !std::binary_search(command.retired_instances.begin(), command.retired_instances.end(), index))
            return ControlError::invalid_argument;
          if (current->process) additions->update_fences[index] = std::max(additions->update_fences[index],
              current->process->maximum_synchronization_epoch());
        } else if (current || std::any_of(device.circuits.begin(), device.circuits.end(),
            [&](const auto &circuit) { return circuit.identity.instance == index; })) return ControlError::already_exists;
        const auto &gate = device.sequence_recovery[index];
        if (gate && gate->disabled() && !gate->ready(RuntimeClock::now())) return ControlError::sequence_cooldown;
        ControlCommand prepare;
        prepare.identity.device = device.handle;
        prepare.identity.instance = index;
        prepare.update = std::move(entry.program);
        prepare.admin_enabled = entry.admin_enabled;
        const auto *sequence_source = entry.replace_existing && !(gate && gate->disabled()) ? current.get() : nullptr;
        const auto error = add_update_instance(prepare, *additions, sequence_source);
        if (error != ControlError::none) return error;
      }
    } catch (const std::bad_alloc &) { return ControlError::capacity; }
      catch (const std::exception &) { return ControlError::construction_failed; }
  }
  // Candidate pointers remain heap-stable when their registry moves into the
  // prepared generation. No live owner can observe or service these instances.
  auto *candidate_instances = additions.get();
  const auto selected_instance = [&](std::size_t index) -> std::unique_ptr<OwnedInstance> & {
    if (candidate_instances && candidate_instances->instances[index]) return candidate_instances->instances[index];
    return device.instances[index];
  };
  const auto replacing = [&](std::size_t index) {
    return candidate_instances && candidate_instances->instances[index] && device.instances[index];
  };
  const auto key = [](const CircuitIdentity &value) { return std::pair{value.interface_id, value.instance}; };
  for (std::size_t index{}; index < definitions.size(); ++index) {
    const auto &entry = definitions[index];
    const auto &identity = entry.identity;
    if (identity.device != device.handle || !identity.interface_id || !identity.configuration_generation ||
        identity.instance > device_catalog::isis_instance_last ||
        identity.physical_port_ordinal >= device_catalog::maximum_ports_per_router ||
        (index && key(definitions[index - 1U].identity) >= key(identity))) return ControlError::invalid_argument;
    const auto *common = entry.common();
    if (entry.update_transmission && !valid_transmission(*entry.update_transmission)) return ControlError::invalid_argument;
    if (!common || (entry.broadcast && entry.configuration != P2pCircuitConfiguration{})) return ControlError::invalid_argument;
    if (entry.update_transmission && !valid_medium_transmission(*entry.update_transmission, entry.update_view()))
      return ControlError::invalid_argument;
    if (const auto &instance = selected_instance(identity.instance)) {
      const auto view = entry.update_view();
      const auto &transmission = entry.update_transmission.value_or(instance->configuration.transmission);
      if (!valid_medium_transmission(transmission, view)) return ControlError::unsupported_update_medium;
      if (instance->status != UpdateStatus::applied && !requires_reconstruction(instance->status))
        return ControlError::update_refused;
      if (!matches_update_instance(instance->configuration, entry.update_view(), identity.interface_id))
        return ControlError::invalid_argument;
      const auto mask = static_cast<std::uint8_t>(view.levels);
      for (std::size_t level{}; level < 2U; ++level)
        if ((mask & (1U << level)) && !instance->configuration.levels[level]) return ControlError::invalid_argument;
      std::size_t count{};
      for (const auto &other : definitions) if (other.identity.instance == identity.instance) {
        ++count;
        if (!other.common()) return ControlError::invalid_argument;
        const auto other_view = other.update_view();
        if (&other != &entry && other_view.broadcast == view.broadcast && other_view.circuit_id == view.circuit_id)
          return ControlError::already_exists;
      }
      if (count > instance->configuration.maximum_circuits) return ControlError::capacity;
    }
    if (common->receive_authentication || common->transmit_authentication)
      return ControlError::unsupported_authentication;
    if (entry.broadcast) for (const auto &level : entry.broadcast->levels)
      if (level && (level->receive_authentication || level->transmit_authentication)) return ControlError::unsupported_authentication;
    for (std::size_t previous = index; previous && definitions[previous - 1U].identity.interface_id == identity.interface_id;) {
      const auto &other = definitions[--previous];
      if (other.identity.physical_port_ordinal != identity.physical_port_ordinal ||
          (other.common()->wire_instance == common->wire_instance &&
           other.common()->destinations().conflicts(common->destinations()))) return ControlError::already_exists;
    }
  }
  try {
    PreparedGeneration staged;
    staged.additions = std::move(additions);
    staged.device = device.handle;
    staged.retired_instances = std::move(command.retired_instances);
    staged.administrative = std::move(command.administrative);
    staged.adjacency_policies = std::move(command.adjacency_policies);
    staged.prefix_catalogs = std::move(command.prefix_catalogs);
    staged.prefix_workspaces.reserve(staged.prefix_catalogs.size());
    for (const auto &edit : staged.prefix_catalogs) {
      const auto &current = device.instances[edit.instance]->configuration;
      auto proposed = current;
      proposed.origination->prefixes = edit.program;
      const auto status = prepare_neighbor_origination(proposed);
      if (status != ControlError::none) return status;
      if (proposed.origination->content != current.origination->content) return ControlError::invalid_argument;
      staged.prefix_workspaces.push_back(make_fragment_workspace(proposed));
    }
    if (!staged.administrative.empty()) staged.route_commit_generation = route_floor + 1U;
    staged.output.reserve(definitions.size());
    staged.plan.reserve(definitions.size());
    staged.keep.resize(device.circuits.size());
    std::vector<std::size_t> lookup;
    lookup.reserve(device.circuits.size());
    for (std::size_t index{}; index < device.circuits.size(); ++index) lookup.push_back(index);
    std::sort(lookup.begin(), lookup.end(), [&](auto left, auto right) {
      return key(device.circuits[left].identity) < key(device.circuits[right].identity);
    });
    const auto now = PointToPointCircuit::Clock::now();
    std::size_t replacement_count{};
    for (auto &entry : command.circuits) {
      const auto old = std::lower_bound(lookup.begin(), lookup.end(), key(entry.identity), [&](auto index, auto target) {
        return key(device.circuits[index].identity) < target;
      });
      if (old != lookup.end() && key(device.circuits[*old].identity) == key(entry.identity)) {
        const auto &current = device.circuits[*old];
        if (entry.identity.configuration_generation < current.identity.configuration_generation)
          return ControlError::stale_configuration;
        if (entry.identity.configuration_generation == current.identity.configuration_generation) {
          if (replacing(entry.identity.instance)) return ControlError::stale_configuration;
          if (entry.identity != current.identity || !current.matches(entry))
            return ControlError::stale_configuration;
          staged.keep[*old] = 1U;
          staged.plan.push_back({*old, true});
          continue;
        }
      } else if (entry.identity.configuration_generation <= device.retired_epoch_floor)
        return ControlError::stale_configuration;
      staged.plan.push_back({replacement_count++, false});
    }
    // Retained circuits move only at commit. Reserve replacement storage for
    // changed epochs alone, so an unchanged large generation does not allocate
    // a second full array of circuit objects merely to preserve its live state.
    staged.replacements.reserve(replacement_count);
    staged.update_reservations.reserve(replacement_count);
    for (std::size_t index{}; index < command.circuits.size(); ++index) {
      if (staged.plan[index].retained) continue;
      auto &entry = command.circuits[index];
      ControlCommand replacement;
      replacement.identity = entry.identity;
      replacement.configuration = std::move(entry.configuration);
      replacement.random_state = entry.random_state;
      replacement.broadcast = std::move(entry.broadcast);
      replacement.update_transmission = entry.update_transmission;
      replacement.carrier = entry.carrier;
      staged.replacements.emplace_back(replacement, now);
    }
    for (auto &replacement : staged.replacements) {
      auto &instance = selected_instance(replacement.identity.instance);
      if (!instance) continue;
      // Only the detached medium changes here. A prepared rebind may still
      // borrow the live owner's old slot, so do not attach it before Down.
      if (!instance->admin_enabled) circuit_down(replacement);
      if (requires_reconstruction(instance->status)) {
        // Disabled bindings carry configuration only. Fresh level slots are
        // assigned together when the complete entity is reconstructed.
        replacement.update = instance.get();
        circuit_down(replacement);
        continue;
      }
      if (!instance->process) return ControlError::update_refused;
      replacement.update_egress = std::make_unique<UpdateEgress>(*instance, replacement.random_state, replacement.update_transmission);
      const auto old = std::find_if(device.circuits.begin(), device.circuits.end(), [&](const auto &current) {
        return same_circuit(current.identity, replacement.identity);
      });
      if (old != device.circuits.end() && old->update == instance.get() && old->lan() && replacement.lan() &&
          old->identity.physical_port_ordinal == replacement.identity.physical_port_ordinal &&
          old->wire_instance == replacement.wire_instance && old->format == replacement.format) {
        for (std::size_t level{}; level < 2U; ++level)
          replacement.previous_dis[level].remote = old->previous_dis[level].remote;
      }
      if (old != device.circuits.end() && old->update == instance.get()) {
        const auto reserved = instance->process->prepare_rebind_circuit(old->update_slot,
            update_configuration(replacement));
        if (reserved != UpdateStatus::applied)
          return reserved == UpdateStatus::capacity ? ControlError::capacity : ControlError::update_refused;
        replacement.update = instance.get();
        replacement.update_slot = old->update_slot;
        replacement.rebind_update = true;
        continue;
      }
      // Reuse a circuit removed by this complete generation only if its slot
      // is not reserved for a same-identity replacement. Old live bindings stay
      // untouched until commit emits their Down events.
      const auto reusable = std::find_if(device.circuits.begin(), device.circuits.end(), [&](const auto &current) {
        const auto ordinal = static_cast<std::size_t>(&current - device.circuits.data());
        return !staged.keep[ordinal] && current.update == instance.get() &&
            current.identity.configuration_generation < replacement.identity.configuration_generation &&
            std::none_of(definitions.begin(), definitions.end(), [&](const auto &definition) {
              return same_circuit(definition.identity, current.identity);
            }) && std::none_of(staged.replacements.begin(), staged.replacements.end(), [&](const auto &selected) {
              return selected.update == instance.get() && selected.update_slot == current.update_slot;
            });
      });
      replacement.update = instance.get();
      if (reusable != device.circuits.end()) {
        const auto reserved = instance->process->prepare_rebind_circuit(reusable->update_slot,
            update_configuration(replacement));
        if (reserved != UpdateStatus::applied)
          return reserved == UpdateStatus::capacity ? ControlError::capacity : ControlError::update_refused;
        replacement.update_slot = reusable->update_slot;
        replacement.rebind_update = true;
      } else {
        auto admission = instance->process->admit_circuit(update_configuration(replacement));
        if (admission.status != UpdateStatus::applied)
          return admission.status == UpdateStatus::capacity ? ControlError::capacity : ControlError::update_refused;
        replacement.update_slot = *admission.index;
        staged.update_reservations.push_back({instance.get(), std::move(admission)});
      }
    }
    prepared_.emplace(std::move(staged));
    return ControlError::none;
  } catch (const std::bad_alloc &) { return ControlError::capacity; }
    catch (const std::exception &) { return ControlError::construction_failed; }
}

void ControlWorker::commit_generation(DeviceState &device) noexcept {
  static_assert(std::is_nothrow_move_constructible_v<OwnedCircuit>);
  auto &staged = *prepared_;
  for (std::size_t index{}; index < device.circuits.size(); ++index)
    if (!staged.keep[index]) retire_circuit(device, device.circuits[index]);
  for (auto &replacement : staged.replacements) if (replacement.rebind_update) {
    if (replacement.update->process->rebind_circuit(replacement.update_slot,
        update_configuration(replacement)) != UpdateStatus::applied) std::terminate();
    replacement.rebind_update = false;
  }
  staged.committed = true;
  for (const auto &selection : staged.plan)
    staged.output.push_back(std::move(selection.retained ? device.circuits[selection.index] : staged.replacements[selection.index]));
  active_circuits_ = active_circuits_ - device.circuits.size() + staged.output.size();
  device.circuits.swap(staged.output);
  // Every circuit attached to a retired owner was excluded and retired above.
  // Remove only after the live circuit vector stops borrowing that owner.
  for (const auto index : staged.retired_instances) remove_update_instance(device, index);
  if (staged.additions) {
    for (std::size_t ordinal{}; ordinal < staged.additions->instance_count; ++ordinal) {
      const auto index = staged.additions->instance_order[ordinal];
      if (device.instances[index]) std::terminate();
      device.instances[index] = std::move(staged.additions->instances[index]);
      device.sequence_recovery[index] = std::move(staged.additions->sequence_recovery[index]);
      device.instance_order[device.instance_count++] = index;
    }
  }
  for (const auto &edit : staged.administrative)
    set_admin_state(device, *device.instances[edit.instance], edit.enabled);
  for (const auto &edit : staged.adjacency_policies)
    if (set_strict_policy(device, edit.instance, edit.strict_families) != ControlError::none) std::terminate();
  for (std::size_t index{}; index < staged.prefix_catalogs.size(); ++index) {
    auto &edit = staged.prefix_catalogs[index];
    auto &instance = *device.instances[edit.instance];
    // The cold lease proved complete worst-case fragment capacity. Both swaps
    // occur on the sole writer before service can borrow the new catalog.
    instance.configuration.origination->prefixes = std::move(edit.program);
    instance.fragment_workspace.swap(staged.prefix_workspaces[index]);
    instance.local_roots_dirty.fill(true);
  }
  if (staged.route_commit_generation) {
    // The network owner has committed the matching dual-family RIB under its
    // forwarding barrier. Older queued receipts cannot acknowledge this key.
    device.route_generation = device.route_installed = staged.route_commit_generation;
    device.route_pending = 0U;
    device.installed_routes = {};
    device.route_status = ::router::routing::RouteInstallStatus::installed;
    device.route_retry_at = {};
  }
  if (device.first_circuit >= device.circuits.size()) device.first_circuit = 0U;
  prepared_.reset();
}

void ControlWorker::retire_circuit(DeviceState &device, OwnedCircuit &circuit) noexcept {
  device.retired_epoch_floor = std::max(device.retired_epoch_floor, circuit.identity.configuration_generation);
  circuit_down(circuit);
  if (circuit.update) {
    if (circuit.update->status == UpdateStatus::applied &&
        circuit.update->process->release_circuit(circuit.update_slot,
            circuit.identity.configuration_generation) != UpdateStatus::applied) std::terminate();
    circuit.update = nullptr;
  }
}

void ControlWorker::set_admin_state(DeviceState &device, OwnedInstance &instance, bool enabled) noexcept {
  if (instance.admin_enabled == enabled) return;
  instance.admin_enabled = enabled;
  for (auto &circuit : device.circuits) if (circuit.update == &instance) {
    if (!enabled) circuit_down(circuit);
    else if (instance.status == UpdateStatus::applied) circuit_up(circuit, RuntimeClock::now());
  }
  if (enabled) instance.local_roots_dirty.fill(true);
}

ControlResult ControlWorker::apply(ControlCommand &command) noexcept {
  ControlResult result;
  result.id = command.id;
  result.checkpoint_barrier_epoch = checkpoint_barrier_epoch_;
  result.thread_identity = identity_.load(std::memory_order_relaxed);
  result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
  if (command.kind == ControlCommandKind::shutdown) {
    stop_.store(true, std::memory_order_release);
    return result;
  }
  if (command.kind == ControlCommandKind::query_worker) return result;
  if (command.kind == ControlCommandKind::begin_checkpoint_barrier) {
    if (command.checkpoint_barrier_epoch) result.error = ControlError::invalid_argument;
    else if (checkpoint_barrier_epoch_) result.error = ControlError::checkpoint_barrier_pending;
    else if (prepared_) result.error = ControlError::generation_pending;
    else if (checkpoint_barrier_counter_ == std::numeric_limits<std::uint64_t>::max()) result.error = ControlError::epoch_exhausted;
    else {
      checkpoint_barrier_started_ = RuntimeClock::now();
      result.checkpoint_barrier_epoch = checkpoint_barrier_epoch_ = ++checkpoint_barrier_counter_;
      result.checkpoint_anchor_nanoseconds = checkpoint_barrier_started_.time_since_epoch().count();
    }
    return result;
  }
  if (command.kind == ControlCommandKind::end_checkpoint_barrier) {
    if (!checkpoint_barrier_epoch_ || command.checkpoint_barrier_epoch != checkpoint_barrier_epoch_)
      result.error = ControlError::stale_checkpoint_barrier;
    else if (checkpoint_restore_) result.error = ControlError::generation_pending;
    else result.checkpoint_barrier_epoch = checkpoint_barrier_epoch_ = 0U;
    return result;
  }
  if (command.kind == ControlCommandKind::prepare_checkpoint_restore ||
      command.kind == ControlCommandKind::commit_checkpoint_restore ||
      command.kind == ControlCommandKind::abort_checkpoint_restore) {
    if (!checkpoint_barrier_epoch_ || command.checkpoint_barrier_epoch != checkpoint_barrier_epoch_)
      result.error = ControlError::stale_checkpoint_barrier;
    else if (command.kind == ControlCommandKind::abort_checkpoint_restore) checkpoint_restore_.reset();
    else if (command.kind == ControlCommandKind::commit_checkpoint_restore) {
      if (!checkpoint_restore_ || checkpoint_restore_->source_epoch != command.checkpoint_source_epoch)
        result.error = ControlError::stale_checkpoint_barrier;
      else {
        static_assert(std::is_nothrow_swappable_v<decltype(devices_)>);
        devices_.swap(checkpoint_restore_->devices);
        active_circuits_ = checkpoint_restore_->active_circuits;
        first_device_ = checkpoint_restore_->first_device;
        checkpoint_restore_.reset();
        result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
      }
    } else if (checkpoint_restore_) result.error = ControlError::generation_pending;
    else {
      const auto now = RuntimeClock::time_point{RuntimeClock::duration{command.checkpoint_now_nanoseconds}};
      if (!command.checkpoint_transfer || now < checkpoint_barrier_started_ || now > RuntimeClock::now())
        result.error = ControlError::invalid_argument;
      else {
        checkpoint_restore_ = prepare_checkpoint_restore(
            *reinterpret_cast<const ControlWorkerCheckpoint *>(command.checkpoint_transfer), command.checkpoint_source_epoch, now);
        if (!checkpoint_restore_) result.error = ControlError::invalid_argument;
      }
    }
    return result;
  }
  if (command.kind == ControlCommandKind::capture_checkpoint) {
    if (!checkpoint_barrier_epoch_ || command.checkpoint_barrier_epoch != checkpoint_barrier_epoch_) {
      result.error = ControlError::stale_checkpoint_barrier;
      return result;
    }
    const auto now = RuntimeClock::time_point{RuntimeClock::duration{command.checkpoint_now_nanoseconds}};
    if (!command.checkpoint_transfer || now < checkpoint_barrier_started_ || now > RuntimeClock::now()) {
      result.error = ControlError::invalid_argument;
      return result;
    }
    if (checkpoint_restore_) { result.error = ControlError::generation_pending; return result; }
    try {
      auto staged = capture_checkpoint(now);
      *reinterpret_cast<ControlWorkerCheckpoint *>(command.checkpoint_transfer) = std::move(staged);
    } catch (const std::bad_alloc &) { result.error = ControlError::capacity; }
      catch (const std::invalid_argument &) { result.error = ControlError::invalid_argument; }
      catch (const std::exception &) { result.error = ControlError::construction_failed; }
    return result;
  }
  if (checkpoint_barrier_epoch_) {
    result.error = ControlError::checkpoint_barrier_pending;
    return result;
  }
  const auto handle = command.identity.device;
  if (!handle.generation || handle.index >= devices_.size()) { result.error = ControlError::invalid_argument; return result; }
  auto &device = devices_[handle.index];
  if (command.kind == ControlCommandKind::commit_generation || command.kind == ControlCommandKind::abort_generation) {
    if (!prepared_) result.error = ControlError::not_found;
    else if (prepared_->device != handle) result.error = ControlError::stale_device;
    else if (command.kind == ControlCommandKind::abort_generation) prepared_.reset();
    else if (std::any_of(device.instances.begin(), device.instances.end(), [](const auto &instance) {
      return instance && instance->status != UpdateStatus::applied && !requires_reconstruction(instance->status);
    })) {
      prepared_.reset();
      result.error = ControlError::update_refused;
    } else {
      commit_generation(device);
      result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
    }
    return result;
  }
  if (prepared_ && command.kind != ControlCommandKind::query_circuit &&
      command.kind != ControlCommandKind::query_local_port_usage &&
      command.kind != ControlCommandKind::query_adjacencies &&
      command.kind != ControlCommandKind::query_update_instance &&
      command.kind != ControlCommandKind::query_sequence_recovery) {
    result.error = ControlError::generation_pending;
    return result;
  }
  if (command.kind == ControlCommandKind::register_device) {
    if (device.active) result.error = device.handle == handle ? ControlError::already_exists : ControlError::stale_device;
    else {
      if (device.handle != handle) {
        device.retired_epoch_floor = 0U;
        device.update_fences.fill(0U);
        for (auto &gate : device.sequence_recovery) gate.reset();
        device.installed_routes = {};
        device.pending_routes = {};
        device.route_generation = device.route_installed = device.route_pending = 0U;
        device.route_status = ::router::routing::RouteInstallStatus::pending;
        device.route_retry_at = {};
        device.route_retry = {};
      }
      device.handle = handle;
      device.active = true;
    }
    return result;
  }
  if (!device.active || device.handle != handle) { result.error = ControlError::stale_device; return result; }
  if (command.kind == ControlCommandKind::set_local_port_carrier ||
      command.kind == ControlCommandKind::query_local_port_usage) {
    const auto port = command.identity.physical_port_ordinal;
    const bool edit = command.kind == ControlCommandKind::set_local_port_carrier;
    // One local port event updates every circuit and passive prefix source in
    // this serialized turn. Protocol service cannot observe an intermediate gate.
    for (auto &owned : device.circuits) if (owned.identity.physical_port_ordinal == port) {
      result.local_port_in_use = true;
      if (edit && owned.carrier != command.carrier) {
        owned.carrier = command.carrier;
        if (!command.carrier) circuit_down(owned);
        else if (!owned.update || owned.update->status == UpdateStatus::applied)
          circuit_up(owned, RuntimeClock::now());
      }
    }
    for (auto &instance : device.instances)
      if (instance && instance->configuration.origination && instance->configuration.origination->prefixes) {
        auto &catalog = *instance->configuration.origination->prefixes;
        result.local_port_in_use = result.local_port_in_use || std::any_of(catalog.interfaces.begin(), catalog.interfaces.end(),
            [port](const auto &source) { return source.physical_port == port; });
        if (edit && set_local_prefix_carrier(catalog, port, command.carrier)) instance->local_roots_dirty.fill(true);
      }
    result.carrier = command.carrier;
    return result;
  }
  result.route_published_generation = device.route_generation;
  result.route_installed_generation = device.route_installed;
  result.route_install_status = device.route_status;
  result.route_withdrawal_pending = device.route_pending ||
      std::any_of(device.installed_routes.begin(), device.installed_routes.end(),
          [](const auto &stamp) { return stamp.families != 0U; });
  if (command.kind == ControlCommandKind::query_sequence_recovery) {
    const auto now = RuntimeClock::now();
    result.sequence_recovery_pending = std::any_of(device.sequence_recovery.begin(), device.sequence_recovery.end(),
        [&](const auto &gate) { return gate && gate->disabled() && !gate->ready(now); });
    return result;
  }
  if (command.kind == ControlCommandKind::query_adjacencies) {
    result.error = command.adjacency_query ? query_adjacencies(device, *command.adjacency_query) : ControlError::invalid_argument;
    return result;
  }
  if (command.kind == ControlCommandKind::prepare_generation) {
    result.error = prepare_generation(command, device);
    if (result.error == ControlError::none && prepared_->route_commit_generation)
      result.route_published_generation = prepared_->route_commit_generation;
    return result;
  }
  if (command.kind == ControlCommandKind::remove_device) {
    for (auto &owned : device.circuits) retire_circuit(device, owned);
    active_circuits_ -= device.circuits.size();
    device.circuits.clear();
    for (std::size_t index{}; index < device.instances.size(); ++index) remove_update_instance(device, index);
    device.active = false;
    result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
    return result;
  }
  if (command.kind == ControlCommandKind::add_update_instance ||
      command.kind == ControlCommandKind::remove_update_instance ||
      command.kind == ControlCommandKind::query_update_instance ||
      command.kind == ControlCommandKind::set_update_admin_state ||
      command.kind == ControlCommandKind::originate_lsp ||
      command.kind == ControlCommandKind::replace_local_content ||
      command.kind == ControlCommandKind::withdraw_local_content) {
    const auto index = command.identity.instance;
    if (index >= device.instances.size()) result.error = ControlError::invalid_argument;
    else if (command.kind == ControlCommandKind::add_update_instance)
      result.error = add_update_instance(command, device);
    else if (!device.instances[index]) result.error = ControlError::not_found;
    else if (command.kind == ControlCommandKind::remove_update_instance) remove_update_instance(device, index);
    else {
      auto &instance = *device.instances[index];
      if (command.kind == ControlCommandKind::set_update_admin_state) {
        set_admin_state(device, instance, command.admin_enabled);
        result.admin_enabled = instance.admin_enabled;
        return result;
      }
      if (command.kind == ControlCommandKind::replace_local_content ||
          command.kind == ControlCommandKind::withdraw_local_content) {
        result.error = edit_local_content(command, instance, result);
        return result;
      }
      if (command.kind == ControlCommandKind::originate_lsp) {
        if (!instance.admin_enabled || instance.status != UpdateStatus::applied || !instance.process || instance.local)
          result.error = ControlError::update_refused;
        else {
          packet::isis::DecodeError decode{};
          const auto pdu = packet::isis::parse(command.local_lsp, decode);
          packet::isis::InstanceError error{};
          const auto selected = pdu ? packet::isis::select_instance(*pdu, instance.configuration.format,
              false, error) : std::nullopt;
          if (!selected || selected->instance != instance.configuration.wire_instance) {
            result.error = ControlError::update_refused;
            return result;
          }
          result.origin = instance.process->originate(command.level, command.local_lsp,
              RuntimeClock::now(), command.purge, instance.observer());
          if (result.origin.status != LevelStatus::applied) result.error = ControlError::update_refused;
        }
      }
      result.update_status = instance.status;
      result.admin_enabled = instance.admin_enabled;
      result.update_epoch = instance.process ? instance.process->maximum_synchronization_epoch() : device.update_fences[index];
      result.decision_runs = instance.decision_runs;
      for (std::size_t level{}; level < 2U; ++level)
        result.spf_pending[level] = instance.spf[level] && instance.spf[level]->deadline().has_value();
      result.decision_status = instance.decision_status;
      result.database_validations = instance.database_validations;
      result.decision_revisions = instance.decision_revisions;
      result.corrupted_lsp = instance.corrupted_lsp;
      packet::isis::LspId root{};
      std::copy(instance.configuration.local.begin(), instance.configuration.local.end(), root.begin());
      for (std::size_t level{}; level < result.retained_lsps.size(); ++level)
        if (const auto *owner = instance.process ? instance.process->level(level) : nullptr) {
          const auto &database = owner->database().database();
          result.retained_lsps[level] = database.size();
          for (std::size_t record_index{}; record_index < database.size(); ++record_index)
            if (database.at(record_index, RuntimeClock::now())->purge_installed) ++result.retained_purges[level];
          if (const auto own = database.find(root, RuntimeClock::now()))
            result.local_root_links[level] = lsp_link_counts(own->pdu.tlvs);
          if (instance.local) result.local_root_sequences[level] = instance.local->sequence(level, root).value_or(0U);
        }
      for (std::size_t level{}; level < 2U; ++level) {
        if (!instance.decisions[level] || instance.consumed_decision_revision[level] != instance.decision_revisions[level] ||
            instance.status != UpdateStatus::applied || instance.decision_status[level] != DecisionStatus::applied) continue;
        const auto &decision = *instance.decisions[level];
        result.prefix_advertisements[level] = decision.prefixes().size();
        if (!command.selected_prefix) continue;
        for (std::size_t prefix{}; prefix < decision.prefixes().size(); ++prefix) {
          const auto &entry = decision.prefixes()[prefix];
          if (entry.prefix != *command.selected_prefix || (command.selected_lsp && entry.origin != *command.selected_lsp)) continue;
          const auto distance = decision.distance_to_prefix(prefix);
          auto &best = result.selected_prefix_distance[level];
          if (distance && (!best || *distance < *best)) best = distance;
        }
      }
      if (command.selected_lsp) {
        if (command.level > 1U) {
          result.error = ControlError::invalid_argument;
          return result;
        }
        const auto *owner = instance.process ? instance.process->level(command.level) : nullptr;
        const auto selected = owner ? owner->database().database().find(*command.selected_lsp, RuntimeClock::now()) : std::nullopt;
        if (selected) {
          result.selected_lsp = selected->header;
          result.selected_lsp_links = lsp_link_counts(selected->pdu.tlvs);
        }
        else result.error = ControlError::not_found;
        packet::isis::LanId selected_node{};
        std::copy_n(command.selected_lsp->begin(), selected_node.size(), selected_node.begin());
        for (std::size_t level{}; level < 2U; ++level)
          if (instance.decisions[level] && instance.consumed_decision_revision[level] == instance.decision_revisions[level] &&
              instance.status == UpdateStatus::applied &&
              instance.decision_status[level] == DecisionStatus::applied)
            result.selected_cost[level] = instance.decisions[level]->cost(selected_node);
      }
    }
    return result;
  }
  auto found = std::find_if(device.circuits.begin(), device.circuits.end(),
      [&](const auto &owned) { return same_circuit(owned.identity, command.identity); });
  if (command.kind == ControlCommandKind::add_p2p_circuit || command.kind == ControlCommandKind::add_lan_circuit) {
    const auto *common = circuit_hello_configuration(command.configuration, command.broadcast);
    if (command.update_transmission && !valid_transmission(*command.update_transmission)) {
      result.error = ControlError::invalid_argument;
      return result;
    }
    if (!common || (command.kind == ControlCommandKind::add_lan_circuit) != command.broadcast.has_value() ||
        (command.broadcast && command.configuration != P2pCircuitConfiguration{})) {
      result.error = ControlError::invalid_argument;
      return result;
    }
    if (command.broadcast) for (const auto &level : command.broadcast->levels)
      if (level && (level->receive_authentication || level->transmit_authentication)) {
        result.error = ControlError::unsupported_authentication;
        return result;
      }
    if (found != device.circuits.end()) result.error = ControlError::already_exists;
    else if (!command.identity.interface_id || !command.identity.configuration_generation ||
        command.identity.instance > device_catalog::isis_instance_last ||
        command.identity.physical_port_ordinal >= device_catalog::maximum_ports_per_router)
      result.error = ControlError::invalid_argument;
    else if (command.identity.configuration_generation <= device.retired_epoch_floor)
      result.error = ControlError::stale_configuration;
    else if (common->receive_authentication || common->transmit_authentication)
      result.error = ControlError::unsupported_authentication;
    else if (std::any_of(device.circuits.begin(), device.circuits.end(), [&](const auto &other) {
      return other.identity.interface_id == command.identity.interface_id &&
          (other.identity.physical_port_ordinal != command.identity.physical_port_ordinal ||
           (other.wire_instance == common->wire_instance &&
            other.destinations.conflicts(common->destinations())));
    })) result.error = ControlError::already_exists;
    else if (active_circuits_ >= maximum_circuits_) result.error = ControlError::capacity;
    else try {
      device.circuits.emplace_back(command, PointToPointCircuit::Clock::now());
      result.error = attach_update_circuit(device, device.circuits.back());
      if (result.error != ControlError::none) {
        device.circuits.pop_back();
        return result;
      }
      ++active_circuits_;
      result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
    } catch (const std::bad_alloc &) { result.error = ControlError::capacity; }
      catch (const std::exception &) { result.error = ControlError::construction_failed; }
    return result;
  }
  if (found == device.circuits.end()) { result.error = ControlError::not_found; return result; }
  if (found->identity.configuration_generation != command.identity.configuration_generation) {
    result.error = ControlError::stale_configuration;
    return result;
  }
  if (command.kind == ControlCommandKind::remove_circuit) {
    retire_circuit(device, *found);
    device.circuits.erase(found);
    --active_circuits_;
    result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
    return result;
  }
  if (command.kind == ControlCommandKind::set_circuit_carrier) {
    if (found->carrier != command.carrier) {
      found->carrier = command.carrier;
      if (!command.carrier) circuit_down(*found);
      else if (!found->update || found->update->status == UpdateStatus::applied)
        circuit_up(*found, RuntimeClock::now());
    }
    result.carrier = found->carrier;
    return result;
  }
  if (command.kind != ControlCommandKind::query_circuit) { result.error = ControlError::invalid_argument; return result; }
  result.carrier = found->carrier;
  result.admin_enabled = !found->update || found->update->admin_enabled;
  result.broadcast_circuit = found->lan() != nullptr;
  if (const auto *broadcast = found->lan()) {
    for (std::size_t level{}; level < 2U; ++level) if (const auto *circuit = broadcast->at(level)) {
      result.lan_neighbors[level] = circuit->neighbors().size();
      result.designated[level] = circuit->designated();
      result.hello_pending = result.hello_pending || circuit->hello_pending();
      for (std::size_t peer{}; peer < circuit->neighbors().size(); ++peer)
        result.lan_up[level] += circuit->neighbors().at(peer)->adjacency.state == LanState::up ? 1U : 0U;
    }
    if (command.selected_next_hop) {
      const auto *circuit = command.level >= 1U && command.level <= 2U ? broadcast->at(command.level - 1U) : nullptr;
      const auto peer = circuit && command.selected_lan_peer ? circuit->neighbors().find(*command.selected_lan_peer) : std::nullopt;
      if (peer) result.bound_next_hop = bind_lan_next_hop(*peer, circuit->configuration().protocols,
          {found->identity.interface_id, found->identity.configuration_generation, found->identity.physical_port_ordinal},
          *command.selected_next_hop);
      if (!result.bound_next_hop) result.error = ControlError::not_found;
    }
  } else {
    result.adjacency = found->p2p().adjacency();
    if (command.selected_next_hop) {
      result.bound_next_hop = bind_p2p_next_hop(result.adjacency,
          found->p2p().peer_attributes(), found->p2p().configuration().protocols,
          {found->identity.interface_id, found->identity.configuration_generation,
           found->identity.physical_port_ordinal}, command.level, *command.selected_next_hop);
      if (!result.bound_next_hop) result.error = ControlError::not_found;
    }
    result.hello_pending = found->p2p().hello_pending();
  }
  result.counters = found->counters;
  if (found->update) {
    result.update_status = found->update->status;
    for (std::size_t level{}; level < 2U; ++level) {
      const auto *owner = found->update->process ? found->update->process->level(level) : nullptr;
      if (!owner) continue;
      const auto &database = owner->database();
      for (std::size_t index{}; index < database.size(); ++index) {
        const auto entry = database.snp_entry_at(index, RuntimeClock::now());
        const auto flags = entry ? database.flags(entry->id, found->update_slot) : std::nullopt;
        if (flags && flags->srm) ++result.flood_requests[level];
        if (flags && flags->ssn) ++result.snp_requests[level];
      }
    }
  }
  std::optional<RuntimeClock::time_point> holding;
  if (const auto *broadcast = found->lan()) {
    for (std::size_t level{}; level < 2U; ++level) if (const auto *circuit = broadcast->at(level)) {
      const auto next = circuit->neighbors().deadline();
      if (next && (!holding || *next < *holding)) holding = next;
    }
  } else holding = found->p2p().holding_deadline();
  if (holding) result.holding_deadline_nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(holding->time_since_epoch()).count();
  return result;
}

void ControlWorker::receive(
    const protocol::PacketChannel<device_catalog::isis_packet_ring_frames>::Borrowed &packet,
    PointToPointCircuit::Clock::time_point now) noexcept {
  const auto handle = packet.metadata.device;
  if (handle.index >= devices_.size()) return;
  auto &device = devices_[handle.index];
  if (!device.active || device.handle != handle) return;
  packet::isis::EthernetDecodeError decode{};
  const auto wire = packet::isis::parse_ethernet_pdu(packet.frame->view(), decode);
  if (!wire) return;
  for (auto &owned : device.circuits) {
    if (owned.identity.interface_id != packet.metadata.interface_id ||
        owned.identity.physical_port_ordinal != packet.metadata.physical_port_ordinal ||
        owned.identity.instance != packet.metadata.instance_id) continue;
    if (!owned.carrier || (owned.update && !owned.update->admin_enabled)) { ++owned.counters.discarded; return; }
    packet::isis::InstanceError error{};
    const auto selection = packet::isis::select_instance(wire->pdu, owned.format, owned.physical_point_to_point, error);
    const bool p2p_hello = wire->pdu.type == packet::isis::PduType::point_to_point_hello;
    const bool lan_hello = wire->pdu.type == packet::isis::PduType::lan_hello_l1 || wire->pdu.type == packet::isis::PduType::lan_hello_l2;
    const bool hello = p2p_hello || lan_hello;
    if ((p2p_hello && owned.lan()) || (lan_hello && !owned.lan())) continue;
    if ((owned.destinations.select(wire->pdu.type) != wire->ethernet.destination) || !selection ||
        selection->instance != owned.wire_instance) continue;
    if (owned.identity.configuration_generation != packet.metadata.configuration_generation) {
      ++owned.counters.stale_ingress;
      continue;
    }
    if (!hello) {
      if (!owned.update || owned.update->status != UpdateStatus::applied) {
        ++owned.counters.update_discarded;
        owned.counters.last_update = UpdateStatus::inactive;
      } else {
        auto received = owned.update->process->receive(owned.update_slot,
            owned.identity.configuration_generation, *packet.frame, std::nullopt,
            now, owned.update->observer());
        const bool local_work = received.status == UpdateStatus::self_originated &&
            handle_self_lsp(owned, wire->pdu, *packet.frame, received, now);
        if (received.status == UpdateStatus::applied ||
            received.snp.database.status == SnpBatchStatus::accepted)
          handle_confusion(owned, wire->pdu, received, now);
        owned.counters.last_update = received.status;
        if (owned.update_egress && received.level < 2U) {
          owned.update_egress->lsp[received.level] = now;
          owned.update_egress->remaining[received.level] = 0U;
        }
        ++owned.counters.update_received;
        if (received.status != UpdateStatus::applied && !local_work) ++owned.counters.update_discarded;
      }
      continue;
    }
    if (owned.update && owned.update->status != UpdateStatus::applied) {
      ++owned.counters.received;
      ++owned.counters.discarded;
      continue;
    }
    if (auto *broadcast = owned.lan()) {
      const auto level = wire->pdu.type == packet::isis::PduType::lan_hello_l1 ? 0U : 1U;
      auto *circuit = broadcast->at(level);
      if (!circuit) continue;
      LanObserverContext context{owned, level};
      const auto received = circuit->receive(*packet.frame, std::nullopt, now, lan_observer(context));
      if (received == LanCircuitReceive::instance) continue;
      ++owned.counters.received;
      if (received != LanCircuitReceive::accepted) ++owned.counters.discarded;
      continue;
    }
    const auto received = owned.p2p().receive(*packet.frame, std::nullopt, now, &owned, event);
    if (received == CircuitReceive::instance) continue;
    ++owned.counters.received;
    if (received != CircuitReceive::accepted) ++owned.counters.discarded;
  }
}

void ControlWorker::run() noexcept {
  const auto hash = static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
  identity_.store(hash ? hash : 1U, std::memory_order_release);
  std::optional<ControlResult> pending_result;
  while (!stop_.load(std::memory_order_acquire)) {
    work_.store(false, std::memory_order_release);
    if (pending_result && results_.try_push(*pending_result)) pending_result.reset();
    auto command_budget = device_catalog::network_command_work_budget;
    while (!pending_result && command_budget--) {
      const auto command = commands_.receive();
      if (!command) break;
      const auto result = apply(*command->value);
      static_cast<void>(commands_.release(command->handle));
      if (!results_.try_push(result)) pending_result = result;
      if (stop_.load(std::memory_order_acquire)) break;
    }
    if (stop_.load(std::memory_order_acquire)) break;
    if (checkpoint_barrier_epoch_ || prepared_) {
      // Command/result handling remains live. A prepared generation also leases
      // every sequence floor and validation result until commit or abort. Defer
      // protocol directions, route receipts and absolute-deadline service so
      // refresh or ingress cannot invalidate that lease after acknowledgement.
      // A coalesced notification causes at most one extra paused command turn.
      std::unique_lock lock(wait_mutex_);
      wait_condition_.wait(lock, [&] {
        return stop_.load(std::memory_order_acquire) || work_.load(std::memory_order_acquire) ||
            (!pending_result && !commands_.empty());
      });
      continue;
    }
    const auto now = PointToPointCircuit::Clock::now();
    complete_routes(now);
    for (std::size_t shard{}; shard < forwarding_shards_; ++shard) {
      auto budget = device_catalog::isis_work_budget_packets;
      while (budget--) {
        const auto completion = channels_.egress[shard].try_completion();
        if (!completion) break;
        const auto handle = completion->metadata.device;
        if (handle.index >= devices_.size()) continue;
        auto &device = devices_[handle.index];
        if (!device.active || device.handle != handle) continue;
        packet::isis::EthernetDecodeError decode{};
        const auto wire = packet::isis::parse_ethernet_pdu(completion->frame->view(), decode);
        if (!wire) continue;
        for (auto &owned : device.circuits) if (owned.identity.interface_id == completion->metadata.interface_id &&
            owned.identity.physical_port_ordinal == completion->metadata.physical_port_ordinal &&
            owned.identity.instance == completion->metadata.instance_id) {
          if (!owned.carrier || (owned.update && !owned.update->admin_enabled)) { ++owned.counters.stale_completion; continue; }
          packet::isis::InstanceError error{};
          const auto selection = packet::isis::select_instance(wire->pdu, owned.format, owned.physical_point_to_point, error);
          if (owned.destinations.select(wire->pdu.type) != wire->ethernet.destination || !selection || selection->instance != owned.wire_instance) continue;
          if (owned.identity.configuration_generation != completion->metadata.configuration_generation ||
              completion->metadata.transmission_class != static_cast<std::uint8_t>(wire->pdu.type)) {
            ++owned.counters.stale_completion;
            continue;
          }
          if (wire->pdu.type == packet::isis::PduType::lan_hello_l1 || wire->pdu.type == packet::isis::PduType::lan_hello_l2) {
            const auto level = wire->pdu.type == packet::isis::PduType::lan_hello_l1 ? 0U : 1U;
            auto *broadcast = owned.lan();
            auto *circuit = broadcast ? broadcast->at(level) : nullptr;
            if (!circuit || !owned.lan_transmissions[level].complete(completion->metadata.configuration_generation,
                completion->metadata.transmission_id)) { ++owned.counters.stale_completion; continue; }
            if (circuit->complete_hello(completion->enqueued, now)) {
              if (completion->enqueued) ++owned.counters.hello_enqueued;
              else ++owned.counters.hello_refused;
            }
            continue;
          }
          if (owned.lan() && wire->pdu.type == packet::isis::PduType::point_to_point_hello) {
            ++owned.counters.stale_completion;
            continue;
          }
          if (wire->pdu.type != packet::isis::PduType::point_to_point_hello) {
            if (!complete_update(owned, *completion, wire->pdu, now)) ++owned.counters.stale_completion;
            continue;
          }
          if (!owned.transmission.complete(completion->metadata.configuration_generation,
              completion->metadata.transmission_id)) {
            ++owned.counters.stale_completion;
            continue;
          }
          if (owned.p2p().complete_hello(completion->enqueued, now)) {
            if (completion->enqueued) ++owned.counters.hello_enqueued;
            else ++owned.counters.hello_refused;
          }
        }
      }
      budget = device_catalog::isis_work_budget_packets;
      while (budget--) {
        const auto packet = channels_.ingress[shard].try_receive();
        if (!packet) break;
        receive(*packet, now);
        static_cast<void>(channels_.ingress[shard].release(packet->handle));
      }
    }
    classify_lan_backlog();
    auto deadline = PointToPointCircuit::Clock::time_point::max();
    auto transmit_budget = device_catalog::isis_work_budget_packets;
    auto generation_budget = device_catalog::isis_work_budget_packets;
    auto lifetime_budget = device_catalog::isis_work_budget_packets;
    for (std::size_t offset{}; offset < devices_.size(); ++offset) {
      auto &device = devices_[(first_device_ + offset) % devices_.size()];
      // Expired adjacency and DIS work precedes new local content and SPF.
      // If a bounded LAN expiration quantum leaves due peers, defer fresh
      // decisions to the next immediate owner turn rather than reuse stale Up.
      bool adjacency_pending{};
      for (auto &owned : device.circuits) {
        if (!owned.carrier) continue;
        if (owned.update && !owned.update->admin_enabled) continue;
        if (owned.update && owned.update->status != UpdateStatus::applied) continue;
        if (auto *broadcast = owned.lan()) {
          for (std::size_t level{}; level < 2U; ++level) if (auto *circuit = broadcast->at(level)) {
            LanObserverContext context{owned, level};
            circuit->service(now, device_catalog::isis_work_budget_packets, lan_observer(context));
            if (const auto due = circuit->neighbors().deadline(); due && *due <= now) adjacency_pending = true;
          }
        } else static_cast<void>(owned.p2p().expire(now, &owned, event));
      }
      if (adjacency_pending) deadline = std::min(deadline, now);
      for (std::size_t ordinal{}; ordinal < device.instance_count; ++ordinal) {
        const auto index = device.instance_order[(device.first_instance + ordinal) % device.instance_count];
        if (!adjacency_pending && device.instances[index]->admin_enabled)
          deadline = std::min(deadline, service_local_instance(device, index, now, generation_budget));
        deadline = std::min(deadline, service_update_lifetimes(*device.instances[index], now, lifetime_budget));
      }
      if (device.instance_count) device.first_instance = (device.first_instance + 1U) % device.instance_count;
      for (std::size_t ordinal{}; ordinal < device.circuits.size(); ++ordinal) {
        auto &owned = device.circuits[(device.first_circuit + ordinal) % device.circuits.size()];
        if (!owned.carrier) continue;
        if (owned.update && !owned.update->admin_enabled) continue;
        if (owned.update && owned.update->status != UpdateStatus::applied) {
          owned.transmission.cancel();
          circuit_down(owned);
          continue;
        }
        if (owned.lan()) {
          deadline = std::min(deadline, service_previous_pseudonodes(owned, now, lifetime_budget));
          deadline = std::min(deadline, service_lan(owned, now, transmit_budget));
          deadline = std::min(deadline, emit_updates(owned, now, transmit_budget));
          continue;
        }
        const auto shard = owned.identity.device.index % forwarding_shards_;
        auto &channel = channels_.egress[shard];
        if (transmit_budget && channel.producer_available()) {
          const auto built = owned.p2p().hello(output_, std::nullopt, scratch_, now);
          if (built) --transmit_budget;
          if (built && *built == HelloBuildResult::encoded) {
            const auto ticket = owned.transmission.begin();
            if (!ticket) {
              ++owned.counters.transmission_exhausted;
              circuit_down(owned);
              continue;
            }
            const bool published = channel.try_send({owned.identity.device, owned.identity.interface_id,
                owned.identity.physical_port_ordinal, owned.identity.configuration_generation, *ticket,
                static_cast<std::uint8_t>(packet::isis::PduType::point_to_point_hello), owned.identity.instance}, output_);
            if (!published) {
              owned.transmission.cancel();
              static_cast<void>(owned.p2p().complete_hello(false, now));
            }
            else if (channels_.egress_wakeup) channels_.egress_wakeup(channels_.egress_context, shard);
          }
        }
        deadline = std::min(deadline, emit_updates(owned, now, transmit_budget));
        const auto next = owned.p2p().deadline();
        // A ready circuit with no channel credit waits for its completion
        // notification. Its holding deadline still participates in expiry.
        if (next > now || channel.producer_available()) deadline = std::min(deadline, next);
        else if (const auto holding = owned.p2p().holding_deadline()) deadline = std::min(deadline, *holding);
      }
      if (!device.circuits.empty()) device.first_circuit = (device.first_circuit + 1U) % device.circuits.size();
      deadline = std::min(deadline, service_routes(device, now));
    }
    first_device_ = (first_device_ + 1U) % devices_.size();
    std::unique_lock lock(wait_mutex_);
    const auto ready = [&] {
      return stop_.load(std::memory_order_acquire) || work_.load(std::memory_order_acquire) ||
          (!pending_result && !commands_.empty());
    };
    if (deadline == PointToPointCircuit::Clock::time_point::max()) wait_condition_.wait(lock, ready);
    else static_cast<void>(wait_condition_.wait_until(lock, deadline, ready));
  }
  identity_.store(0U, std::memory_order_release);
}

} // namespace router::isis
