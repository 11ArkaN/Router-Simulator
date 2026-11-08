// The quiescent IS-IS pthread copies its complete owned state into detached
// values. Timers become relative or explicit sentinels; scratch, pointers and
// key leases are omitted. No frame is replayed or protocol observer invoked.

#include "router/isis_control_checkpoint.hpp"

#include <stdexcept>

namespace router::isis {
ControlWorkerCheckpoint ControlWorker::capture_checkpoint(RuntimeClock::time_point now) const {
  if (!checkpoint_barrier_epoch_ || prepared_) throw std::logic_error("IS-IS capture requires stable quiescence");
  const auto deadline = [&](RuntimeClock::time_point point) {
    const auto result = checkpoint_time::deadline(point, now);
    if (!result) throw std::invalid_argument("IS-IS control checkpoint clock range");
    return *result;
  };
  ControlWorkerCheckpoint result;
  result.barrier_epoch = checkpoint_barrier_epoch_;
  result.forwarding_shards = forwarding_shards_;
  result.maximum_circuits = maximum_circuits_;
  result.active_circuits = active_circuits_;
  result.first_device = first_device_;
  result.devices.reserve(devices_.size());
  for (const auto &device : devices_) {
    if (!device.handle.generation) continue;
    auto &out = result.devices.emplace_back();
    out.handle = device.handle;
    out.active = device.active;
    out.retired_epoch_floor = device.retired_epoch_floor;
    out.update_fences = device.update_fences;
    out.instance_order.assign(device.instance_order.begin(), device.instance_order.begin() +
        static_cast<std::ptrdiff_t>(device.instance_count));
    out.first_instance = device.first_instance;
    out.first_circuit = device.first_circuit;
    out.route_generation = device.route_generation;
    out.route_installed = device.route_installed;
    out.route_pending = device.route_pending;
    out.route_status = device.route_status;
    out.route_retry_at = deadline(device.route_retry_at);
    out.route_retry = device.route_retry;
    for (std::size_t index{}; index < device.instances.size(); ++index) {
      const auto project = [](const auto &stamp) { return ControlRouteStamp{stamp.epoch, stamp.decision, stamp.status, stamp.families}; };
      out.installed_routes[index] = project(device.installed_routes[index]);
      out.pending_routes[index] = project(device.pending_routes[index]);
      if (device.sequence_recovery[index])
        out.gates.push_back({static_cast<std::uint8_t>(index), device.sequence_recovery[index]->checkpoint(now)});
      if (!device.instances[index]) continue;
      const auto &instance = *device.instances[index];
      auto &saved = out.instances.emplace_back();
      saved.instance = static_cast<std::uint8_t>(index);
      saved.configuration = instance.configuration;
      if (instance.process) saved.process = instance.process->checkpoint(now);
      if (instance.local) saved.local = instance.local->checkpoint(now);
      saved.consumed_decision_revision = instance.consumed_decision_revision;
      saved.decision_runs = instance.decision_runs;
      saved.decision_status = instance.decision_status;
      saved.local_roots_dirty = instance.local_roots_dirty;
      saved.first_root_level = instance.first_root_level;
      saved.database_validations = instance.database_validations;
      saved.decision_revisions = instance.decision_revisions;
      saved.revision = instance.revision;
      saved.expiration_revision = instance.expiration_revision;
      saved.expiration_blocked = instance.expiration_blocked;
      saved.corrupted_lsp = instance.corrupted_lsp;
      saved.status = instance.status;
      for (std::size_t level{}; level < 2U; ++level) {
        if (instance.decisions[level]) saved.decisions[level] = instance.decisions[level]->checkpoint();
        if (instance.spf[level]) saved.spf[level] = instance.spf[level]->checkpoint(now);
        if (instance.validation[level]) saved.validation[level] = instance.validation[level]->checkpoint(now);
      }
      for (std::size_t family{}; family < saved.families.size(); ++family) {
        auto &target = saved.families[family];
        const auto &source = instance.route_families[family];
        target.consumed = source.consumed;
        target.status = source.status;
        target.bindings = source.bindings;
        for (std::size_t level{}; level < 2U; ++level)
          if (source.decisions[level]) target.decisions[level] = source.decisions[level]->checkpoint();
      }
    }
    out.circuits.reserve(device.circuits.size());
    for (const auto &circuit : device.circuits) {
      if (circuit.rebind_update) throw std::logic_error("IS-IS capture during unpublished circuit binding");
      auto &saved = out.circuits.emplace_back();
      saved.definition.identity = circuit.identity;
      saved.definition.random_state = circuit.random_state;
      saved.definition.update_transmission = circuit.update_transmission;
      saved.definition.carrier = circuit.carrier;
      if (const auto *lan = circuit.lan()) {
        LanCircuitProgram program;
        for (std::size_t level{}; level < 2U; ++level)
          if (const auto *entry = lan->at(level)) program.levels[level] = entry->configuration();
        saved.definition.broadcast = std::move(program);
        saved.medium = lan->checkpoint(now);
      } else {
        saved.definition.configuration = circuit.p2p().configuration();
        saved.medium = circuit.p2p().checkpoint(now);
      }
      saved.transmission = circuit.transmission.checkpoint();
      saved.counters = circuit.counters;
      if (circuit.update) saved.update_slot = circuit.update_slot;
      saved.queued_lsp = circuit.queued_lsp;
      for (std::size_t level{}; level < 2U; ++level) {
        saved.lan_transmissions[level] = circuit.lan_transmissions[level].checkpoint();
        saved.previous_dis[level] = {circuit.previous_dis[level].remote, circuit.previous_dis[level].fragment,
            deadline(circuit.previous_dis[level].retry)};
      }
      if (!circuit.update_egress) continue;
      const auto &source = *circuit.update_egress;
      auto &target = saved.egress.emplace();
      target.program = source.program;
      target.retries.reserve(source.retries.size());
      for (const auto &retry : source.retries) target.retries.push_back({retry.header, retry.level, deadline(retry.at)});
      target.epochs = source.epochs;
      target.revision = source.revision;
      target.complete_started = source.complete_started;
      target.transient_first = source.transient_first;
      target.designated = source.designated;
      target.scan = source.scan;
      target.remaining = source.remaining;
      target.pacing = deadline(source.pacing);
      target.csnp_ready = deadline(source.csnp_ready);
      target.credits = source.credits;
      target.random = source.random;
      target.lan_active = source.lan_active;
      target.synchronize = source.synchronize;
      if (source.broadcast_scan) target.broadcast_scan = source.broadcast_scan->checkpoint(now);
      if (source.lan_lsp) target.lan_lsp = {source.lan_lsp->level, source.lan_lsp->epoch, source.lan_lsp->ticket};
      if (source.lan_csnp) target.lan_csnp = {source.lan_csnp->level, source.lan_csnp->epoch, source.lan_csnp->ticket};
      for (std::size_t level{}; level < 2U; ++level) {
        target.partial[level] = deadline(source.partial[level]);
        target.complete[level] = deadline(source.complete[level]);
        target.complete_periodic[level] = deadline(source.complete_periodic[level]);
        target.lsp[level] = deadline(source.lsp[level]);
        target.earliest[level] = deadline(source.earliest[level]);
      }
    }
  }
  return result;
}
} // namespace router::isis
