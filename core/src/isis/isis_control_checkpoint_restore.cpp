// The IS-IS control owner prepares an independent registry under a transport
// barrier. Every child is validated before the allocation-free registry swap;
// failure destroys candidates and leaves live owners and channels untouched.

#include "router/isis_control_checkpoint.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
std::unique_ptr<ControlWorker::PreparedCheckpoint> ControlWorker::prepare_checkpoint_restore(
    const ControlWorkerCheckpoint &saved, std::uint64_t source_epoch, RuntimeClock::time_point now) const noexcept {
  if (saved.version != 5U || !source_epoch || saved.barrier_epoch != source_epoch ||
      saved.forwarding_shards != forwarding_shards_ || saved.maximum_circuits != maximum_circuits_ ||
      saved.active_circuits > maximum_circuits_ || saved.first_device >= devices_.size() ||
      saved.devices.size() > devices_.size()) return nullptr;
  try {
    auto result = std::make_unique<PreparedCheckpoint>();
    result->source_epoch = source_epoch;
    result->first_device = saved.first_device;
    std::optional<std::size_t> previous;
    for (const auto &source : saved.devices) {
      const auto index = source.handle.index;
      if (!source.handle.generation || index >= devices_.size() || (previous && index <= *previous) ||
          source.first_instance > device_catalog::isis_instance_last || source.first_circuit > maximum_circuits_ ||
          source.instances.size() > device_catalog::isis_instance_last + 1U ||
          source.gates.size() > device_catalog::isis_instance_last + 1U ||
          source.instance_order.size() != source.instances.size() ||
          source.route_status > routing::RouteInstallStatus::forwarding_failed ||
          source.route_installed > source.route_generation ||
          (source.route_pending && source.route_pending != source.route_generation) ||
          source.route_retry < std::chrono::milliseconds::zero() ||
          (!source.active && (!source.circuits.empty() || !source.instances.empty()))) return nullptr;
      previous = index;
      auto &target = result->devices[index];
      target.handle = source.handle;
      target.active = source.active;
      target.retired_epoch_floor = source.retired_epoch_floor;
      target.update_fences = source.update_fences;
      target.first_instance = source.first_instance;
      target.first_circuit = source.first_circuit;
      target.route_generation = source.route_generation;
      target.route_installed = source.route_installed;
      target.route_pending = source.route_pending;
      target.route_status = source.route_status;
      target.route_retry = source.route_retry;
      const auto retry = checkpoint_time::restore_deadline(source.route_retry_at, now);
      if (!retry) return nullptr;
      target.route_retry_at = *retry;
      for (std::size_t instance{}; instance < target.instances.size(); ++instance) {
        const auto restore_stamp = [](const auto &image, auto &stamp) {
          if (image.status > UpdateStatus::adjacency || image.families > 3U) return false;
          stamp = {image.epoch, image.decision, image.status, image.families};
          return true;
        };
        if (!restore_stamp(source.installed_routes[instance], target.installed_routes[instance]) ||
            !restore_stamp(source.pending_routes[instance], target.pending_routes[instance])) return nullptr;
      }
      std::optional<std::uint8_t> previous_instance;
      for (const auto &instance : source.instances) {
        if (instance.instance > device_catalog::isis_instance_last || (previous_instance && instance.instance <= *previous_instance)) return nullptr;
        previous_instance = instance.instance;
        target.instances[instance.instance] = restore_checkpoint_instance(instance, now);
        if (!target.instances[instance.instance]) return nullptr;
      }
      std::array<bool, device_catalog::isis_instance_last + 1U> ordered{};
      for (const auto instance : source.instance_order) {
        if (instance > device_catalog::isis_instance_last || ordered[instance] || !target.instances[instance]) return nullptr;
        ordered[instance] = true;
        target.instance_order[target.instance_count++] = instance;
      }
      previous_instance.reset();
      for (const auto &gate : source.gates) {
        if (gate.instance > device_catalog::isis_instance_last || (previous_instance && gate.instance <= *previous_instance)) return nullptr;
        previous_instance = gate.instance;
        auto restored = SequenceRecovery::restore_checkpoint(gate.state, now);
        if (!restored) return nullptr;
        if (const auto &instance = target.instances[gate.instance]; instance && instance->configuration.origination) {
          std::array<std::optional<SequenceLevelLifetime>, 2U> lifetimes;
          for (std::size_t level{}; level < 2U; ++level) if (instance->configuration.levels[level])
            lifetimes[level] = SequenceLevelLifetime{instance->configuration.levels[level]->maximum_age,
                static_cast<std::uint16_t>(instance->configuration.levels[level]->purge_retention.count())};
          SequenceRecovery expected(lifetimes, instance->configuration.origination->resource_retry);
          if (!expected.restore(gate.state, now)) return nullptr;
        }
        target.sequence_recovery[gate.instance] = std::make_unique<SequenceRecovery>(std::move(*restored));
      }
      for (std::size_t instance{}; instance < target.instances.size(); ++instance)
        if (target.instances[instance] && target.instances[instance]->configuration.origination &&
            (!target.sequence_recovery[instance] || (!target.instances[instance]->process &&
                !target.sequence_recovery[instance]->disabled()))) return nullptr;
      if (source.circuits.size() > maximum_circuits_ - result->active_circuits) return nullptr;
      target.circuits.reserve(source.circuits.size());
      for (const auto &circuit : source.circuits) {
        if (std::any_of(target.circuits.begin(), target.circuits.end(), [&](const auto &existing) {
          return existing.identity.instance == circuit.definition.identity.instance &&
              existing.identity.interface_id == circuit.definition.identity.interface_id;
        })) return nullptr;
        auto restored = restore_checkpoint_circuit(circuit, target, now);
        if (!restored) return nullptr;
        if (restored->update && std::any_of(target.circuits.begin(), target.circuits.end(), [&](const auto &existing) {
          return existing.update == restored->update && existing.update_slot == restored->update_slot;
        })) return nullptr;
        target.circuits.push_back(std::move(*restored));
      }
      result->active_circuits += target.circuits.size();
    }
    if (result->active_circuits != saved.active_circuits) return nullptr;
    return result;
  } catch (const std::exception &) { return nullptr; }
}
} // namespace router::isis
