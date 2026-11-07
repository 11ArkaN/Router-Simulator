// Detached circuit restoration belongs to the IS-IS control owner. Candidate
// instance pointers stay within the candidate registry. Child validation and
// receipt identities are checked before any live owner can be replaced.

#include "router/isis_control_checkpoint.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
std::unique_ptr<ControlWorker::OwnedCircuit> ControlWorker::restore_checkpoint_circuit(
    const ControlCircuitCheckpoint &saved, DeviceState &device, RuntimeClock::time_point now) const noexcept {
  try {
    const auto &definition = saved.definition;
    const auto &identity = definition.identity;
    if (identity.device != device.handle || !identity.interface_id || !identity.configuration_generation ||
        identity.instance > device_catalog::isis_instance_last ||
        identity.physical_port_ordinal >= device_catalog::maximum_ports_per_router || !definition.random_state ||
        definition.broadcast.has_value() != std::holds_alternative<LanPairCheckpoint>(saved.medium)) return nullptr;
    ControlCommand command;
    command.identity = identity;
    command.configuration = definition.configuration;
    command.broadcast = definition.broadcast;
    command.random_state = definition.random_state;
    command.update_transmission = definition.update_transmission;
    std::optional<OwnedCircuit::Medium> medium;
    if (definition.broadcast) {
      auto child = LanCircuitPair::restore_checkpoint(std::get<LanPairCheckpoint>(saved.medium), *definition.broadcast, now);
      if (!child) return nullptr;
      medium.emplace(std::in_place_type<LanCircuitPair>, std::move(*child));
    } else {
      auto child = PointToPointCircuit::restore_checkpoint(std::get<P2pCircuitCheckpoint>(saved.medium), definition.configuration, now);
      if (!child) return nullptr;
      medium.emplace(std::in_place_type<PointToPointCircuit>, std::move(*child));
    }
    auto result = std::make_unique<OwnedCircuit>(command, now, std::move(medium));
    if (!result->transmission.restore(saved.transmission)) return nullptr;
    if (result->lan()) {
      if (saved.transmission.pending) return nullptr;
    } else if (static_cast<bool>(saved.transmission.pending) != result->p2p().hello_pending()) return nullptr;
    for (std::size_t level{}; level < 2U; ++level) {
      if (!result->lan_transmissions[level].restore(saved.lan_transmissions[level])) return nullptr;
      const auto *lan = result->lan() ? result->lan()->at(level) : nullptr;
      if (static_cast<bool>(saved.lan_transmissions[level].pending) != (lan && lan->hello_pending())) return nullptr;
      const auto &previous = saved.previous_dis[level];
      const auto retry = checkpoint_time::restore_deadline(previous.retry, now);
      if (!retry || previous.fragment > 256U || (!result->lan() && (previous.remote || previous.fragment != 256U))) return nullptr;
      result->previous_dis[level] = {previous.remote, previous.fragment, *retry};
    }
    result->counters = saved.counters;
    result->queued_lsp = saved.queued_lsp;
    if (saved.update_slot) {
      result->update = device.instances[identity.instance].get();
      if (!result->update || !matches_update_instance(result->update->configuration, result->update_view(), identity.interface_id)) return nullptr;
      result->update_slot = *saved.update_slot;
      if (result->update->process) {
        const auto image = result->update->process->checkpoint(now);
        if (*saved.update_slot >= image.circuits.size() || !image.circuits[*saved.update_slot].configured ||
            image.circuits[*saved.update_slot].configuration != update_configuration(*result)) return nullptr;
      } else if (saved.egress) return nullptr;
    } else if (saved.egress) return nullptr;
    if (!saved.egress) {
      if (result->update && result->update->process) return nullptr;
      return result;
    }
    const auto &source = *saved.egress;
    const auto expected = definition.update_transmission.value_or(result->update->configuration.transmission);
    if (source.program != expected || !valid_medium_transmission(expected, result->update_view()) || !source.random ||
        source.credits > expected.pacing_burst) return nullptr;
    auto target = std::make_unique<UpdateEgress>(*result->update, definition.random_state, definition.update_transmission);
    if (source.retries.size() > target->retries.capacity() ||
        source.broadcast_scan.has_value() != target->broadcast_scan.has_value()) return nullptr;
    const auto restore = [&](const auto &image, auto &value) {
      const auto restored = checkpoint_time::restore_deadline(image, now);
      if (!restored) throw std::invalid_argument("IS-IS egress checkpoint clock range");
      value = *restored;
    };
    for (const auto &retry : source.retries) {
      if (retry.level > 1U || !result->update->configuration.levels[retry.level] ||
          !retry.header.sequence) return nullptr;
      RuntimeClock::time_point at;
      restore(retry.at, at);
      target->retries.push_back({retry.header, retry.level, at});
    }
    // Retry order is scheduling state. Check uniqueness through a detached index
    // instead of sorting the restored owner's fair iteration order.
    std::vector<std::pair<std::size_t, packet::isis::LspId>> identities;
    identities.reserve(source.retries.size());
    for (const auto &retry : source.retries) identities.emplace_back(retry.level, retry.header.id);
    std::sort(identities.begin(), identities.end());
    if (std::adjacent_find(identities.begin(), identities.end()) != identities.end()) return nullptr;
    target->epochs = source.epochs;
    target->revision = source.revision;
    target->complete_started = source.complete_started;
    target->transient_first = source.transient_first;
    target->designated = source.designated;
    target->scan = source.scan;
    target->remaining = source.remaining;
    target->credits = source.credits;
    target->random = source.random;
    target->lan_active = source.lan_active;
    target->synchronize = source.synchronize;
    restore(source.pacing, target->pacing);
    restore(source.csnp_ready, target->csnp_ready);
    for (std::size_t level{}; level < 2U; ++level) {
      restore(source.partial[level], target->partial[level]);
      restore(source.complete[level], target->complete[level]);
      restore(source.complete_periodic[level], target->complete_periodic[level]);
      restore(source.lsp[level], target->lsp[level]);
      restore(source.earliest[level], target->earliest[level]);
      const auto &configuration = result->update->configuration.levels[level];
      if (source.scan[level] > (configuration ? configuration->database.records : 0U) ||
          source.remaining[level] > (configuration ? configuration->database.records : 0U)) return nullptr;
    }
    if (source.broadcast_scan && !target->broadcast_scan->restore(*source.broadcast_scan, now)) return nullptr;
    if ((!result->lan() && (source.lan_active || source.lan_lsp || source.lan_csnp)) ||
        (source.broadcast_scan && source.broadcast_scan->pending != source.lan_lsp.has_value())) return nullptr;
    const auto reservation = [&](const auto &image, auto &value) {
      if (!image) return true;
      if (image->level > 1U || !image->epoch || !image->ticket || !result->lan()->at(image->level)) return false;
      value = UpdateEgress::LanReservation{image->level, image->epoch, image->ticket};
      return true;
    };
    if (!reservation(source.lan_lsp, target->lan_lsp) || !reservation(source.lan_csnp, target->lan_csnp)) return nullptr;
    const auto matches_reservation = [&](const auto &image, bool complete) {
      if (!image) return true;
      const auto output = result->update->process->outputs(result->update_slot, image->level);
      if (!output || output->synchronization_epoch != image->epoch) return false;
      if (!complete) return output->reservations.lsp.checkpoint().transmission.pending == image->ticket;
      const auto snp = output->reservations.snp.checkpoint();
      return snp.transmission.pending == image->ticket && snp.pending_emission == SnpEmission::complete;
    };
    if (!matches_reservation(source.lan_lsp, false) || !matches_reservation(source.lan_csnp, true)) return nullptr;
    result->update_egress = std::move(target);
    return result;
  } catch (const std::exception &) { return nullptr; }
}
} // namespace router::isis
