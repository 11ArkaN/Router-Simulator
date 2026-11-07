// The instance owner prepares both levels and stable circuit mappings together.
// Peer catalogs are accepted same-owner projections, not topology lookups.
// Restoration never publishes a half-built level or moves its borrowed state.

#include "router/isis_instance_update.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>
#include <utility>

namespace router::isis {
InstanceUpdateCheckpoint InstanceUpdateProcess::checkpoint(RuntimeClock::time_point now) const {
  InstanceUpdateCheckpoint result;
  result.configuration = {local_, maximum_areas_, configuration_, selector_, maximum_circuits_, initial_synchronization_epoch_};
  result.admission_counter = admission_ticket_;
  result.circuits.reserve(circuits_.size());
  for (const auto &circuit : circuits_)
    result.circuits.push_back({circuit.configuration, circuit.synchronization_epochs, circuit.activated, circuit.configured,
        circuit.admission_pending, circuit.admission_ticket, circuit.active, circuit.peer, circuit.lan_peers});
  for (std::size_t level{}; level < levels_.size(); ++level)
    if (levels_[level]) result.levels[level] = levels_[level]->checkpoint(now);
  return result;
}

std::unique_ptr<InstanceUpdateProcess> InstanceUpdateProcess::restore_checkpoint(const InstanceUpdateCheckpoint &saved,
    InstanceUpdateConfiguration expected, std::span<const UpdateCircuitConfiguration> bindings,
    RuntimeClock::time_point now) noexcept {
  if (!expected.maximum_circuits) expected.maximum_circuits = bindings.size();
  if (saved.version != 1U || saved.configuration != expected || saved.circuits.size() != bindings.size() ||
      bindings.size() > expected.maximum_circuits) return nullptr;
  const auto present = [](Levels mask, std::size_t level) { return (static_cast<unsigned>(mask) & (1U << level)) != 0U; };
  const auto valid_peer = [](const packet::Mac &peer) { return peer != packet::Mac{} && !(peer[0U] & 1U); };
  for (std::size_t index{}; index < saved.circuits.size(); ++index) {
    const auto &circuit = saved.circuits[index];
    const auto mask = static_cast<unsigned>(circuit.active);
    if (circuit.configuration != bindings[index] || mask > 3U ||
        (mask & ~static_cast<unsigned>(circuit.configuration.levels)) ||
        (!circuit.configured && (mask || circuit.peer != packet::Mac{})) ||
        (circuit.admission_pending && (mask || !circuit.admission_ticket)) ||
        circuit.admission_ticket > saved.admission_counter ||
        (circuit.configuration.broadcast && circuit.peer != packet::Mac{}) ||
        (!circuit.configuration.broadcast && circuit.peer != packet::Mac{} && !valid_peer(circuit.peer)) ||
        (!circuit.configuration.broadcast && mask && !valid_peer(circuit.peer))) return nullptr;
    for (std::size_t level{}; level < 2U; ++level) {
      const bool active = present(circuit.active, level);
      const auto &peers = circuit.lan_peers[level];
      if (circuit.synchronization_epochs[level] < expected.initial_synchronization_epoch ||
          (!circuit.activated[level] && circuit.synchronization_epochs[level] != expected.initial_synchronization_epoch) ||
          (active && !circuit.activated[level]) || peers.size() > circuit.configuration.neighbor_capacity ||
          (!circuit.configuration.broadcast && !peers.empty()) ||
          (circuit.configuration.broadcast && active != !peers.empty()) ||
          (!expected.levels[level] && (active || circuit.activated[level] || !peers.empty()))) return nullptr;
      for (std::size_t peer{}; peer < peers.size(); ++peer)
        if (!valid_peer(peers[peer]) || (peer && peers[peer - 1U] >= peers[peer])) return nullptr;
    }
  }
  try {
    std::vector<std::uint64_t> tickets;
    tickets.reserve(bindings.size());
    for (const auto &circuit : saved.circuits) if (circuit.admission_ticket) tickets.push_back(circuit.admission_ticket);
    std::sort(tickets.begin(), tickets.end());
    if (std::adjacent_find(tickets.begin(), tickets.end()) != tickets.end()) return nullptr;
    // The deferred constructor performs normal policy and circuit validation
    // and reserves peer catalogs, but builds no disposable empty level owners.
    auto result = std::unique_ptr<InstanceUpdateProcess>(new InstanceUpdateProcess(expected.local, expected.maximum_areas,
        expected.levels, bindings, expected.selector, expected.maximum_circuits, expected.initial_synchronization_epoch,
        LevelConstruction::deferred));
    std::vector<LevelCircuitProgram> slots;
    slots.reserve(bindings.size());
    for (std::size_t level{}; level < expected.levels.size(); ++level) {
      if (saved.levels[level].has_value() != expected.levels[level].has_value()) return nullptr;
      if (!expected.levels[level]) continue;
      const auto &state = *saved.levels[level];
      if (state.circuits.size() != bindings.size()) return nullptr;
      slots.clear();
      for (std::size_t index{}; index < bindings.size(); ++index) {
        const auto &upper = saved.circuits[index];
        const auto &lower = state.circuits[index];
        const bool active = present(upper.active, level);
        if (lower.configuration.epoch != upper.synchronization_epochs[level] || lower.eligible != active ||
            lower.activated != upper.activated[level] || (active && lower.configuration.broadcast != upper.configuration.broadcast))
          return nullptr;
        // Inactive levels can retain a previous medium until their next Up.
        // Their captured media are still cross-checked by the level database.
        slots.push_back({lower.configuration, expected.levels[level]->snp_entry_capacity});
      }
      const auto &configuration = *expected.levels[level];
      const LevelProcessConfiguration policy{level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1,
          effective_limits(configuration, expected.selector, expected.maximum_circuits), configuration.acknowledgement_capacity,
          configuration.maximum_age, configuration.purge_retention, configuration.waiting_time, expected.maximum_circuits};
      result->levels_[level] = LevelProcess::restore_checkpoint(state, policy, slots, now);
      if (!result->levels_[level]) return nullptr;
    }
    for (std::size_t index{}; index < bindings.size(); ++index) {
      auto &circuit = result->circuits_[index];
      const auto &state = saved.circuits[index];
      circuit.synchronization_epochs = state.synchronization_epochs;
      circuit.activated = state.activated;
      circuit.configured = state.configured;
      circuit.admission_pending = state.admission_pending;
      circuit.admission_ticket = state.admission_ticket;
      circuit.active = state.active;
      circuit.peer = state.peer;
      for (std::size_t level{}; level < 2U; ++level)
        circuit.lan_peers[level].assign(state.lan_peers[level].begin(), state.lan_peers[level].end());
    }
    result->admission_ticket_ = saved.admission_counter;
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
