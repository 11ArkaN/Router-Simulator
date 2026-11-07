// A prepared level owner keeps its databases and borrowing exchanges at stable
// heap addresses. Failed restoration destroys only this unpublished candidate;
// the enclosing instance commits owner pointers after every level is prepared.

#include "router/isis_level_process.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <new>
#include <stdexcept>

namespace router::isis {
LevelProcessCheckpoint LevelProcess::checkpoint(RuntimeClock::time_point now) const {
  LevelProcessCheckpoint result;
  result.database = database_.checkpoint(now);
  result.acknowledgements = acknowledgements_.checkpoint();
  result.configuration = {database_.type(), result.database.database.limits, result.acknowledgements.capacity,
      maximum_age_, purge_retention_, waiting_time_, result.database.maximum_circuits};
  result.waiting = waiting_;
  result.waiting_timer_expired = waiting_timer_expired_;
  if (waiting_) {
    result.waiting_nanoseconds = checkpoint_time::offset(waiting_until_, now);
    if (!result.waiting_nanoseconds) throw std::invalid_argument("IS-IS Waiting checkpoint clock range is invalid");
  }
  result.circuits.reserve(circuits_.size());
  for (const auto &circuit : circuits_)
    result.circuits.push_back({circuit.configuration, circuit.eligible, circuit.designated, circuit.activated,
        circuit.snp.checkpoint(), circuit.lsp.checkpoint()});
  return result;
}

std::unique_ptr<LevelProcess> LevelProcess::restore_checkpoint(const LevelProcessCheckpoint &saved,
    LevelProcessConfiguration expected, std::span<const LevelCircuitProgram> bindings,
    RuntimeClock::time_point now) noexcept {
  if (!expected.maximum_circuits) expected.maximum_circuits = bindings.size();
  if (saved.version != 1U || saved.configuration != expected || saved.circuits.size() != bindings.size() ||
      bindings.size() > expected.maximum_circuits || saved.database.circuits.size() != bindings.size() ||
      saved.waiting != saved.waiting_nanoseconds.has_value()) return nullptr;
  for (std::size_t index{}; index < bindings.size(); ++index) {
    const auto &circuit = saved.circuits[index];
    if (circuit.configuration != bindings[index].configuration ||
        circuit.snp.entry_capacity != bindings[index].snp_entry_capacity ||
        (circuit.eligible && !circuit.activated) ||
        (circuit.designated && (!circuit.eligible || !circuit.configuration.broadcast)) ||
        saved.database.circuits[index].eligible != circuit.eligible ||
        (!circuit.eligible && (circuit.snp.transmission.pending || circuit.lsp.transmission.pending || circuit.snp.complete.active)) ||
        (!circuit.activated && (circuit.snp.transmission.next_ticket != 1U || circuit.lsp.transmission.next_ticket != 1U))) return nullptr;
  }
  for (const auto &entry : saved.acknowledgements.entries)
    if (entry.circuit >= saved.circuits.size() || !saved.circuits[entry.circuit].eligible) return nullptr;
  try {
    auto result = std::make_unique<LevelProcess>(expected.level, expected.database,
        std::span<const LevelCircuitConfiguration>{}, expected.acknowledgement_capacity, 0U,
        expected.maximum_age, expected.purge_retention, expected.waiting_time, expected.maximum_circuits);
    // Prepare the complete slot count once, before any borrowing coordinator
    // is built. Later vector moves are unnecessary throughout restoration.
    result->circuits_.reserve(bindings.size());
    if (!result->database_.reserve_circuit_capacity(bindings.size())) return nullptr;
    for (std::size_t index{}; index < bindings.size(); ++index) {
      const auto admitted = result->admit_circuit(bindings[index].configuration, bindings[index].snp_entry_capacity);
      if (admitted.status != LevelStatus::applied || admitted.index != index) return nullptr;
    }
    if (!result->database_.restore(saved.database, now, expected.maximum_age) ||
        !result->acknowledgements_.restore(saved.acknowledgements, bindings.size())) return nullptr;
    for (std::size_t index{}; index < bindings.size(); ++index) {
      auto &circuit = result->circuits_[index];
      const auto &state = saved.circuits[index];
      if (!circuit.snp.restore(state.snp) || !circuit.lsp.restore(state.lsp)) return nullptr;
      circuit.eligible = state.eligible;
      circuit.designated = state.designated;
      circuit.activated = state.activated;
    }
    if (saved.waiting_nanoseconds) {
      const auto maximum = std::chrono::duration_cast<std::chrono::nanoseconds>(expected.waiting_time).count();
      if (*saved.waiting_nanoseconds > maximum || (saved.waiting_timer_expired && *saved.waiting_nanoseconds > 0)) return nullptr;
      const auto deadline = checkpoint_time::restore(*saved.waiting_nanoseconds, now);
      if (!deadline) return nullptr;
      result->waiting_until_ = *deadline;
    }
    result->waiting_ = saved.waiting;
    result->waiting_timer_expired_ = saved.waiting_timer_expired;
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
