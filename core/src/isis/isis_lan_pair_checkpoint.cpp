// The interface aggregate publishes both restored LAN levels together.
// Normal construction validates shared identity before independently checked
// level states replace its cold owners. No borrowed area storage is relocated.

#include "router/isis_lan_circuit_pair.hpp"

#include <new>
#include <stdexcept>
#include <utility>

namespace router::isis {
LanPairCheckpoint LanCircuitPair::checkpoint(LanCircuit::Clock::time_point now) const {
  LanPairCheckpoint result;
  for (std::size_t level{}; level < circuits_.size(); ++level)
    if (circuits_[level]) result.levels[level] = circuits_[level]->checkpoint(now);
  return result;
}
std::unique_ptr<LanCircuitPair> LanCircuitPair::restore_checkpoint(const LanPairCheckpoint &saved,
    LanCircuitProgram expected, LanCircuit::Clock::time_point now) noexcept {
  if (saved.version != 1U) return nullptr;
  for (std::size_t level{}; level < expected.levels.size(); ++level)
    if (saved.levels[level].has_value() != expected.levels[level].has_value() ||
        (saved.levels[level] && saved.levels[level]->configuration != *expected.levels[level])) return nullptr;
  try {
    auto result = std::make_unique<LanCircuitPair>(std::move(expected), 1U, now);
    for (std::size_t level{}; level < result->circuits_.size(); ++level) if (saved.levels[level]) {
      auto circuit = LanCircuit::restore_checkpoint(*saved.levels[level], result->circuits_[level]->configuration(), now);
      if (!circuit) return nullptr;
      *result->circuits_[level] = std::move(*circuit);
    }
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
