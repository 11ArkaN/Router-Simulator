// Local semantic ownership is restored independently of received LSDB bytes.
// Reserved withdrawn identities retain sequence floors and retirement work.
// Only a fully checked candidate escapes; no live update owner is mutated.

#include "router/isis_local_lsp_set.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>

namespace router::isis {
LocalLspSetCheckpoint LocalLspSet::checkpoint(RuntimeClock::time_point now) const {
  LocalLspSetCheckpoint result;
  result.local = local_;
  result.maximum_areas = maximum_areas_;
  result.selector = selector_;
  result.levels = levels_;
  result.waiting_overload = waiting_overload_;
  result.first = first_;
  result.terminal = terminal_;
  result.entries.reserve(entries_.size());
  for (const auto &entry : entries_)
    result.entries.push_back({entry.content, entry.generation.checkpoint(now), entry.last_error,
        entry.retirement_pending, entry.retirement_blocked});
  return result;
}
std::unique_ptr<LocalLspSet> LocalLspSet::restore_checkpoint(const LocalLspSetCheckpoint &saved,
    packet::isis::SystemId local, std::uint8_t maximum_areas, UpdateInstanceSelector selector,
    LocalLspProgram expected, RuntimeClock::time_point now) noexcept {
  if (saved.version != 1U || saved.local != local || saved.maximum_areas != maximum_areas ||
      saved.selector != selector || saved.levels != expected.levels || saved.entries.empty() ||
      saved.entries.size() != expected.records.size() || saved.first >= saved.entries.size() ||
      (saved.terminal != GenerationStatus::waiting && saved.terminal != GenerationStatus::sequence_exhausted &&
          saved.terminal != GenerationStatus::ticket_exhausted)) return nullptr;
  for (std::size_t level{}; level < saved.levels.size(); ++level)
    if (!saved.levels[level] && saved.waiting_overload[level]) return nullptr;
  try {
    std::sort(expected.records.begin(), expected.records.end(), [](const auto &a, const auto &b) {
      return a.level != b.level ? a.level < b.level : a.id < b.id;
    });
    bool stopped{};
    for (std::size_t index{}; index < saved.entries.size(); ++index) {
      const auto &entry = saved.entries[index];
      if (entry.content.level != expected.records[index].level || entry.content.id != expected.records[index].id ||
          static_cast<unsigned>(entry.last_error) > static_cast<unsigned>(UpdateStatus::adjacency) ||
          (entry.content.active && (entry.retirement_pending || entry.retirement_blocked)) ||
          (entry.retirement_blocked && !entry.retirement_pending)) return nullptr;
      stopped = stopped || entry.generation.stopped;
      expected.records[index] = entry.content;
    }
    if (stopped != (saved.terminal != GenerationStatus::waiting)) return nullptr;
    // Initial entropy is irrelevant after replacing every generation state.
    // A valid seed permits normal construction and semantic TLV validation.
    expected.random = 1U;
    auto result = std::make_unique<LocalLspSet>(local, maximum_areas, selector, std::move(expected), now);
    for (std::size_t index{}; index < saved.entries.size(); ++index) {
      auto &entry = result->entries_[index];
      const auto &state = saved.entries[index];
      if (!entry.generation.restore(state.generation, now)) return nullptr;
      entry.last_error = state.last_error;
      entry.retirement_pending = state.retirement_pending;
      entry.retirement_blocked = state.retirement_blocked;
    }
    result->waiting_overload_ = saved.waiting_overload;
    result->first_ = saved.first;
    result->terminal_ = saved.terminal;
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
