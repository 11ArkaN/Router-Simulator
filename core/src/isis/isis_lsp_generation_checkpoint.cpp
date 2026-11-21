// The local generation owner preserves counters, jitter and reservations.
// Transfers contain relative deadlines only; restoration is allocation-free
// and cannot change the construction policy or partially publish state.

#include "router/isis_lsp_generation.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace router::isis {
LspGenerationCheckpoint LspGenerationSchedule::checkpoint(RuntimeClock::time_point now) const {
  const auto refresh = checkpoint_time::offset(refresh_at_, now);
  const auto changed = checkpoint_time::offset(changed_at_, now);
  const auto hold = checkpoint_time::offset(hold_until_, now);
  if (!refresh || !changed || !hold) throw std::invalid_argument("IS-IS generation checkpoint clock range");
  return {1U, minimum_, refresh_, random_, tickets_, committed_, observed_, *refresh, *changed, *hold,
      pending_, dirty_, changed_during_pending_, blocked_, stopped_};
}
bool LspGenerationSchedule::restore(const LspGenerationCheckpoint &saved, RuntimeClock::time_point now) noexcept {
  if (saved.version != 1U || saved.minimum != minimum_ || saved.refresh != refresh_ || !saved.random ||
      saved.changed_nanoseconds > 0 ||
      saved.refresh_nanoseconds > std::chrono::duration_cast<RuntimeClock::duration>(refresh_).count() ||
      saved.hold_nanoseconds > std::chrono::duration_cast<RuntimeClock::duration>(minimum_).count() ||
      (saved.changed_during_pending && (!saved.pending || !saved.dirty)) ||
      (saved.pending && (saved.blocked || saved.stopped || saved.pending->status != GenerationStatus::ready ||
          !saved.pending->sequence || saved.pending->sequence <= saved.committed || !saved.pending->ticket ||
          saved.pending->ticket != saved.tickets)) ||
      (saved.stopped && std::max(saved.committed, saved.observed) != std::numeric_limits<std::uint32_t>::max() &&
          saved.tickets != std::numeric_limits<std::uint64_t>::max())) return false;
  const auto refresh = checkpoint_time::restore(saved.refresh_nanoseconds, now);
  const auto changed = checkpoint_time::restore(saved.changed_nanoseconds, now);
  const auto hold = checkpoint_time::restore(saved.hold_nanoseconds, now);
  if (!refresh || !changed || !hold) return false;
  random_ = saved.random;
  tickets_ = saved.tickets;
  committed_ = saved.committed;
  observed_ = saved.observed;
  refresh_at_ = *refresh;
  changed_at_ = *changed;
  hold_until_ = *hold;
  pending_ = saved.pending;
  dirty_ = saved.dirty;
  changed_during_pending_ = saved.changed_during_pending;
  blocked_ = saved.blocked;
  stopped_ = saved.stopped;
  return true;
}
} // namespace router::isis
