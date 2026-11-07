// Independent recovery and integrity-scan owners retain relative deadlines.
// Policy remains immutable, saturation never silently re-enables an entity,
// and a scan cursor names an identity rather than borrowing repository storage.

#include "router/isis_sequence_recovery.hpp"
#include "router/isis_database_validation.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
SequenceRecoveryCheckpoint SequenceRecovery::checkpoint(RuntimeClock::time_point now) const {
  SequenceRecoveryCheckpoint result{1U, cooldown_, resource_retry_, {}, disabled_, saturated_};
  if (disabled_ && !saturated_) {
    result.due_nanoseconds = checkpoint_time::offset(due_, now);
    if (!result.due_nanoseconds) throw std::invalid_argument("IS-IS recovery checkpoint clock range");
  }
  return result;
}
bool SequenceRecovery::restore(const SequenceRecoveryCheckpoint &saved, RuntimeClock::time_point now) noexcept {
  if (saved.version != 1U || saved.cooldown != cooldown_ || saved.resource_retry != resource_retry_ ||
      (saved.saturated && !saved.disabled) ||
      saved.due_nanoseconds.has_value() != (saved.disabled && !saved.saturated) ||
      (saved.due_nanoseconds && *saved.due_nanoseconds > std::max(cooldown_, resource_retry_).count())) return false;
  const auto due = saved.due_nanoseconds ? checkpoint_time::restore(*saved.due_nanoseconds, now) :
      std::optional{RuntimeClock::time_point{}};
  if (!due) return false;
  due_ = *due;
  disabled_ = saved.disabled;
  saturated_ = saved.saturated;
  return true;
}
DatabaseValidationCheckpoint DatabaseValidation::checkpoint(RuntimeClock::time_point now) const {
  const auto due = checkpoint_time::offset(due_, now);
  if (!due) throw std::invalid_argument("IS-IS validation checkpoint clock range");
  return {1U, interval_, random_, *due, cursor_, scanning_, corrupted_};
}
bool DatabaseValidation::restore(const DatabaseValidationCheckpoint &saved, RuntimeClock::time_point now) noexcept {
  if (saved.version != 1U || saved.interval != interval_ || !saved.random ||
      saved.due_nanoseconds > std::chrono::duration_cast<RuntimeClock::duration>(interval_).count() ||
      (saved.scanning && saved.due_nanoseconds > 0) || (!saved.scanning && saved.cursor) ||
      (saved.corrupted && (!saved.scanning || !saved.cursor))) return false;
  const auto due = checkpoint_time::restore(saved.due_nanoseconds, now);
  if (!due) return false;
  random_ = saved.random;
  due_ = *due;
  cursor_ = saved.cursor;
  scanning_ = saved.scanning;
  corrupted_ = saved.corrupted;
  return true;
}
} // namespace router::isis
