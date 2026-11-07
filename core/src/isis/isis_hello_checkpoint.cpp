// One circuit's Hello owner freezes periodic and emission-spacing state.
// Pending dirty changes and the exact random stream survive host-epoch shifts.
// Transfer validation owns no transport and cannot acknowledge a frame.

#include "router/isis_hello_schedule.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <stdexcept>

namespace router::isis {
HelloScheduleCheckpoint HelloSchedule::checkpoint(Clock::time_point now) const {
  const auto periodic = checkpoint_time::offset(periodic_, now);
  const auto sent = sent_ ? checkpoint_time::offset(last_sent_, now) : std::optional<std::int64_t>{0};
  if (!periodic || !sent) throw std::invalid_argument("IS-IS Hello checkpoint clock range");
  return {1U, interval_, *periodic, *sent, random_, broadcast_, designated_, sent_, dirty_, pending_};
}
bool HelloSchedule::restore(const HelloScheduleCheckpoint &saved, Clock::time_point now) noexcept {
  if (saved.version != 1U || saved.interval != interval_ || saved.broadcast != broadcast_ ||
      saved.designated != designated_ || !saved.random || saved.last_sent_nanoseconds > 0 ||
      (!saved.sent && saved.last_sent_nanoseconds != 0) ||
      saved.periodic_nanoseconds > std::chrono::duration_cast<Clock::duration>(interval_).count()) return false;
  const auto periodic = checkpoint_time::restore(saved.periodic_nanoseconds, now);
  const auto sent = saved.sent ? checkpoint_time::restore(saved.last_sent_nanoseconds, now) : std::optional{Clock::time_point{}};
  if (!periodic || !sent) return false;
  periodic_ = *periodic;
  last_sent_ = *sent;
  random_ = saved.random;
  sent_ = saved.sent;
  dirty_ = saved.dirty;
  pending_ = saved.pending;
  return true;
}
} // namespace router::isis
