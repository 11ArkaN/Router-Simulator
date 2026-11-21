// The interface scan owner retains its jitter and actual-success backlog gate.
// Relative timers freeze while absent. No LSDB candidate or packet is borrowed;
// matching output reservation validation belongs to the enclosing interface.

#include "router/isis_broadcast_scan.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <stdexcept>

namespace router::isis {
BroadcastScanCheckpoint BroadcastScan::checkpoint(Clock::time_point now) const {
  const auto periodic = checkpoint_time::offset(periodic_, now);
  const auto sent = last_sent_ ? checkpoint_time::offset(*last_sent_, now) : std::optional<std::int64_t>{};
  if (!periodic || (last_sent_ && !sent)) throw std::invalid_argument("IS-IS broadcast checkpoint clock range");
  return {1U, interval_, *periodic, sent, random_, pending_};
}
bool BroadcastScan::restore(const BroadcastScanCheckpoint &saved, Clock::time_point now) noexcept {
  if (saved.version != 1U || saved.interval != interval_ || !saved.random ||
      saved.periodic_nanoseconds > std::chrono::duration_cast<Clock::duration>(interval_).count() ||
      (saved.last_sent_nanoseconds && *saved.last_sent_nanoseconds > 0)) return false;
  const auto periodic = checkpoint_time::restore(saved.periodic_nanoseconds, now);
  const auto sent = saved.last_sent_nanoseconds ? checkpoint_time::restore(*saved.last_sent_nanoseconds, now) :
      std::optional{Clock::time_point{}};
  if (!periodic || !sent) return false;
  periodic_ = *periodic;
  last_sent_ = saved.last_sent_nanoseconds ? sent : std::nullopt;
  random_ = saved.random;
  pending_ = saved.pending;
  return true;
}
} // namespace router::isis
