// Owner-local Hello scheduling. Periodic expiration and DIS role changes alone
// restart the periodic deadline. Egress receipts commit emission spacing while
// ordinary content changes retain the independently running periodic timer.

#include "router/isis_hello_schedule.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {

HelloSchedule::HelloSchedule(std::chrono::microseconds effective_interval,
    bool broadcast, bool designated, std::uint64_t random_state, Clock::time_point now)
    : interval_(effective_interval), random_(random_state), broadcast_(broadcast),
      designated_(designated) {
  if (interval_.count() <= 0 || !random_ || (designated && !broadcast))
    throw std::invalid_argument("Invalid IS-IS Hello schedule");
  restart(now);
}

void HelloSchedule::restart(Clock::time_point now) noexcept {
  const auto period = designated_ ? interval_ : *jittered_interval(interval_, random_);
  periodic_ = now + period;
}

bool HelloSchedule::role(std::chrono::microseconds effective_interval,
    bool designated, Clock::time_point now) noexcept {
  if (effective_interval.count() <= 0 || (designated && !broadcast_)) return false;
  if (interval_ != effective_interval || designated_ != designated) {
    interval_ = effective_interval;
    designated_ = designated;
    dirty_ = true;
    restart(now);
  }
  return true;
}

bool HelloSchedule::begin(Clock::time_point now) noexcept {
  if (now >= periodic_) {
    restart(now);
    dirty_ = true;
  }
  if (pending_ || !dirty_ ||
      (broadcast_ && sent_ && now < last_sent_ + std::chrono::seconds{1})) return false;
  dirty_ = false;
  pending_ = true;
  return true;
}

bool HelloSchedule::complete(bool enqueued, Clock::time_point now) noexcept {
  if (!pending_) return false;
  pending_ = false;
  if (enqueued) {
    last_sent_ = now;
    sent_ = true;
  }
  return true;
}

HelloSchedule::Clock::time_point HelloSchedule::deadline() const noexcept {
  // Pending output is awakened by its completion channel. Keep the periodic
  // timer visible so a delayed receipt does not stop periodic continuation.
  if (pending_ || !dirty_) return periodic_;
  if (!broadcast_ || !sent_) return Clock::time_point::min();
  return std::min(periodic_, last_sent_ + std::chrono::seconds{1});
}

} // namespace router::isis
