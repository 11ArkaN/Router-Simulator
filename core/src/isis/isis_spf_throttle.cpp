// The level control owner coalesces SPF changes and advances exponential holds.
// Checked local deadlines and detached images depend only on monotonic values.
#include "router/isis_spf_throttle.hpp"
#include "router/generated_isis_configuration_profile.hpp"
#include <algorithm>
#include <stdexcept>
namespace router::isis {
bool valid_spf_delay_policy(SpfDelayPolicy policy) noexcept {
  const auto duration = [](auto value, auto maximum) {
    return value.count() >= 0 && value <= maximum && value.count() % 100 == 0;
  };
  return duration(policy.maximum, std::chrono::milliseconds{configuration_profile::spf_max_wait_milliseconds_maximum}) &&
      duration(policy.initial, std::chrono::milliseconds{configuration_profile::spf_initial_wait_milliseconds_maximum}) &&
      duration(policy.second, std::chrono::milliseconds{configuration_profile::spf_second_wait_milliseconds_maximum});
}
namespace {
auto after(SpfThrottle::Clock::time_point now, std::chrono::milliseconds duration) noexcept {
  return checkpoint_time::restore(std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count(), now);
}
}
SpfThrottle::SpfThrottle(SpfDelayPolicy policy)
    : policy_(policy), hold_(std::min(policy.second, policy.maximum)) {
  if (!valid_spf_delay_policy(policy)) throw std::invalid_argument("Invalid effective IS-IS SPF delays");
}
bool SpfThrottle::changed(Clock::time_point now) noexcept {
  if (last_ && now < *last_) return false;
  if (pending_) return true;
  auto retained = last_;
  if (retained) {
    const auto quiet = after(*retained, hold_);
    if (!quiet) return false;
    if (now >= *quiet) retained.reset();
  }
  const auto due = retained ? after(*retained, hold_) : after(now, policy_.initial);
  if (!due) return false;
  last_ = retained;
  if (!retained) hold_ = std::min(policy_.second, policy_.maximum);
  pending_ = *due;
  return true;
}
bool SpfThrottle::complete(Clock::time_point now) noexcept {
  if (!due(now)) return false;
  const auto next = last_ ? std::min(hold_ * 2, policy_.maximum) : std::min(policy_.second, policy_.maximum);
  if (!after(now, next)) return false;
  hold_ = next; last_ = now; pending_.reset();
  return true;
}
SpfThrottleCheckpoint SpfThrottle::checkpoint(Clock::time_point now) const {
  SpfThrottleCheckpoint saved{1U, policy_, hold_, {}, {}};
  const auto capture = [&](const auto &point, auto &target) {
    if (!point) return;
    target = checkpoint_time::offset(*point, now);
    if (!target) throw std::invalid_argument("IS-IS SPF checkpoint epoch overflow");
  };
  if (last_ && now < *last_) throw std::invalid_argument("IS-IS SPF checkpoint precedes calculation");
  capture(last_, saved.last_run_nanoseconds); capture(pending_, saved.pending_nanoseconds);
  if (!last_ && saved.pending_nanoseconds && *saved.pending_nanoseconds >
      std::chrono::duration_cast<std::chrono::nanoseconds>(policy_.initial).count())
    throw std::invalid_argument("IS-IS SPF checkpoint precedes notification");
  return saved;
}
bool SpfThrottle::restore(const SpfThrottleCheckpoint &saved, Clock::time_point now) noexcept {
  if (saved.version != 1U || saved.policy != policy_ || saved.next_hold.count() < 0 ||
      saved.next_hold > policy_.maximum || (saved.last_run_nanoseconds && *saved.last_run_nanoseconds > 0)) return false;
  auto reachable = std::min(policy_.second, policy_.maximum);
  while (reachable.count() && reachable < saved.next_hold && reachable < policy_.maximum)
    reachable = std::min(reachable * 2, policy_.maximum);
  if (reachable != saved.next_hold || (!saved.last_run_nanoseconds &&
      saved.next_hold != std::min(policy_.second, policy_.maximum))) return false;
  std::optional<Clock::time_point> last, pending;
  if (saved.last_run_nanoseconds) {
    last = checkpoint_time::restore(*saved.last_run_nanoseconds, now);
    if (!last || !after(*last, saved.next_hold)) return false;
  }
  if (saved.pending_nanoseconds) {
    pending = checkpoint_time::restore(*saved.pending_nanoseconds, now);
    if (!pending || (last && pending != after(*last, saved.next_hold)) ||
        (!last && *saved.pending_nanoseconds > std::chrono::duration_cast<std::chrono::nanoseconds>(policy_.initial).count())) return false;
  }
  hold_ = saved.next_hold; last_ = last; pending_ = pending;
  return true;
}
}
