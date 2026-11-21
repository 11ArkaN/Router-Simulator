// ISO 10589 7.3.16.1 requires disabling the IS network entity before restarting
// at sequence one. A separate explicit resource retry keeps reconstruction
// failure from polling a past deadline or truncating the required cooldown.

#include "router/isis_sequence_recovery.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
SequenceRecovery::SequenceRecovery(std::array<std::optional<SequenceLevelLifetime>, 2U> levels,
    std::chrono::milliseconds resource_retry) {
  std::chrono::seconds longest{};
  for (const auto &level : levels) if (level) {
    if (!level->maximum_age || !level->zero_age_lifetime)
      throw std::invalid_argument("Invalid IS-IS sequence recovery lifetime");
    longest = std::max(longest, std::chrono::seconds{static_cast<std::uint32_t>(level->maximum_age) +
        level->zero_age_lifetime});
  }
  if (!longest.count() || resource_retry.count() <= 0 ||
      resource_retry > std::chrono::duration_cast<std::chrono::milliseconds>(RuntimeClock::duration::max()))
    throw std::invalid_argument("Invalid IS-IS sequence recovery program");
  cooldown_ = std::chrono::duration_cast<RuntimeClock::duration>(longest);
  resource_retry_ = std::chrono::duration_cast<RuntimeClock::duration>(resource_retry);
}
void SequenceRecovery::wait(RuntimeClock::time_point now, RuntimeClock::duration duration) noexcept {
  saturated_ = now > RuntimeClock::time_point::max() - duration;
  due_ = saturated_ ? RuntimeClock::time_point::max() : now + duration;
}
bool SequenceRecovery::begin(RuntimeClock::time_point now) noexcept {
  if (disabled_) return false;
  disabled_ = true;
  wait(now, cooldown_);
  return true;
}
bool SequenceRecovery::ready(RuntimeClock::time_point now) const noexcept {
  return disabled_ && !saturated_ && now >= due_;
}
bool SequenceRecovery::resource_failed(RuntimeClock::time_point now) noexcept {
  if (!ready(now)) return false;
  wait(now, resource_retry_);
  return true;
}
bool SequenceRecovery::recovered(RuntimeClock::time_point now) noexcept {
  if (!ready(now)) return false;
  disabled_ = false;
  return true;
}
std::optional<RuntimeClock::time_point> SequenceRecovery::deadline() const noexcept {
  return disabled_ && !saturated_ ? std::optional(due_) : std::nullopt;
}
} // namespace router::isis
