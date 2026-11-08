// One instance level owns its SPF burst and pending calculation deadline.
// Inputs are local change notifications and monotonic points; no clock, peer,
// event queue or routing state is shared or advanced by this module.
#pragma once
#include "router/isis_checkpoint_time.hpp"
namespace router::isis {
struct SpfDelayPolicy {
  std::chrono::milliseconds maximum{}, initial{}, second{};
  bool operator==(const SpfDelayPolicy &) const = default;
};
// Effective policy validation is allocation-free and changes no owner.
[[nodiscard]] bool valid_spf_delay_policy(SpfDelayPolicy) noexcept;
struct SpfThrottleCheckpoint {
  std::uint32_t version{1U};
  SpfDelayPolicy policy;
  std::chrono::milliseconds next_hold{};
  std::optional<std::int64_t> last_run_nanoseconds, pending_nanoseconds;
};
class SpfThrottle final {
public:
  using Clock = checkpoint_time::Clock;
  // Effective SPF durations are nonnegative multiples of 100 ms within the
  // pinned leaf maxima. Initial and second remain independent of the cap.
  // Invalid policy throws invalid_argument. Construction allocates nothing.
  explicit SpfThrottle(SpfDelayPolicy policy);
  // Same level owner, nondecreasing time. Repeated changes coalesce without
  // moving a pending deadline. A complete quiet hold resets the next burst.
  // Overflow or a point before the last calculation refuses without mutation.
  // No allocation.
  [[nodiscard]] bool changed(Clock::time_point now) noexcept;
  // Called after the complete level calculation quantum, never for a partial
  // family result. The second hold then doubles to the maximum. An early call
  // or unrepresentable quiet boundary refuses without consuming pending work.
  [[nodiscard]] bool complete(Clock::time_point now) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> deadline() const noexcept { return pending_; }
  [[nodiscard]] bool due(Clock::time_point now) const noexcept { return pending_ && *pending_ <= now; }
  // Quiescent same-owner transfer. Relative nanoseconds freeze remaining wait
  // while absent. Capture throws on an invalid epoch; restore validates policy,
  // reachable exponential stage and timestamp relationships before mutation.
  [[nodiscard]] SpfThrottleCheckpoint checkpoint(Clock::time_point now) const;
  [[nodiscard]] bool restore(const SpfThrottleCheckpoint &, Clock::time_point now) noexcept;
private:
  SpfDelayPolicy policy_;
  std::chrono::milliseconds hold_;
  std::optional<Clock::time_point> last_, pending_;
};
}
