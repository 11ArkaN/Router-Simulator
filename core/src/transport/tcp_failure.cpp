// Connection-failure threshold implementation. It deliberately separates
// reporting from state mutation in IP and the application, preserving the
// endpoint shard as the only owner of those external states.

#include "router/tcp_failure.hpp"

#include "router/tcp_sequence.hpp"

#include <limits>

namespace router::transport::tcp {

bool FailureDetector::set_data_r2(
    std::optional<Duration> timeout) noexcept {
  // Zero and negative values would make an already admitted segment fail at
  // its transmission instant. Applications that want immediate cancellation
  // use CLOSE or ABORT rather than manufacturing a nonconforming R2 value.
  if (timeout && *timeout <= Duration::zero())
    return false;
  data_r2_ = timeout;
  return true;
}

bool FailureDetector::begin(std::uint32_t first, std::uint32_t end, bool syn,
                            Clock::time_point now) noexcept {
  const auto length = end - first;
  if (length == 0U || length > 0x40000000U)
    return false;
  // Replacing the tracked interval is valid only when the sender has moved to
  // another oldest-unacknowledged segment. Its R1 count and age begin anew.
  segment_first_ = first;
  segment_end_ = end;
  retransmissions_ = 0U;
  first_transmitted_at_ = now;
  active_ = true;
  syn_ = syn;
  negative_advice_reported_ = false;
  return true;
}

std::optional<FailureDetector::Duration>
FailureDetector::active_r2() const noexcept {
  if (!active_)
    return std::nullopt;
  // SYN uses the standards-mandated minimum independently of an application's
  // data timeout. An application may still explicitly abort an OPEN sooner.
  return syn_ ? std::optional<Duration>{device_catalog::tcp_failure_syn_r2}
              : data_r2_;
}

FailureAction FailureDetector::retransmitted(
    std::uint32_t first, std::uint32_t end,
    Clock::time_point now) noexcept {
  if (!active_ || first != segment_first_ || end != segment_end_ ||
      now < first_transmitted_at_)
    return FailureAction::none;
  if (retransmissions_ != std::numeric_limits<std::uint32_t>::max())
    ++retransmissions_;

  // R2 is checked first because an endpoint must close once its failure limit
  // is reached, rather than issuing advice for a connection it will discard.
  if (const auto r2 = active_r2();
      r2 && now - first_transmitted_at_ >= *r2)
    return FailureAction::abort_connection;
  if (!negative_advice_reported_ &&
      retransmissions_ >= device_catalog::tcp_failure_r1_retransmissions) {
    negative_advice_reported_ = true;
    return FailureAction::negative_ip_advice;
  }
  return FailureAction::none;
}

void FailureDetector::acknowledge(std::uint32_t acknowledgment) noexcept {
  if (!active_)
    return;
  if (sequence::before_or_equal(segment_end_, acknowledgment)) {
    reset();
    return;
  }
  // A partial cumulative ACK leaves the same original segment outstanding.
  // Move its first unacknowledged byte without resetting R1 or extending R2.
  if (sequence::after(acknowledgment, segment_first_))
    segment_first_ = acknowledgment;
}

FailureAction FailureDetector::service(Clock::time_point now) const noexcept {
  if (const auto r2 = active_r2();
      r2 && now >= first_transmitted_at_ &&
      now - first_transmitted_at_ >= *r2)
    return FailureAction::abort_connection;
  return FailureAction::none;
}

std::optional<FailureDetector::Clock::time_point>
FailureDetector::deadline() const noexcept {
  const auto r2 = active_r2();
  return r2 ? std::optional{first_transmitted_at_ + *r2} : std::nullopt;
}

void FailureDetector::reset() noexcept {
  // Keep the application-selected data R2 across successive segments in the
  // same connection. Only per-segment retransmission evidence is discarded.
  first_transmitted_at_ = {};
  segment_first_ = 0U;
  segment_end_ = 0U;
  retransmissions_ = 0U;
  active_ = false;
  syn_ = false;
  negative_advice_reported_ = false;
}

FailureCheckpoint
FailureDetector::checkpoint(Clock::time_point now) const noexcept {
  const auto age = active_ && now > first_transmitted_at_
                       ? now - first_transmitted_at_
                       : Duration::zero();
  const auto data_r2 = data_r2_.value_or(Duration::zero());
  return {
      .segment_first = segment_first_,
      .segment_end = segment_end_,
      .retransmissions = retransmissions_,
      .segment_age_nanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(age).count(),
      .data_r2_nanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(data_r2).count(),
      .active = active_,
      .syn = syn_,
      .negative_advice_reported = negative_advice_reported_,
      .data_r2_infinite = !data_r2_.has_value()};
}

bool FailureDetector::validate_checkpoint(
    const FailureCheckpoint &state) noexcept {
  if (state.segment_age_nanoseconds < 0 || state.data_r2_nanoseconds < 0 ||
      (state.data_r2_infinite && state.data_r2_nanoseconds != 0) ||
      (!state.data_r2_infinite && state.data_r2_nanoseconds == 0))
    return false;
  if (!state.active)
    return state.segment_first == 0U && state.segment_end == 0U &&
           state.retransmissions == 0U &&
           state.segment_age_nanoseconds == 0 && !state.syn &&
           !state.negative_advice_reported;
  const auto length = state.segment_end - state.segment_first;
  if (length == 0U || length > 0x40000000U)
    return false;
  // Advice cannot precede the generated R1 threshold. The converse need not
  // hold because a checkpoint may be taken after the threshold transmission
  // was admitted but before the owner consumes the returned action.
  return !state.negative_advice_reported ||
         state.retransmissions >=
             device_catalog::tcp_failure_r1_retransmissions;
}

bool FailureDetector::restore(const FailureCheckpoint &state,
                              Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  const auto age = std::chrono::nanoseconds{state.segment_age_nanoseconds};
  if (age > now.time_since_epoch())
    return false;

  // Validation completes before mutation so a rejected checkpoint cannot
  // partly replace the live connection's application policy or evidence.
  data_r2_ = state.data_r2_infinite
                 ? std::nullopt
                 : std::optional<Duration>{
                       std::chrono::nanoseconds{state.data_r2_nanoseconds}};
  segment_first_ = state.segment_first;
  segment_end_ = state.segment_end;
  retransmissions_ = state.retransmissions;
  first_transmitted_at_ = now - age;
  active_ = state.active;
  syn_ = state.syn;
  negative_advice_reported_ = state.negative_advice_reported;
  return true;
}

} // namespace router::transport::tcp
