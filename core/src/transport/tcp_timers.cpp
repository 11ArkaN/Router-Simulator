// RFC 1122 local timer mechanics. A deadline changes only when its associated
// transport condition changes or an emitted probe/ACK is actually admitted.

#include "router/tcp_timers.hpp"

#include <algorithm>

namespace router::transport::tcp {

AckSchedule DelayedAcknowledger::on_segment(
    bool in_order, std::uint32_t data_octets, bool fin,
    Clock::time_point now) noexcept {
  if (!in_order || fin) {
    // Duplicate, gap-filling, out-of-order and FIN processing must promptly
    // communicate current RCV.NXT. Any old delayed deadline is superseded.
    deadline_ = now;
    data_segments_since_ack_ = 0U;
    return AckSchedule::immediate;
  }
  if (data_octets == 0U)
    return AckSchedule::none;
  if (data_segments_since_ack_ != 0U) {
    // ACK every second data segment. This is at least as strong as RFC 1122's
    // requirement for every second full-sized segment and handles tiny flows
    // without relying on a guessed peer MSS at the receiver.
    deadline_ = now;
    data_segments_since_ack_ = 0U;
    return AckSchedule::immediate;
  }
  data_segments_since_ack_ = 1U;
  deadline_ = now + device_catalog::tcp_delayed_ack;
  return AckSchedule::delayed;
}

void DelayedAcknowledger::request_immediate(Clock::time_point now) noexcept {
  deadline_ = now;
  data_segments_since_ack_ = 0U;
}

bool DelayedAcknowledger::due(Clock::time_point now) const noexcept {
  return deadline_ && now >= *deadline_;
}

void DelayedAcknowledger::acknowledge_committed() noexcept {
  deadline_.reset();
  data_segments_since_ack_ = 0U;
}

DelayedAckCheckpoint
DelayedAcknowledger::checkpoint(Clock::time_point now) const noexcept {
  const auto remaining = deadline_ && *deadline_ > now
                             ? *deadline_ - now
                             : Clock::duration::zero();
  return {.remaining_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                  .count(),
          .data_segments_since_ack = data_segments_since_ack_,
          .deadline_present = deadline_.has_value()};
}

bool DelayedAcknowledger::restore(const DelayedAckCheckpoint &state,
                                  Clock::time_point now) noexcept {
  if (state.remaining_nanoseconds < 0 ||
      state.data_segments_since_ack > 1U ||
      (!state.deadline_present && state.data_segments_since_ack != 0U) ||
      (!state.deadline_present && state.remaining_nanoseconds != 0))
    return false;
  deadline_ = state.deadline_present
                  ? std::optional{now + std::chrono::nanoseconds{
                                            state.remaining_nanoseconds}}
                  : std::nullopt;
  data_segments_since_ack_ = state.data_segments_since_ack;
  return true;
}

void PersistTimer::update(bool zero_window, bool queued_data,
                          Duration current_rto,
                          Clock::time_point now) noexcept {
  if (!zero_window || !queued_data) {
    deadline_.reset();
    interval_ = Duration::zero();
    return;
  }
  if (deadline_)
    return;
  // The first probe waits one current RTO. Bound malformed or unexpectedly
  // large caller values at the explicit persist ceiling from the profile.
  interval_ = std::clamp(current_rto, Duration{1},
                         Duration{device_catalog::tcp_persist_maximum});
  deadline_ = now + interval_;
}

bool PersistTimer::due(Clock::time_point now) const noexcept {
  return deadline_ && now >= *deadline_;
}

bool PersistTimer::probe_committed(Clock::time_point now) noexcept {
  if (!deadline_ || now < *deadline_)
    return false;
  const auto maximum = Duration{device_catalog::tcp_persist_maximum};
  interval_ = interval_ > maximum - interval_ ? maximum : interval_ * 2;
  deadline_ = now + interval_;
  return true;
}

PersistCheckpoint PersistTimer::checkpoint(Clock::time_point now) const noexcept {
  const auto remaining = deadline_ && *deadline_ > now
                             ? *deadline_ - now
                             : Clock::duration::zero();
  return {.remaining_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                  .count(),
          .interval_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(interval_)
                  .count(),
          .active = deadline_.has_value()};
}

bool PersistTimer::restore(const PersistCheckpoint &state,
                           Clock::time_point now) noexcept {
  const auto maximum = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           device_catalog::tcp_persist_maximum)
                           .count();
  if (state.remaining_nanoseconds < 0 || state.interval_nanoseconds < 0 ||
      state.interval_nanoseconds > maximum ||
      (state.active != (state.interval_nanoseconds > 0)) ||
      (!state.active && state.remaining_nanoseconds != 0))
    return false;
  interval_ = std::chrono::nanoseconds{state.interval_nanoseconds};
  deadline_ = state.active
                  ? std::optional{now + std::chrono::nanoseconds{
                                            state.remaining_nanoseconds}}
                  : std::nullopt;
  return true;
}

} // namespace router::transport::tcp
