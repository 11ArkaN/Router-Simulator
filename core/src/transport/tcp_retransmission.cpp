// Integer-duration implementation of RFC 6298 sections 2 through 5. Exact
// duration arithmetic avoids floating-point drift across native and Wasm
// checkpoints while preserving alpha 1/8, beta 1/4 and exponential backoff.

#include "router/tcp_retransmission.hpp"

#include <algorithm>
#include <limits>

namespace router::transport::tcp {
namespace {

using Duration = RetransmissionEstimator::Duration;

[[nodiscard]] constexpr Duration initial_timeout() noexcept {
  return std::chrono::duration_cast<Duration>(device_catalog::tcp_rto_initial);
}
[[nodiscard]] constexpr Duration minimum_timeout() noexcept {
  return std::chrono::duration_cast<Duration>(device_catalog::tcp_rto_minimum);
}
[[nodiscard]] constexpr Duration maximum_timeout() noexcept {
  return std::chrono::duration_cast<Duration>(device_catalog::tcp_rto_maximum);
}
[[nodiscard]] constexpr Duration clock_granularity() noexcept {
  return std::chrono::duration_cast<Duration>(
      device_catalog::tcp_rto_clock_granularity);
}

} // namespace

RetransmissionEstimator::RetransmissionEstimator() noexcept
    : timeout_(initial_timeout()) {}

RetransmissionEstimator::Duration RetransmissionEstimator::bounded_timeout(
    Duration smoothed, Duration variation) noexcept {
  const auto maximum = maximum_timeout();
  if (smoothed >= maximum)
    return maximum;
  // RFC 6298 multiplies RTTVAR by K=4. Compare before multiplying so a hostile
  // restored or extreme host duration cannot overflow a signed duration rep.
  if (variation > (maximum - smoothed) / 4)
    return maximum;
  const auto variance_term = std::max(clock_granularity(), variation * 4);
  if (variance_term > maximum - smoothed)
    return maximum;
  return std::clamp(smoothed + variance_term, minimum_timeout(), maximum);
}

RttSampleResult RetransmissionEstimator::observe(
    Duration sample, bool segment_was_retransmitted,
    bool timestamp_removes_ambiguity) noexcept {
  if (sample <= Duration::zero())
    return RttSampleResult::invalid;
  if (segment_was_retransmitted && !timestamp_removes_ambiguity)
    return RttSampleResult::ignored_retransmission_ambiguity;

  if (!measurement_present_) {
    // RFC 6298 section 2.2 initializes SRTT=R and RTTVAR=R/2. Keeping both as
    // host durations retains sub-millisecond samples even though RTO is later
    // rounded to the profile's conservative one-second floor.
    smoothed_rtt_ = sample;
    rtt_variation_ = sample / 2;
    measurement_present_ = true;
  } else {
    // Section 2.3 explicitly updates RTTVAR using the old SRTT first. Written
    // as delta updates, the alpha and beta fractions cannot overflow through
    // an intermediate multiplication by seven or three.
    const auto difference = sample >= smoothed_rtt_
                                ? sample - smoothed_rtt_
                                : smoothed_rtt_ - sample;
    rtt_variation_ += (difference - rtt_variation_) / 4;
    smoothed_rtt_ += (sample - smoothed_rtt_) / 8;
  }
  timeout_ = bounded_timeout(smoothed_rtt_, rtt_variation_);
  return RttSampleResult::accepted;
}

RetransmissionEstimator::Duration
RetransmissionEstimator::on_timeout(bool waiting_for_syn) noexcept {
  const auto maximum = maximum_timeout();
  timeout_ = timeout_ >= maximum / 2 ? maximum : timeout_ * 2;
  syn_retransmitted_ = syn_retransmitted_ || waiting_for_syn;
  return timeout_;
}

void RetransmissionEstimator::on_handshake_complete() noexcept {
  if (syn_retransmitted_)
    timeout_ = std::max(
        timeout_, std::chrono::duration_cast<Duration>(
                      device_catalog::tcp_rto_after_syn_retransmission));
  syn_retransmitted_ = false;
}

RetransmissionCheckpoint RetransmissionEstimator::checkpoint() const noexcept {
  return {.smoothed_rtt_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  smoothed_rtt_).count(),
          .rtt_variation_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  rtt_variation_).count(),
          .timeout_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(timeout_)
                  .count(),
          .measurement_present = measurement_present_,
          .syn_retransmitted = syn_retransmitted_};
}

bool RetransmissionEstimator::validate_checkpoint(
    const RetransmissionCheckpoint &state) noexcept {
  const auto minimum_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(minimum_timeout())
          .count();
  const auto maximum_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(maximum_timeout())
          .count();
  if (state.timeout_nanoseconds < minimum_ns ||
      state.timeout_nanoseconds > maximum_ns ||
      state.smoothed_rtt_nanoseconds < 0 ||
      state.rtt_variation_nanoseconds < 0)
    return false;
  // An uninitialized estimator has no latent sample fields. Rejecting them
  // prevents a corrupt checkpoint from influencing the first accepted RTT.
  return state.measurement_present ||
         (state.smoothed_rtt_nanoseconds == 0 &&
          state.rtt_variation_nanoseconds == 0);
}

bool RetransmissionEstimator::restore(
    const RetransmissionCheckpoint &state) noexcept {
  if (!validate_checkpoint(state))
    return false;
  smoothed_rtt_ = std::chrono::duration_cast<Duration>(
      std::chrono::nanoseconds{state.smoothed_rtt_nanoseconds});
  rtt_variation_ = std::chrono::duration_cast<Duration>(
      std::chrono::nanoseconds{state.rtt_variation_nanoseconds});
  timeout_ = std::chrono::duration_cast<Duration>(
      std::chrono::nanoseconds{state.timeout_nanoseconds});
  measurement_present_ = state.measurement_present;
  syn_retransmitted_ = state.syn_retransmitted;
  return true;
}

} // namespace router::transport::tcp
