// RFC 5681 slow start, congestion avoidance, fast retransmit, fast recovery
// and timeout response. Saturating arithmetic prevents peer-controlled ACK or
// window values from wrapping a sender into a falsely permissive state.

#include "router/tcp_congestion.hpp"

#include <algorithm>
#include <limits>

namespace router::transport::tcp {
namespace {

[[nodiscard]] std::uint32_t saturating_add(std::uint32_t left,
                                           std::uint32_t right) noexcept {
  const auto maximum = std::numeric_limits<std::uint32_t>::max();
  return right > maximum - left ? maximum : left + right;
}

[[nodiscard]] std::uint32_t saturating_multiply(std::uint32_t value,
                                                std::uint32_t factor) noexcept {
  const auto maximum = std::numeric_limits<std::uint32_t>::max();
  return value != 0U && factor > maximum / value ? maximum : value * factor;
}

} // namespace

CongestionController::CongestionController(std::uint32_t sender_mss) noexcept
    : sender_mss_(std::max(sender_mss, 1U)),
      congestion_window_(initial_window(sender_mss_)),
      slow_start_threshold_(std::numeric_limits<std::uint32_t>::max()) {}

std::uint32_t
CongestionController::initial_window(std::uint32_t sender_mss) noexcept {
  if (sender_mss == 0U)
    return 0U;
  // RFC 5681 section 3.1 retains the standards-track RFC 3390 upper bound.
  // The optional experimental RFC 6928 IW10 policy is intentionally absent.
  if (sender_mss > 2190U)
    return saturating_multiply(sender_mss, 2U);
  if (sender_mss > 1095U)
    return saturating_multiply(sender_mss, 3U);
  return saturating_multiply(sender_mss, 4U);
}

std::uint32_t CongestionController::reduced_threshold(
    std::uint32_t flight_size) const noexcept {
  return std::max(flight_size / 2U, saturating_multiply(sender_mss_, 2U));
}

void CongestionController::on_new_ack(
    std::uint32_t newly_acknowledged) noexcept {
  duplicate_acknowledgments_ = 0U;
  recovery_inflation_limit_ = 0U;
  if (sack_recovery_)
    return;
  if (fast_recovery_) {
    // RFC 5681 step 6 deflates exactly to the threshold on the first ACK that
    // advances SND.UNA. Applying normal growth in the same ACK would retain
    // artificial duplicate-ACK inflation beyond recovery.
    congestion_window_ = slow_start_threshold_;
    fast_recovery_ = false;
    return;
  }
  if (newly_acknowledged == 0U)
    return;
  if (congestion_window_ < slow_start_threshold_) {
    congestion_window_ = saturating_add(
        congestion_window_, std::min(newly_acknowledged, sender_mss_));
    return;
  }

  // RFC 5681 equation 3 approximates one SMSS of growth per RTT. A minimum
  // one-byte increment is required when integer division would otherwise stop
  // a very large congestion window from increasing at all.
  const auto numerator = static_cast<std::uint64_t>(sender_mss_) * sender_mss_;
  const auto increment = std::max<std::uint32_t>(
      static_cast<std::uint32_t>(numerator / congestion_window_), 1U);
  congestion_window_ = saturating_add(congestion_window_, increment);
}

DuplicateAckAction CongestionController::on_duplicate_ack(
    std::uint32_t flight_size) noexcept {
  duplicate_acknowledgments_ = saturating_add(duplicate_acknowledgments_, 1U);
  if (duplicate_acknowledgments_ < 3U)
    return DuplicateAckAction::none;
  if (duplicate_acknowledgments_ == 3U) {
    slow_start_threshold_ = reduced_threshold(flight_size);
    congestion_window_ = saturating_add(
        slow_start_threshold_, saturating_multiply(sender_mss_, 3U));
    // RFC 5681 permits bounding artificial inflation to the approximate count
    // of outstanding segments to resist duplicate-ACK spoofing.
    recovery_inflation_limit_ =
        sender_mss_ == 0U ? 0U : flight_size / sender_mss_;
    fast_recovery_ = true;
    return DuplicateAckAction::retransmit_oldest;
  }
  if (fast_recovery_ &&
      duplicate_acknowledgments_ - 3U < recovery_inflation_limit_)
    congestion_window_ = saturating_add(congestion_window_, sender_mss_);
  return DuplicateAckAction::none;
}

void CongestionController::on_retransmission_timeout(
    std::uint32_t flight_size) noexcept {
  slow_start_threshold_ = reduced_threshold(flight_size);
  // RFC 5681 section 3.1 defines the loss window after an RTO as one SMSS.
  congestion_window_ = sender_mss_;
  duplicate_acknowledgments_ = 0U;
  recovery_inflation_limit_ = 0U;
  fast_recovery_ = false;
  sack_recovery_ = false;
}

void CongestionController::enter_sack_recovery(
    std::uint32_t flight_size) noexcept {
  // RFC 6675 step 4.2 uses half of actual FlightSize for both variables. It
  // does not apply RFC 5681's three-SMSS duplicate-ACK inflation because Pipe
  // controls every subsequent transmission during SACK recovery.
  slow_start_threshold_ = reduced_threshold(flight_size);
  congestion_window_ = slow_start_threshold_;
  duplicate_acknowledgments_ = 0U;
  recovery_inflation_limit_ = 0U;
  fast_recovery_ = true;
  sack_recovery_ = true;
}

void CongestionController::on_sack_ack(bool recovery_complete) noexcept {
  duplicate_acknowledgments_ = 0U;
  recovery_inflation_limit_ = 0U;
  if (!sack_recovery_ || !recovery_complete)
    return;
  // The ACK covering RecoveryPoint ends recovery at ssthresh. Normal slow
  // start or congestion-avoidance growth resumes on a later advancing ACK.
  congestion_window_ = slow_start_threshold_;
  fast_recovery_ = false;
  sack_recovery_ = false;
}

void CongestionController::reduce_sender_mss(
    std::uint32_t sender_mss) noexcept {
  if (sender_mss == 0U || sender_mss >= sender_mss_)
    return;
  // Use 64-bit multiplication because a valid byte-counted cwnd can approach
  // UINT32_MAX. The one-segment floor keeps forward progress after a drastic
  // MTU reduction while still preventing a burst of newly smaller segments.
  const auto scaled = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(congestion_window_) * sender_mss) /
      sender_mss_);
  congestion_window_ = std::max(sender_mss, scaled);
  recovery_inflation_limit_ = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(recovery_inflation_limit_) * sender_mss) /
      sender_mss_);
  sender_mss_ = sender_mss;
}

std::uint32_t CongestionController::send_allowance(
    std::uint32_t receiver_window, std::uint32_t flight_size) const noexcept {
  const auto usable_window = std::min(congestion_window_, receiver_window);
  return flight_size >= usable_window ? 0U : usable_window - flight_size;
}

CongestionCheckpoint CongestionController::checkpoint() const noexcept {
  return {.sender_mss = sender_mss_,
          .congestion_window = congestion_window_,
          .slow_start_threshold = slow_start_threshold_,
          .duplicate_acknowledgments = duplicate_acknowledgments_,
          .recovery_inflation_limit = recovery_inflation_limit_,
          .fast_recovery = fast_recovery_,
          .sack_recovery = sack_recovery_};
}

bool CongestionController::validate_checkpoint(
    const CongestionCheckpoint &state) noexcept {
  if (state.sender_mss == 0U || state.congestion_window == 0U ||
      state.slow_start_threshold == 0U)
    return false;
  if (!state.fast_recovery &&
      (state.duplicate_acknowledgments >= 3U ||
       state.recovery_inflation_limit != 0U))
    return false;
  if (state.sack_recovery &&
      (!state.fast_recovery || state.recovery_inflation_limit != 0U))
    return false;
  return !state.fast_recovery || state.sack_recovery ||
         state.duplicate_acknowledgments >= 3U;
}

bool CongestionController::restore(const CongestionCheckpoint &state) noexcept {
  if (!validate_checkpoint(state))
    return false;
  sender_mss_ = state.sender_mss;
  congestion_window_ = state.congestion_window;
  slow_start_threshold_ = state.slow_start_threshold;
  duplicate_acknowledgments_ = state.duplicate_acknowledgments;
  recovery_inflation_limit_ = state.recovery_inflation_limit;
  fast_recovery_ = state.fast_recovery;
  sack_recovery_ = state.sack_recovery;
  return true;
}

} // namespace router::transport::tcp
