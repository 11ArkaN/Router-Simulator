// Congestion tests cover standards-track RFC 5681 byte accounting, loss
// response and recovery transitions. Values are exact so a later optimization
// cannot silently replace FlightSize with the receiver or congestion window.

#include "router/tcp_congestion.hpp"

#include <limits>
#include <stdexcept>

void tcp_congestion_tests() {
  using router::transport::tcp::CongestionController;
  using router::transport::tcp::DuplicateAckAction;

  if (CongestionController::initial_window(0U) != 0U ||
      CongestionController::initial_window(536U) != 2144U ||
      CongestionController::initial_window(1460U) != 4380U ||
      CongestionController::initial_window(3000U) != 6000U)
    throw std::runtime_error("TCP initial window left RFC 5681 bounds");

  CongestionController controller{1460U};
  if (controller.congestion_window() != 4380U ||
      controller.slow_start_threshold() !=
          std::numeric_limits<std::uint32_t>::max())
    throw std::runtime_error("TCP congestion state did not initialize safely");

  // One ACK covering many segments increases slow start by at most one SMSS,
  // preventing ACK division or coalescing from bypassing byte accounting.
  controller.on_new_ack(10'000U);
  if (controller.congestion_window() != 5840U)
    throw std::runtime_error("TCP slow start exceeded one SMSS per new ACK");
  if (controller.send_allowance(4000U, 3500U) != 500U ||
      controller.send_allowance(4000U, 4000U) != 0U)
    throw std::runtime_error("TCP sender ignored the advertised receive window");

  // A timeout with 10,000 bytes in flight sets ssthresh to 5,000, then resets
  // cwnd to the one-SMSS loss window. Subsequent ACKs re-enter slow start.
  controller.on_retransmission_timeout(10'000U);
  if (controller.slow_start_threshold() != 5000U ||
      controller.congestion_window() != 1460U)
    throw std::runtime_error("TCP timeout used cwnd instead of FlightSize");
  controller.on_new_ack(1460U);
  if (controller.congestion_window() != 2920U)
    throw std::runtime_error("TCP did not restart slow start after timeout");

  // Three duplicate ACKs trigger one retransmission and inflate from the new
  // threshold. Later duplicates add at most one SMSS each within the bounded
  // number of outstanding segments. A new ACK deflates to ssthresh exactly.
  if (controller.on_duplicate_ack(8760U) != DuplicateAckAction::none ||
      controller.on_duplicate_ack(8760U) != DuplicateAckAction::none ||
      controller.on_duplicate_ack(8760U) !=
          DuplicateAckAction::retransmit_oldest ||
      controller.slow_start_threshold() != 4380U ||
      controller.congestion_window() != 8760U ||
      !controller.in_fast_recovery())
    throw std::runtime_error("TCP fast retransmit did not begin on duplicate ACK 3");
  static_cast<void>(controller.on_duplicate_ack(8760U));
  if (controller.congestion_window() != 10'220U)
    throw std::runtime_error("TCP fast recovery did not inflate by one SMSS");
  controller.on_new_ack(1460U);
  if (controller.in_fast_recovery() || controller.congestion_window() != 4380U)
    throw std::runtime_error("TCP fast recovery did not deflate on a new ACK");

  // RFC 6675 uses Pipe rather than duplicate-ACK inflation. Partial cumulative
  // ACKs retain recovery and the ACK covering RecoveryPoint ends at ssthresh.
  controller.enter_sack_recovery(12'000U);
  if (!controller.in_fast_recovery() ||
      controller.congestion_window() != 6000U ||
      controller.slow_start_threshold() != 6000U)
    throw std::runtime_error("TCP SACK recovery applied RFC 5681 inflation");
  controller.on_sack_ack(false);
  if (!controller.in_fast_recovery() ||
      controller.congestion_window() != 6000U)
    throw std::runtime_error("TCP partial SACK ACK ended recovery");
  controller.on_sack_ack(true);
  if (controller.in_fast_recovery() ||
      controller.congestion_window() != 6000U)
    throw std::runtime_error("TCP SACK RecoveryPoint did not end recovery");

  // Restore a congestion-avoidance state and verify RFC 5681 equation 3:
  // floor(1460*1460/10000)=213 bytes for this ACK.
  auto avoidance = controller.checkpoint();
  avoidance.congestion_window = 10'000U;
  avoidance.slow_start_threshold = 5000U;
  CongestionController restored{1U};
  if (!restored.restore(avoidance))
    throw std::runtime_error("TCP rejected a valid congestion checkpoint");
  restored.on_new_ack(1460U);
  if (restored.congestion_window() != 10'213U)
    throw std::runtime_error("TCP congestion avoidance equation drifted");

  // RFC 5681 section 3.1 recommends scaling cwnd when PMTUD lowers SMSS. The
  // event is not congestion, so ssthresh is preserved and a duplicate or
  // larger notification cannot raise either value from untrusted input.
  restored.reduce_sender_mss(500U);
  const auto reduced = restored.checkpoint();
  if (reduced.sender_mss != 500U || reduced.congestion_window != 3497U ||
      reduced.slow_start_threshold != 5000U)
    throw std::runtime_error("TCP PMTU reduction did not scale cwnd by the MSS ratio");
  restored.reduce_sender_mss(1000U);
  if (restored.checkpoint().sender_mss != 500U ||
      restored.congestion_window() != 3497U)
    throw std::runtime_error("TCP network input raised the sender MSS");

  auto invalid = avoidance;
  invalid.fast_recovery = false;
  invalid.duplicate_acknowledgments = 3U;
  if (CongestionController::validate_checkpoint(invalid) ||
      restored.restore(invalid))
    throw std::runtime_error("TCP accepted inconsistent recovery state");
}
