// Failure-policy tests cover the exact RFC 9293 R1 and R2 boundaries, SYN's
// mandatory horizon, application overrides and relative checkpoint restore.

#include "router/tcp_failure.hpp"

#include <chrono>
#include <stdexcept>

void tcp_failure_tests() {
  using namespace router::transport::tcp;
  using namespace std::chrono_literals;
  using Clock = FailureDetector::Clock;

  const auto start = Clock::time_point{200s};
  FailureDetector detector;
  if (!detector.begin(1000U, 1500U, false, start))
    throw std::runtime_error("TCP failure detector rejected a data segment");
  if (detector.retransmitted(1000U, 1500U, start + 1s) !=
          FailureAction::none ||
      detector.retransmitted(1000U, 1500U, start + 3s) !=
          FailureAction::none ||
      detector.retransmitted(1000U, 1500U, start + 7s) !=
          FailureAction::negative_ip_advice ||
      detector.retransmitted(1000U, 1500U, start + 15s) !=
          FailureAction::none) {
    throw std::runtime_error("TCP R1 did not report exactly once at three retransmissions");
  }
  if (detector.service(start + 99s) != FailureAction::none ||
      detector.service(start + 100s) != FailureAction::abort_connection)
    throw std::runtime_error("TCP data R2 did not retain the 100-second default");

  // A covering cumulative ACK resets evidence. A duplicate ACK before the
  // segment end cannot hide an unreachable peer from the failure policy.
  detector.acknowledge(1499U);
  if (!detector.active())
    throw std::runtime_error("TCP failure detector accepted a partial acknowledgment");
  detector.acknowledge(1500U);
  if (detector.active() || detector.deadline())
    throw std::runtime_error("TCP failure evidence survived a covering acknowledgment");

  // An application may use infinity for a long-lived data connection. The SYN
  // failure horizon remains finite and at least three minutes, as MUST-23
  // requires, regardless of that data policy.
  if (!detector.set_data_r2(std::nullopt) ||
      !detector.begin(7U, 8U, false, start) || detector.deadline() ||
      detector.service(start + 24h) != FailureAction::none)
    throw std::runtime_error("TCP infinite application R2 was not connection-local");
  if (!detector.begin(9U, 10U, true, start) ||
      detector.service(start + 179s) != FailureAction::none ||
      detector.service(start + 180s) != FailureAction::abort_connection)
    throw std::runtime_error("TCP SYN R2 violated the three-minute minimum");

  // Checkpoint age is relative to the new monotonic origin. A restored third
  // retransmission still emits R1 once and the original R2 remaining duration
  // is not extended by restore.
  FailureDetector saved;
  if (!saved.set_data_r2(120s) ||
      !saved.begin(0xfffffff0U, 0x10U, false, start) ||
      saved.retransmitted(0xfffffff0U, 0x10U, start + 1s) !=
          FailureAction::none ||
      saved.retransmitted(0xfffffff0U, 0x10U, start + 2s) !=
          FailureAction::none)
    throw std::runtime_error("TCP failure wrap fixture could not be prepared");
  const auto checkpoint = saved.checkpoint(start + 50s);
  FailureDetector restored;
  const auto restored_at = Clock::time_point{500s};
  if (!restored.restore(checkpoint, restored_at) ||
      restored.retransmitted(0xfffffff0U, 0x10U, restored_at + 1s) !=
          FailureAction::negative_ip_advice ||
      restored.service(restored_at + 69s) != FailureAction::none ||
      restored.service(restored_at + 70s) !=
          FailureAction::abort_connection)
    throw std::runtime_error("TCP failure checkpoint changed R1 or R2 progress");

  auto invalid = checkpoint;
  invalid.negative_advice_reported = true;
  invalid.retransmissions = 2U;
  const auto before = restored.checkpoint(restored_at + 60s);
  if (restored.restore(invalid, restored_at + 60s) ||
      restored.checkpoint(restored_at + 60s).segment_first !=
          before.segment_first)
    throw std::runtime_error("TCP failure restore mutated state before validation");
}
