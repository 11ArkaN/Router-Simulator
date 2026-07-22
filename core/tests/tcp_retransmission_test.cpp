// RFC 6298 estimator tests use exact wall-duration values and checkpoint
// continuation. No test clock is injected into production because this value
// object computes intervals and the endpoint owner schedules real deadlines.

#include "router/tcp_retransmission.hpp"

#include <chrono>
#include <stdexcept>

void tcp_retransmission_tests() {
  using namespace std::chrono_literals;
  using router::transport::tcp::RetransmissionCheckpoint;
  using router::transport::tcp::RetransmissionEstimator;
  using router::transport::tcp::RttSampleResult;

  RetransmissionEstimator estimator;
  if (estimator.timeout() != 1s || estimator.has_measurement())
    throw std::runtime_error("TCP RTO did not start at RFC 6298 one second");
  if (estimator.observe(0ns, false) != RttSampleResult::invalid ||
      estimator.observe(-1ns, false) != RttSampleResult::invalid)
    throw std::runtime_error("TCP RTO accepted a nonpositive RTT sample");

  // First sample: SRTT=2s, RTTVAR=1s and RTO=2+4*1=6s.
  if (estimator.observe(2s, false) != RttSampleResult::accepted ||
      estimator.smoothed_rtt() != 2s || estimator.rtt_variation() != 1s ||
      estimator.timeout() != 6s)
    throw std::runtime_error("TCP RTO first-sample initialization drifted");

  // Second sample uses the old 2s SRTT for RTTVAR before alpha updates SRTT:
  // RTTVAR remains 1s, SRTT becomes 2.125s, and RTO becomes 6.125s.
  if (estimator.observe(3s, false) != RttSampleResult::accepted ||
      estimator.smoothed_rtt() != 2125ms ||
      estimator.rtt_variation() != 1s || estimator.timeout() != 6125ms)
    throw std::runtime_error("TCP RTO alpha or beta update order drifted");

  const auto before_karn = estimator.checkpoint();
  if (estimator.observe(40ms, true) !=
          RttSampleResult::ignored_retransmission_ambiguity ||
      estimator.checkpoint().timeout_nanoseconds !=
          before_karn.timeout_nanoseconds)
    throw std::runtime_error("TCP RTO violated Karn retransmission ambiguity");
  if (estimator.observe(40ms, true, true) != RttSampleResult::accepted)
    throw std::runtime_error("TCP timestamp did not remove RTT ambiguity");

  // Repeated timeouts double but never exceed the configured RFC-permitted
  // 60-second ceiling. The first timeout also records SYN loss so post-handshake
  // data cannot continue with an RTO below RFC 6298 section 5.7's three seconds.
  RetransmissionEstimator syn_estimator;
  if (syn_estimator.on_timeout(true) != 2s)
    throw std::runtime_error("TCP RTO did not exponentially back off a SYN");
  syn_estimator.on_handshake_complete();
  if (syn_estimator.timeout() != 3s)
    throw std::runtime_error("TCP RTO did not apply the post-SYN-loss floor");
  for (unsigned count = 0U; count < 8U; ++count)
    static_cast<void>(syn_estimator.on_timeout(false));
  if (syn_estimator.timeout() != 60s ||
      syn_estimator.on_timeout(false) != 60s)
    throw std::runtime_error("TCP RTO exceeded its standards-profile ceiling");

  const auto saved = estimator.checkpoint();
  RetransmissionEstimator restored;
  if (!restored.restore(saved) || restored.checkpoint().timeout_nanoseconds !=
                                      saved.timeout_nanoseconds ||
      restored.checkpoint().smoothed_rtt_nanoseconds !=
          saved.smoothed_rtt_nanoseconds ||
      restored.checkpoint().rtt_variation_nanoseconds !=
          saved.rtt_variation_nanoseconds)
    throw std::runtime_error("TCP RTO checkpoint did not preserve estimator state");

  auto invalid = saved;
  invalid.timeout_nanoseconds = 999'999'999LL;
  if (RetransmissionEstimator::validate_checkpoint(invalid) ||
      restored.restore(invalid))
    throw std::runtime_error("TCP RTO accepted a timeout below one second");
  invalid = RetransmissionCheckpoint{.smoothed_rtt_nanoseconds = 1,
                                     .rtt_variation_nanoseconds = 0,
                                     .timeout_nanoseconds = 1'000'000'000LL,
                                     .measurement_present = false,
                                     .syn_retransmitted = false};
  if (RetransmissionEstimator::validate_checkpoint(invalid))
    throw std::runtime_error("TCP RTO accepted latent uninitialized samples");
}
