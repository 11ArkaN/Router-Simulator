// RFC 6298 retransmission-timeout estimator for one TCP control block.
// The owning endpoint supplies monotonic RTT samples and timeout events. This
// value object owns estimator state only and never schedules a global event.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <chrono>
#include <cstdint>

namespace router::transport::tcp {

struct RetransmissionCheckpoint {
  std::int64_t smoothed_rtt_nanoseconds{};
  std::int64_t rtt_variation_nanoseconds{};
  std::int64_t timeout_nanoseconds{};
  bool measurement_present{};
  bool syn_retransmitted{};
};

enum class RttSampleResult : std::uint8_t {
  accepted,
  ignored_retransmission_ambiguity,
  invalid
};

class RetransmissionEstimator final {
public:
  using Duration = std::chrono::steady_clock::duration;

  RetransmissionEstimator() noexcept;

  // A sample must be strictly positive. RFC 6298 Karn processing ignores a
  // retransmitted segment unless a negotiated timestamp identifies which
  // transmission the acknowledgment covers.
  [[nodiscard]] RttSampleResult
  observe(Duration sample, bool segment_was_retransmitted,
          bool timestamp_removes_ambiguity = false) noexcept;

  // The TCB calls this only when its live retransmission deadline expires.
  // It returns the backed-off RTO used for the next deadline. waiting_for_syn
  // records RFC 6298 section 5.7 behavior for handshake completion.
  [[nodiscard]] Duration on_timeout(bool waiting_for_syn) noexcept;
  void on_handshake_complete() noexcept;

  [[nodiscard]] Duration timeout() const noexcept { return timeout_; }
  [[nodiscard]] bool has_measurement() const noexcept {
    return measurement_present_;
  }
  [[nodiscard]] Duration smoothed_rtt() const noexcept {
    return smoothed_rtt_;
  }
  [[nodiscard]] Duration rtt_variation() const noexcept {
    return rtt_variation_;
  }

  [[nodiscard]] RetransmissionCheckpoint checkpoint() const noexcept;
  [[nodiscard]] static bool
  validate_checkpoint(const RetransmissionCheckpoint &state) noexcept;
  [[nodiscard]] bool
  restore(const RetransmissionCheckpoint &state) noexcept;

private:
  [[nodiscard]] static Duration bounded_timeout(Duration smoothed,
                                                Duration variation) noexcept;

  Duration smoothed_rtt_{};
  Duration rtt_variation_{};
  Duration timeout_{};
  bool measurement_present_{};
  bool syn_retransmitted_{};
};

} // namespace router::transport::tcp
