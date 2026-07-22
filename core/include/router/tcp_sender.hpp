// Integrated TCP data sender for one connection. The endpoint shard owns this
// object and supplies packet admission results plus monotonic timestamps. It
// combines caller-sized storage, RFC 5681 congestion state and RFC 6298 RTO.

#pragma once

#include "router/tcp_congestion.hpp"
#include "router/tcp_failure.hpp"
#include "router/tcp_retransmission.hpp"
#include "router/tcp_sack_scoreboard.hpp"
#include "router/tcp_send_buffer.hpp"
#include "router/tcp_timers.hpp"
#include "router/tcp_transmission_history.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::transport::tcp {

enum class TransmissionReason : std::uint8_t {
  new_data,
  fast_retransmit,
  timeout_retransmit,
  persist_probe,
  sack_recovery
};

struct PreparedTransmission {
  PreparedSendRange range;
  TransmissionReason reason{TransmissionReason::new_data};
  SackNextReason sack_reason{SackNextReason::lost_retransmission};
  std::uint64_t sender_generation{};

  [[nodiscard]] explicit operator bool() const noexcept {
    return static_cast<bool>(range);
  }
};

struct SenderAcknowledgeResult {
  SendAcknowledgeStatus status{SendAcknowledgeStatus::invalid};
  std::uint32_t newly_acknowledged{};
  bool fast_retransmission_ready{};
  bool sack_recovery_ready{};
};

struct SenderCheckpoint {
  SendBufferCheckpoint bytes;
  TransmissionHistoryCheckpoint history;
  FailureCheckpoint failure;
  SackScoreboardCheckpoint sack;
  CongestionCheckpoint congestion;
  RetransmissionCheckpoint retransmission;
  PersistCheckpoint persist;
  std::uint32_t receiver_window{};
  std::uint32_t maximum_receiver_window{};
  std::uint32_t rtt_sequence_end{};
  std::int64_t retransmission_remaining_nanoseconds{};
  std::int64_t rtt_probe_age_nanoseconds{};
  std::int64_t sws_override_remaining_nanoseconds{};
  std::uint64_t generation{};
  FailureAction pending_failure_action{FailureAction::none};
  bool retransmission_deadline_present{};
  bool rtt_probe_present{};
  bool rtt_probe_retransmitted{};
  bool fast_retransmission_pending{};
  bool sws_override_deadline_present{};
  bool nagle_enabled{true};
  bool sack_enabled{};
};

class Sender final {
public:
  using Clock = std::chrono::steady_clock;

  // storage capacity is selected by the runtime resource owner. sender_mss is
  // the effective data MSS after handshake and path/header calculation.
  Sender(std::span<std::uint8_t> storage,
         std::span<TransmissionRecord> history_storage,
         std::span<SackRange> sack_ranges,
         std::span<SackRange> sack_workspace,
         std::uint32_t initial_data_sequence,
         std::uint32_t sender_mss) noexcept;

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] std::size_t
  write(std::span<const std::uint8_t> input,
        Clock::time_point now = Clock::now()) noexcept;

  // The TCB calls this only after RFC 9293 SND.WL1/SND.WL2 validation. A
  // changed peer window invalidates a prepared segment because its allowance
  // may have shrunk before lower-layer admission.
  void update_receiver_window(std::uint32_t receiver_window,
                              Clock::time_point now) noexcept;
  void set_nagle_enabled(bool enabled) noexcept;
  void set_sack_enabled(bool enabled) noexcept;
  // Applies a strictly smaller path-derived SMSS without acknowledging data,
  // firing a retransmission or treating ICMP as a congestion-loss event.
  [[nodiscard]] bool reduce_mss(std::uint32_t sender_mss) noexcept;
  [[nodiscard]] bool transmitted(std::uint32_t sequence) const noexcept {
    return history_.contains(sequence);
  }

  // New transmission allowance is min(cwnd,rwnd)-FlightSize and never exceeds
  // SMSS. Preparing and copying do not consume sequence space or start RTO.
  [[nodiscard]] PreparedTransmission prepare_new(Clock::time_point now,
                                                 bool pushed) noexcept;
  [[nodiscard]] PreparedTransmission
  prepare_fast_retransmission() const noexcept;
  [[nodiscard]] PreparedTransmission
  prepare_timeout_retransmission(Clock::time_point now) const noexcept;
  [[nodiscard]] PreparedTransmission
  prepare_persist_probe(Clock::time_point now) noexcept;
  [[nodiscard]] PreparedTransmission
  prepare_sack_recovery(Clock::time_point now) noexcept;
  [[nodiscard]] bool copy(const PreparedTransmission &intent,
                          std::span<std::uint8_t> output) const noexcept;

  // Commit must follow successful IP and queue admission. It is the only path
  // that advances SND.NXT, starts an RTT probe or applies a loss response.
  [[nodiscard]] bool commit(const PreparedTransmission &intent,
                            Clock::time_point now) noexcept;

  // duplicate_ack_eligible is true only after the owner applies the complete
  // RFC 5681 duplicate-ACK definition, including unchanged window and no data.
  [[nodiscard]] SenderAcknowledgeResult acknowledge(
      std::uint32_t acknowledgment, std::uint32_t receiver_window,
      bool duplicate_ack_eligible, Clock::time_point now,
      std::optional<Clock::duration> timestamp_rtt = std::nullopt,
      std::span<const SackBlock> sack_blocks = {}) noexcept;

  [[nodiscard]] std::optional<Clock::time_point>
  retransmission_deadline() const noexcept {
    return retransmission_deadline_;
  }
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] std::uint32_t flight_size() const noexcept {
    return bytes_.flight_size();
  }
  [[nodiscard]] std::uint32_t receiver_window() const noexcept {
    return receiver_window_;
  }
  [[nodiscard]] std::uint32_t congestion_window() const noexcept {
    return congestion_.congestion_window();
  }
  [[nodiscard]] RetransmissionEstimator::Duration rto() const noexcept {
    return retransmission_.timeout();
  }

  // R1 advice is latched until the endpoint owner consumes it. R2 is also
  // evaluated directly from monotonic time so queue backpressure cannot keep
  // a failed connection alive merely by preventing another retransmission.
  [[nodiscard]] FailureAction
  failure_action(Clock::time_point now) const noexcept;
  [[nodiscard]] FailureAction take_failure_action(
      Clock::time_point now) noexcept;

  [[nodiscard]] SenderCheckpoint checkpoint(Clock::time_point now) const;
  [[nodiscard]] bool restore(const SenderCheckpoint &state,
                             Clock::time_point now) noexcept;

private:
  [[nodiscard]] bool current(const PreparedTransmission &intent) const noexcept;
  void start_or_restart_timer(Clock::time_point now) noexcept;
  void mark_rtt_retransmitted(const PreparedSendRange &range) noexcept;

  SendBuffer bytes_;
  TransmissionHistory history_;
  FailureDetector failure_;
  SackScoreboard sack_;
  CongestionController congestion_;
  RetransmissionEstimator retransmission_;
  PersistTimer persist_;
  std::uint32_t sender_mss_{};
  std::uint32_t receiver_window_{};
  std::uint32_t maximum_receiver_window_{};
  std::uint32_t rtt_sequence_end_{};
  Clock::time_point rtt_sent_at_{};
  std::optional<Clock::time_point> retransmission_deadline_;
  std::optional<Clock::time_point> sws_override_deadline_;
  std::uint64_t generation_{1U};
  FailureAction pending_failure_action_{FailureAction::none};
  bool rtt_probe_present_{};
  bool rtt_probe_retransmitted_{};
  bool fast_retransmission_pending_{};
  bool nagle_enabled_{true};
  bool sack_enabled_{};
  bool valid_{};
};

} // namespace router::transport::tcp
