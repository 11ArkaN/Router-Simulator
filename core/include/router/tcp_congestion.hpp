// RFC 5681 congestion-control state for one TCP sender. The TCB owner supplies
// acknowledged byte counts and real loss signals. This module neither emits
// segments nor infers congestion from topology or editor state.

#pragma once

#include <cstdint>

namespace router::transport::tcp {

enum class DuplicateAckAction : std::uint8_t {
  none,
  retransmit_oldest
};

struct CongestionCheckpoint {
  std::uint32_t sender_mss{};
  std::uint32_t congestion_window{};
  std::uint32_t slow_start_threshold{};
  std::uint32_t duplicate_acknowledgments{};
  std::uint32_t recovery_inflation_limit{};
  bool fast_recovery{};
  bool sack_recovery{};
};

class CongestionController final {
public:
  // A zero SMSS is not a valid TCP segment size. Construction normalizes it
  // to one byte only to keep this noexcept value type initialized; callers
  // must reject zero before publishing a connection.
  explicit CongestionController(std::uint32_t sender_mss) noexcept;

  [[nodiscard]] static std::uint32_t
  initial_window(std::uint32_t sender_mss) noexcept;

  // newly_acknowledged is the count of previously unacknowledged data octets,
  // excluding SYN and FIN sequence-space consumption. ACK division therefore
  // cannot inflate slow start by more than one SMSS for one cumulative ACK.
  void on_new_ack(std::uint32_t newly_acknowledged) noexcept;

  // flight_size is actual outstanding data, not cwnd. RFC 5681 equation 4
  // explicitly forbids substituting the receiver window for this value.
  [[nodiscard]] DuplicateAckAction
  on_duplicate_ack(std::uint32_t flight_size) noexcept;
  void on_retransmission_timeout(std::uint32_t flight_size) noexcept;
  void enter_sack_recovery(std::uint32_t flight_size) noexcept;
  void on_sack_ack(bool recovery_complete) noexcept;
  // RFC 5681 section 3.1 recommends scaling cwnd by new-SMSS/old-SMSS when
  // PMTUD discovers a smaller segment size. This is not a congestion signal,
  // so ssthresh and loss state are retained.
  void reduce_sender_mss(std::uint32_t sender_mss) noexcept;

  [[nodiscard]] std::uint32_t congestion_window() const noexcept {
    return congestion_window_;
  }
  [[nodiscard]] std::uint32_t slow_start_threshold() const noexcept {
    return slow_start_threshold_;
  }
  [[nodiscard]] bool in_fast_recovery() const noexcept {
    return fast_recovery_;
  }
  [[nodiscard]] std::uint32_t send_allowance(
      std::uint32_t receiver_window, std::uint32_t flight_size) const noexcept;

  [[nodiscard]] CongestionCheckpoint checkpoint() const noexcept;
  [[nodiscard]] static bool
  validate_checkpoint(const CongestionCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const CongestionCheckpoint &state) noexcept;

private:
  [[nodiscard]] std::uint32_t reduced_threshold(
      std::uint32_t flight_size) const noexcept;

  std::uint32_t sender_mss_{};
  std::uint32_t congestion_window_{};
  std::uint32_t slow_start_threshold_{};
  std::uint32_t duplicate_acknowledgments_{};
  std::uint32_t recovery_inflation_limit_{};
  bool fast_recovery_{};
  bool sack_recovery_{};
};

} // namespace router::transport::tcp
