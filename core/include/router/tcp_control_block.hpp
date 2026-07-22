// RFC 9293 connection-control state for one TCP four-tuple. The endpoint shard
// is the sole mutable owner and converts returned header intents into encoded
// IP packets. Application byte-stream storage remains a separate owner.

#pragma once

#include "router/tcp_congestion.hpp"
#include "router/tcp_packet.hpp"
#include "router/tcp_retransmission.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

namespace router::transport::tcp {

enum class State : std::uint8_t {
  closed,
  listen,
  syn_sent,
  syn_received,
  established,
  fin_wait_1,
  fin_wait_2,
  close_wait,
  closing,
  last_ack,
  time_wait
};

enum class ControlEvent : std::uint8_t {
  none,
  established,
  peer_closed,
  connection_reset,
  connection_closed,
  data_requires_stream_owner
};

struct ControlResult {
  packet::tcp::Fields segment{};
  ControlEvent event{ControlEvent::none};
  bool emit{};
};

struct ControlBlockCheckpoint {
  RetransmissionCheckpoint retransmission;
  CongestionCheckpoint congestion;
  packet::tcp::Fields outstanding_control{};
  std::int64_t retransmission_remaining_nanoseconds{};
  std::int64_t time_wait_remaining_nanoseconds{};
  std::uint32_t send_unacknowledged{};
  std::uint32_t send_next{};
  std::uint32_t send_window{};
  std::uint32_t send_window_sequence{};
  std::uint32_t send_window_acknowledgment{};
  std::uint32_t receive_next{};
  std::uint32_t receive_window{};
  std::uint32_t initial_send_sequence{};
  std::uint32_t initial_receive_sequence{};
  std::uint16_t local_port{};
  std::uint16_t remote_port{};
  State state{State::closed};
  bool passive_open{};
  bool outstanding_control_present{};
  bool local_fin_sent{};
};

class ControlBlock final {
public:
  using Clock = std::chrono::steady_clock;

  explicit ControlBlock(std::uint16_t local_port, std::uint16_t remote_port,
                        std::uint32_t receive_window,
                        std::uint32_t sender_mss) noexcept;

  [[nodiscard]] ControlResult passive_open() noexcept;
  [[nodiscard]] ControlResult active_open(
      std::uint32_t initial_sequence,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ControlResult on_segment(
      const packet::tcp::View &segment, std::uint32_t passive_initial_sequence,
      Clock::time_point now = Clock::now(),
      std::optional<std::uint32_t> decoded_peer_window = std::nullopt) noexcept;
  [[nodiscard]] ControlResult close(
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ControlResult service_deadline(
      Clock::time_point now = Clock::now()) noexcept;

  // The stream owner calls this only after Sender commits a data packet to the
  // lower queue. It keeps control sequence space synchronized without giving
  // the TCB a mutable pointer to application bytes or packet storage.
  [[nodiscard]] bool commit_sent_data(std::uint32_t sequence,
                                      std::uint32_t octets) noexcept;

  // The receive owner first stores payload and advances its contiguous prefix,
  // then commits the resulting RCV.NXT here. fin_sequence is the sequence
  // occupied by FIN after the payload; an out-of-order FIN remains pending.
  [[nodiscard]] std::optional<ControlResult> commit_received_data(
      std::uint32_t receive_next, std::uint32_t receive_window,
      std::optional<std::uint32_t> fin_sequence,
      Clock::time_point now = Clock::now()) noexcept;

  // Application reads can open the receiver window without receiving another
  // segment. The caller decides through receiver SWS whether an ACK is needed.
  [[nodiscard]] bool set_receive_window(std::uint32_t receive_window) noexcept;
  [[nodiscard]] ControlResult current_acknowledgment() const noexcept {
    return acknowledgment();
  }

  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] std::uint32_t send_unacknowledged() const noexcept {
    return send_unacknowledged_;
  }
  [[nodiscard]] std::uint32_t send_next() const noexcept { return send_next_; }
  [[nodiscard]] std::uint32_t send_window() const noexcept {
    return send_window_;
  }
  [[nodiscard]] std::uint32_t receive_next() const noexcept {
    return receive_next_;
  }
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  [[nodiscard]] ControlBlockCheckpoint checkpoint(
      Clock::time_point now = Clock::now()) const noexcept;
  [[nodiscard]] static bool
  validate_checkpoint(const ControlBlockCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const ControlBlockCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  [[nodiscard]] ControlResult acknowledgment() const noexcept;
  [[nodiscard]] ControlResult reset_for(const packet::tcp::View &segment) const noexcept;
  void track_control(const packet::tcp::Fields &segment,
                     Clock::time_point now) noexcept;
  void acknowledge_control(Clock::time_point now) noexcept;
  void enter_time_wait(Clock::time_point now) noexcept;
  [[nodiscard]] ControlResult accept_peer_fin(Clock::time_point now) noexcept;
  [[nodiscard]] bool synchronized() const noexcept;

  RetransmissionEstimator retransmission_{};
  CongestionController congestion_;
  packet::tcp::Fields outstanding_control_{};
  Clock::time_point retransmission_deadline_{};
  Clock::time_point time_wait_deadline_{};
  std::uint32_t send_unacknowledged_{};
  std::uint32_t send_next_{};
  std::uint32_t send_window_{};
  std::uint32_t send_window_sequence_{};
  std::uint32_t send_window_acknowledgment_{};
  std::uint32_t receive_next_{};
  std::uint32_t receive_window_{};
  std::uint32_t initial_send_sequence_{};
  std::uint32_t initial_receive_sequence_{};
  std::uint16_t local_port_{};
  std::uint16_t remote_port_{};
  State state_{State::closed};
  bool passive_open_{};
  bool outstanding_control_present_{};
  bool local_fin_sent_{};
};

} // namespace router::transport::tcp
