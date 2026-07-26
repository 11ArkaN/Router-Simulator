// RFC 9293 control-state processing for OPEN, SYN, ACK, RST, CLOSE, FIN and
// TIME-WAIT. Byte-stream reassembly is intentionally delegated through an
// explicit event so this owner never acknowledges data it has not stored.

#include "router/tcp_control_block.hpp"

#include "router/tcp_sequence.hpp"

#include <algorithm>

namespace router::transport::tcp {
namespace {

[[nodiscard]] bool has(std::uint8_t flags, packet::tcp::Flag flag) noexcept {
  return (flags & static_cast<std::uint8_t>(flag)) != 0U;
}

[[nodiscard]] std::uint32_t segment_length(
    const packet::tcp::View &segment) noexcept {
  return static_cast<std::uint32_t>(segment.payload.size()) +
         (has(segment.flags, packet::tcp::syn) ? 1U : 0U) +
         (has(segment.flags, packet::tcp::fin) ? 1U : 0U);
}

[[nodiscard]] std::uint16_t wire_window(std::uint32_t window) noexcept {
  // Window scaling is negotiated and applied by the future option owner. An
  // unscaled control block must never truncate through an integer cast.
  return static_cast<std::uint16_t>(std::min(window, 65535U));
}

} // namespace

ControlBlock::ControlBlock(std::uint16_t local_port, std::uint16_t remote_port,
                           std::uint32_t receive_window,
                           std::uint32_t sender_mss) noexcept
    : congestion_(sender_mss), receive_window_(receive_window),
      local_port_(local_port), remote_port_(remote_port) {}

ControlResult ControlBlock::passive_open() noexcept {
  if (state_ != State::closed || local_port_ == 0U)
    return {};
  // LISTEN is keyed only by the local socket. A connection object may have
  // been recycled from an active tuple, but the peer port is selected solely
  // from the next accepted SYN and must not leak into the listener TCB.
  remote_port_ = 0U;
  state_ = State::listen;
  passive_open_ = true;
  return {};
}

void ControlBlock::track_control(const packet::tcp::Fields &segment,
                                 Clock::time_point now) noexcept {
  outstanding_control_ = segment;
  outstanding_control_present_ = true;
  retransmission_deadline_ = now + retransmission_.timeout();
}

void ControlBlock::acknowledge_control(Clock::time_point now) noexcept {
  if (!outstanding_control_present_)
    return;
  outstanding_control_present_ = false;
  // Handshake completion applies the RFC 6298 post-SYN-retransmission floor.
  // The current time is accepted for symmetry with future RTT sampling; no RTT
  // is fabricated merely because a control byte was acknowledged.
  static_cast<void>(now);
  retransmission_.on_handshake_complete();
}

ControlResult ControlBlock::active_open(std::uint32_t initial_sequence,
                                        Clock::time_point now) noexcept {
  if ((state_ != State::closed && state_ != State::listen) ||
      local_port_ == 0U || remote_port_ == 0U)
    return {};
  initial_send_sequence_ = initial_sequence;
  send_unacknowledged_ = initial_sequence;
  send_next_ = initial_sequence + 1U;
  passive_open_ = false;
  state_ = State::syn_sent;
  packet::tcp::Fields syn_segment{.source_port = local_port_,
                                  .destination_port = remote_port_,
                                  .sequence = initial_sequence,
                                  .flags = packet::tcp::syn,
                                  .window = wire_window(receive_window_)};
  track_control(syn_segment, now);
  return {.segment = syn_segment, .emit = true};
}

ControlResult ControlBlock::acknowledgment() const noexcept {
  return {.segment = {.source_port = local_port_,
                      .destination_port = remote_port_,
                      .sequence = send_next_,
                      .acknowledgment = receive_next_,
                      .flags = packet::tcp::ack,
                      .window = wire_window(receive_window_)},
          .emit = true};
}

ControlResult
ControlBlock::reset_for(const packet::tcp::View &segment) const noexcept {
  if (has(segment.flags, packet::tcp::ack)) {
    return {.segment = {.source_port = local_port_,
                        .destination_port = segment.source_port,
                        .sequence = segment.acknowledgment,
                        .flags = packet::tcp::rst},
            .emit = true};
  }
  return {.segment = {.source_port = local_port_,
                      .destination_port = segment.source_port,
                      .acknowledgment = segment.sequence + segment_length(segment),
                      .flags = static_cast<std::uint8_t>(packet::tcp::rst |
                                                         packet::tcp::ack)},
          .emit = true};
}

bool ControlBlock::synchronized() const noexcept {
  return state_ == State::syn_received || state_ == State::established ||
         state_ == State::fin_wait_1 || state_ == State::fin_wait_2 ||
         state_ == State::close_wait || state_ == State::closing ||
         state_ == State::last_ack || state_ == State::time_wait;
}

void ControlBlock::enter_time_wait(Clock::time_point now) noexcept {
  state_ = State::time_wait;
  outstanding_control_present_ = false;
  time_wait_deadline_ =
      now + device_catalog::tcp_maximum_segment_lifetime * 2;
}

ControlResult ControlBlock::accept_peer_fin(Clock::time_point now) noexcept {
  ++receive_next_;
  auto result = acknowledgment();
  result.event = ControlEvent::peer_closed;
  if (state_ == State::established || state_ == State::syn_received)
    state_ = State::close_wait;
  else if (state_ == State::fin_wait_1) {
    if (local_fin_sent_ && send_unacknowledged_ == send_next_)
      enter_time_wait(now);
    else
      state_ = State::closing;
  } else if (state_ == State::fin_wait_2) {
    enter_time_wait(now);
  } else if (state_ == State::time_wait) {
    enter_time_wait(now);
  }
  return result;
}

ControlResult ControlBlock::on_segment(const packet::tcp::View &segment,
                                       std::uint32_t passive_initial_sequence,
                                       Clock::time_point now,
                                       std::optional<std::uint32_t>
                                           decoded_peer_window) noexcept {
  if (segment.destination_port != local_port_)
    return {};
  const auto rst_set = has(segment.flags, packet::tcp::rst);
  const auto ack_set = has(segment.flags, packet::tcp::ack);
  const auto syn_set = has(segment.flags, packet::tcp::syn);
  // The packet view retains the exact 16-bit wire field. Once Window Scale is
  // negotiated, the connection owner supplies its decoded 30-bit value here;
  // keeping both representations prevents the wire parser from depending on
  // handshake state and prevents the TCB from silently truncating rwnd.
  const auto advertised_window =
      decoded_peer_window.value_or(segment.window);

  if (state_ == State::closed)
    return rst_set ? ControlResult{} : reset_for(segment);

  if (state_ == State::listen) {
    if (rst_set)
      return {};
    if (ack_set)
      return reset_for(segment);
    if (!syn_set)
      return {};
    remote_port_ = segment.source_port;
    initial_receive_sequence_ = segment.sequence;
    receive_next_ = segment.sequence + 1U;
    initial_send_sequence_ = passive_initial_sequence;
    send_unacknowledged_ = passive_initial_sequence;
    send_next_ = passive_initial_sequence + 1U;
    send_window_ = advertised_window;
    send_window_sequence_ = segment.sequence;
    send_window_acknowledgment_ = segment.acknowledgment;
    state_ = State::syn_received;
    packet::tcp::Fields syn_ack{
        .source_port = local_port_,
        .destination_port = remote_port_,
        .sequence = initial_send_sequence_,
        .acknowledgment = receive_next_,
        .flags = static_cast<std::uint8_t>(packet::tcp::syn | packet::tcp::ack),
        .window = wire_window(receive_window_)};
    track_control(syn_ack, now);
    return {.segment = syn_ack, .emit = true};
  }

  if (state_ == State::syn_sent) {
    const auto acceptable_ack =
        ack_set && sequence::after(segment.acknowledgment,
                                   initial_send_sequence_) &&
        sequence::before_or_equal(segment.acknowledgment, send_next_);
    if (ack_set && !acceptable_ack)
      return rst_set ? ControlResult{} : reset_for(segment);
    if (rst_set) {
      if (acceptable_ack) {
        state_ = State::closed;
        outstanding_control_present_ = false;
        return {.event = ControlEvent::connection_reset};
      }
      return {};
    }
    if (!syn_set)
      return {};
    initial_receive_sequence_ = segment.sequence;
    receive_next_ = segment.sequence + 1U;
    send_window_ = advertised_window;
    send_window_sequence_ = segment.sequence;
    send_window_acknowledgment_ = segment.acknowledgment;
    if (acceptable_ack) {
      send_unacknowledged_ = segment.acknowledgment;
      acknowledge_control(now);
      state_ = State::established;
      auto result = acknowledgment();
      result.event = ControlEvent::established;
      return result;
    }
    // Simultaneous open retransmits our original SYN with an ACK and remembers
    // that SYN-RECEIVED came from an active rather than passive OPEN.
    state_ = State::syn_received;
    packet::tcp::Fields syn_ack{
        .source_port = local_port_,
        .destination_port = remote_port_,
        .sequence = initial_send_sequence_,
        .acknowledgment = receive_next_,
        .flags = static_cast<std::uint8_t>(packet::tcp::syn | packet::tcp::ack),
        .window = wire_window(receive_window_)};
    track_control(syn_ack, now);
    return {.segment = syn_ack, .emit = true};
  }

  if (!synchronized())
    return {};
  const auto length = segment_length(segment);
  const auto repeated_simultaneous_syn =
      state_ == State::syn_received && !passive_open_ && syn_set && ack_set &&
      segment.payload.empty() && segment.sequence + 1U == receive_next_;
  if (state_ == State::time_wait && has(segment.flags, packet::tcp::fin) &&
      segment.payload.empty() && segment.sequence + 1U == receive_next_) {
    // A retransmitted peer FIN occupies the sequence number immediately before
    // RCV.NXT. It is outside the ordinary receive window after first receipt,
    // but RFC 9293 explicitly requires its ACK and a fresh 2*MSL interval.
    enter_time_wait(now);
    return acknowledgment();
  }
  if (!repeated_simultaneous_syn &&
      !sequence::segment_acceptable(segment.sequence, length, receive_next_,
                                    receive_window_))
    return rst_set ? ControlResult{} : acknowledgment();

  if (rst_set) {
    // RFC 5961 exact-sequence reset validation protects synchronized TCBs from
    // blind in-window RST injection. An in-window non-exact RST gets a challenge
    // ACK and cannot mutate state.
    if (segment.sequence != receive_next_)
      return acknowledgment();
    if (state_ == State::syn_received && passive_open_) {
      state_ = State::listen;
      remote_port_ = 0U;
      outstanding_control_present_ = false;
      return {};
    }
    state_ = State::closed;
    outstanding_control_present_ = false;
    return {.event = ControlEvent::connection_reset};
  }
  if (syn_set && !repeated_simultaneous_syn)
    return acknowledgment();
  if (!ack_set)
    return {};

  bool became_established{};
  if (state_ == State::syn_received) {
    if (!sequence::acknowledgment_advances(segment.acknowledgment,
                                           send_unacknowledged_, send_next_))
      return reset_for(segment);
    send_unacknowledged_ = segment.acknowledgment;
    send_window_ = advertised_window;
    send_window_sequence_ = segment.sequence;
    send_window_acknowledgment_ = segment.acknowledgment;
    acknowledge_control(now);
    state_ = State::established;
    became_established = true;
  } else {
    if (sequence::after(segment.acknowledgment, send_next_))
      return acknowledgment();
    if (sequence::acknowledgment_advances(segment.acknowledgment,
                                          send_unacknowledged_, send_next_)) {
      send_unacknowledged_ = segment.acknowledgment;
      if (send_unacknowledged_ == send_next_)
        acknowledge_control(now);
    }
    if (sequence::before(send_window_sequence_, segment.sequence) ||
        (send_window_sequence_ == segment.sequence &&
         sequence::before_or_equal(send_window_acknowledgment_,
                                   segment.acknowledgment))) {
      send_window_ = advertised_window;
      send_window_sequence_ = segment.sequence;
      send_window_acknowledgment_ = segment.acknowledgment;
    }
  }

  const auto local_fin_acknowledged =
      local_fin_sent_ && send_unacknowledged_ == send_next_;
  if (state_ == State::fin_wait_1 && local_fin_acknowledged)
    state_ = State::fin_wait_2;
  else if (state_ == State::closing && local_fin_acknowledged) {
    enter_time_wait(now);
    return {};
  } else if (state_ == State::last_ack && local_fin_acknowledged) {
    state_ = State::closed;
    return {.event = ControlEvent::connection_closed};
  }

  if (!segment.payload.empty())
    return {.event = ControlEvent::data_requires_stream_owner};
  if (!has(segment.flags, packet::tcp::fin)) {
    return {.event = became_established ? ControlEvent::established
                                        : ControlEvent::none};
  }
  if (segment.sequence != receive_next_)
    return acknowledgment();

  return accept_peer_fin(now);
}

bool ControlBlock::commit_sent_data(std::uint32_t sequence,
                                    std::uint32_t octets) noexcept {
  if ((state_ != State::established && state_ != State::close_wait) ||
      local_fin_sent_ || sequence != send_next_ || octets > 0x40000000U)
    return false;
  send_next_ += octets;
  return true;
}

std::optional<ControlResult> ControlBlock::commit_received_data(
    std::uint32_t next, std::uint32_t window,
    std::optional<std::uint32_t> fin_sequence,
    Clock::time_point now) noexcept {
  if (!synchronized() || state_ == State::time_wait ||
      sequence::before(next, receive_next_) ||
      next - receive_next_ > receive_window_)
    return std::nullopt;
  receive_next_ = next;
  receive_window_ = window;
  if (fin_sequence && *fin_sequence == receive_next_)
    return accept_peer_fin(now);
  return acknowledgment();
}

bool ControlBlock::set_receive_window(std::uint32_t window) noexcept {
  if (!synchronized())
    return false;
  receive_window_ = window;
  return true;
}

ControlResult ControlBlock::close(Clock::time_point now) noexcept {
  if (state_ == State::listen || state_ == State::syn_sent) {
    state_ = State::closed;
    outstanding_control_present_ = false;
    return {.event = ControlEvent::connection_closed};
  }
  if (state_ != State::established && state_ != State::close_wait)
    return {};
  packet::tcp::Fields fin_ack{
      .source_port = local_port_,
      .destination_port = remote_port_,
      .sequence = send_next_,
      .acknowledgment = receive_next_,
      .flags = static_cast<std::uint8_t>(packet::tcp::fin | packet::tcp::ack),
      .window = wire_window(receive_window_)};
  ++send_next_;
  local_fin_sent_ = true;
  state_ = state_ == State::established ? State::fin_wait_1 : State::last_ack;
  track_control(fin_ack, now);
  return {.segment = fin_ack, .emit = true};
}

ControlResult
ControlBlock::service_deadline(Clock::time_point now) noexcept {
  if (state_ == State::time_wait && now >= time_wait_deadline_) {
    state_ = State::closed;
    return {.event = ControlEvent::connection_closed};
  }
  if (!outstanding_control_present_ || now < retransmission_deadline_)
    return {};
  const auto waiting_for_syn = state_ == State::syn_sent ||
                               state_ == State::syn_received;
  const auto next_timeout = retransmission_.on_timeout(waiting_for_syn);
  retransmission_deadline_ = now + next_timeout;
  return {.segment = outstanding_control_, .emit = true};
}

std::optional<ControlBlock::Clock::time_point>
ControlBlock::next_deadline() const noexcept {
  if (state_ == State::time_wait)
    return time_wait_deadline_;
  if (outstanding_control_present_)
    return retransmission_deadline_;
  return std::nullopt;
}

ControlBlockCheckpoint
ControlBlock::checkpoint(Clock::time_point now) const noexcept {
  const auto remaining = [now](bool active, Clock::time_point deadline) {
    return active && deadline > now
               ? std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now)
                     .count()
               : std::int64_t{0};
  };
  return {.retransmission = retransmission_.checkpoint(),
          .congestion = congestion_.checkpoint(),
          .outstanding_control = outstanding_control_,
          .retransmission_remaining_nanoseconds =
              remaining(outstanding_control_present_, retransmission_deadline_),
          .time_wait_remaining_nanoseconds =
              remaining(state_ == State::time_wait, time_wait_deadline_),
          .send_unacknowledged = send_unacknowledged_,
          .send_next = send_next_,
          .send_window = send_window_,
          .send_window_sequence = send_window_sequence_,
          .send_window_acknowledgment = send_window_acknowledgment_,
          .receive_next = receive_next_,
          .receive_window = receive_window_,
          .initial_send_sequence = initial_send_sequence_,
          .initial_receive_sequence = initial_receive_sequence_,
          .local_port = local_port_,
          .remote_port = remote_port_,
          .state = state_,
          .passive_open = passive_open_,
          .outstanding_control_present = outstanding_control_present_,
          .local_fin_sent = local_fin_sent_};
}

bool ControlBlock::validate_checkpoint(
    const ControlBlockCheckpoint &value) noexcept {
  if (!RetransmissionEstimator::validate_checkpoint(value.retransmission) ||
      !CongestionController::validate_checkpoint(value.congestion) ||
      value.local_port == 0U ||
      static_cast<std::uint8_t>(value.state) >
          static_cast<std::uint8_t>(State::time_wait))
    return false;
  if (value.outstanding_control_present !=
      (value.retransmission_remaining_nanoseconds > 0))
    return false;
  if ((value.state == State::time_wait) !=
      (value.time_wait_remaining_nanoseconds > 0))
    return false;
  if (value.state == State::listen && value.remote_port != 0U)
    return false;
  return value.state == State::closed || value.state == State::listen ||
         value.remote_port != 0U;
}

bool ControlBlock::restore(const ControlBlockCheckpoint &value,
                           Clock::time_point now) noexcept {
  if (!validate_checkpoint(value) ||
      !retransmission_.restore(value.retransmission) ||
      !congestion_.restore(value.congestion))
    return false;
  outstanding_control_ = value.outstanding_control;
  retransmission_deadline_ =
      now + std::chrono::nanoseconds{value.retransmission_remaining_nanoseconds};
  time_wait_deadline_ =
      now + std::chrono::nanoseconds{value.time_wait_remaining_nanoseconds};
  send_unacknowledged_ = value.send_unacknowledged;
  send_next_ = value.send_next;
  send_window_ = value.send_window;
  send_window_sequence_ = value.send_window_sequence;
  send_window_acknowledgment_ = value.send_window_acknowledgment;
  receive_next_ = value.receive_next;
  receive_window_ = value.receive_window;
  initial_send_sequence_ = value.initial_send_sequence;
  initial_receive_sequence_ = value.initial_receive_sequence;
  local_port_ = value.local_port;
  remote_port_ = value.remote_port;
  state_ = value.state;
  passive_open_ = value.passive_open;
  outstanding_control_present_ = value.outstanding_control_present;
  local_fin_sent_ = value.local_fin_sent;
  return true;
}

} // namespace router::transport::tcp
