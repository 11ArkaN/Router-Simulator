// TCP sender integration. All time is supplied by the owner from steady_clock.
// A failed lower-layer admission leaves sequence, timer and congestion state
// unchanged, which is essential when bounded packet or port queues are full.

#include "router/tcp_sender.hpp"

#include "router/tcp_sequence.hpp"

#include <algorithm>

namespace router::transport::tcp {

Sender::Sender(std::span<std::uint8_t> storage,
               std::span<TransmissionRecord> history_storage,
               std::span<SackRange> sack_ranges,
               std::span<SackRange> sack_workspace,
               std::uint32_t initial_data_sequence,
               std::uint32_t sender_mss) noexcept
    : bytes_(storage, initial_data_sequence), history_(history_storage),
      failure_(), sack_(sack_ranges, sack_workspace, sender_mss),
      congestion_(sender_mss), sender_mss_(sender_mss) {
  valid_ = bytes_.valid() && history_.valid() && sack_.valid() &&
           sender_mss_ != 0U &&
           sack_.reset(initial_data_sequence, initial_data_sequence);
}

std::size_t Sender::write(std::span<const std::uint8_t> input,
                          Clock::time_point now) noexcept {
  if (!valid_)
    return 0U;
  const auto accepted = bytes_.write(input);
  if (accepted != 0U) {
    // Application writes are one of the events that can create persist: the
    // peer window may already be zero while no earlier bytes were queued.
    persist_.update(receiver_window_ == 0U, bytes_.queued_octets() != 0U,
                    retransmission_.timeout(), now);
    ++generation_;
  }
  return accepted;
}

void Sender::update_receiver_window(std::uint32_t receiver_window,
                                    Clock::time_point now) noexcept {
  if (!valid_)
    return;
  const bool was_zero = receiver_window_ == 0U;
  maximum_receiver_window_ = std::max(maximum_receiver_window_, receiver_window);
  persist_.update(receiver_window == 0U, bytes_.queued_octets() != 0U,
                  retransmission_.timeout(), now);
  if (receiver_window_ == receiver_window)
    return;
  receiver_window_ = receiver_window;
  if (receiver_window == 0U) {
    // A persist condition is flow control, not evidence of path failure. Stop
    // ordinary data RTO and R1/R2 while the peer explicitly advertises zero.
    retransmission_deadline_.reset();
    failure_.reset();
  } else {
    sws_override_deadline_.reset();
    if (was_zero && bytes_.flight_size() != 0U) {
      start_or_restart_timer(now);
      if (const auto oldest = history_.oldest())
        static_cast<void>(failure_.begin(oldest->first, oldest->end, false,
                                         now));
    }
  }
  ++generation_;
}

void Sender::set_nagle_enabled(bool enabled) noexcept {
  if (!valid_ || nagle_enabled_ == enabled)
    return;
  nagle_enabled_ = enabled;
  ++generation_;
}

void Sender::set_sack_enabled(bool enabled) noexcept {
  if (!valid_ || sack_enabled_ == enabled)
    return;
  sack_enabled_ = enabled;
  // Negotiation changes only before data. Disabling later discards advisory
  // recovery state but never removes bytes from the retransmission repository.
  if (!enabled)
    static_cast<void>(sack_.reset(bytes_.send_unacknowledged(),
                                  bytes_.send_next()));
  ++generation_;
}

bool Sender::reduce_mss(std::uint32_t sender_mss) noexcept {
  if (!valid_ || sender_mss == 0U || sender_mss > sender_mss_)
    return false;
  if (sender_mss == sender_mss_)
    return true;
  congestion_.reduce_sender_mss(sender_mss);
  sack_.reduce_sender_mss(sender_mss);
  sender_mss_ = sender_mss;
  // Prepared output was derived from the old segmentation boundary. Advancing
  // generation invalidates it before any lower owner can commit oversized
  // bytes after the PMTU notification.
  ++generation_;
  return true;
}

PreparedTransmission Sender::prepare_new(Clock::time_point now,
                                         bool pushed) noexcept {
  if (!valid_)
    return {};
  persist_.update(receiver_window_ == 0U, bytes_.queued_octets() != 0U,
                  retransmission_.timeout(), now);
  const auto allowance = congestion_.send_allowance(
      receiver_window_, bytes_.flight_size());
  const auto unsent = bytes_.unsent_octets();
  const auto available = std::min(allowance, unsent);
  if (available == 0U)
    return {};

  std::uint32_t payload{};
  if (available >= sender_mss_) {
    payload = sender_mss_;
  } else {
    const auto no_unacknowledged = bytes_.flight_size() == 0U;
    const auto nagle_allows_small = !nagle_enabled_ || no_unacknowledged;
    const auto half_maximum_window =
        maximum_receiver_window_ / 2U + maximum_receiver_window_ % 2U;
    if (pushed && nagle_allows_small && unsent <= allowance)
      payload = unsent;
    else if (nagle_allows_small && maximum_receiver_window_ != 0U &&
             available >= half_maximum_window)
      payload = available;
    else if (pushed) {
      if (!sws_override_deadline_)
        sws_override_deadline_ = now + device_catalog::tcp_sws_override;
      if (now >= *sws_override_deadline_)
        payload = available;
    }
  }
  if (payload == 0U)
    return {};
  const auto range = bytes_.prepare_new(payload);
  // Exhaustion of the caller-sized segment ledger is backpressure before IP
  // admission. No transmitted data may become invisible to R1, R2 or SACK.
  if (!history_.can_record_original(range.sequence,
                                    range.sequence + range.length, now))
    return {};
  return {.range = range,
          .reason = TransmissionReason::new_data,
          .sender_generation = generation_};
}

PreparedTransmission
Sender::prepare_persist_probe(Clock::time_point now) noexcept {
  if (!valid_)
    return {};
  persist_.update(receiver_window_ == 0U, bytes_.queued_octets() != 0U,
                  retransmission_.timeout(), now);
  if (!persist_.due(now))
    return {};
  const auto range = bytes_.flight_size() == 0U
                         ? bytes_.prepare_new(1U)
                         : bytes_.prepare_retransmission(1U);
  return {.range = range,
          .reason = TransmissionReason::persist_probe,
          .sender_generation = generation_};
}

PreparedTransmission
Sender::prepare_sack_recovery(Clock::time_point now) noexcept {
  if (!valid_ || !sack_enabled_ || !sack_.in_recovery())
    return {};
  const auto estimated_pipe = sack_.pipe();
  if (congestion_.congestion_window() < estimated_pipe ||
      congestion_.congestion_window() - estimated_pipe < sender_mss_)
    return {};

  std::optional<SackRange> unsent;
  const auto window_end =
      bytes_.send_unacknowledged() + receiver_window_;
  if (bytes_.unsent_octets() != 0U &&
      sequence::before(bytes_.send_next(), window_end)) {
    const auto allowed = std::min(bytes_.unsent_octets(),
                                  window_end - bytes_.send_next());
    if (allowed != 0U)
      unsent = SackRange{.first = bytes_.send_next(),
                         .end = bytes_.send_next() + allowed};
  }
  const auto selected = sack_.next_segment(unsent);
  if (!selected)
    return {};
  const auto length = selected.range.end - selected.range.first;
  const auto range = selected.reason == SackNextReason::new_data
                         ? bytes_.prepare_new(length)
                         : bytes_.prepare_retransmission_at(
                               selected.range.first, length);
  if (!range || range.sequence != selected.range.first ||
      range.length != length)
    return {};
  const bool can_record =
      selected.reason == SackNextReason::new_data
          ? history_.can_record_original(range.sequence,
                                         range.sequence + range.length, now)
          : history_.can_record_retransmission(
                range.sequence, range.sequence + range.length, now);
  if (!can_record)
    return {};
  return {.range = range,
          .reason = TransmissionReason::sack_recovery,
          .sack_reason = selected.reason,
          .sender_generation = generation_};
}

PreparedTransmission Sender::prepare_fast_retransmission() const noexcept {
  if (!valid_ || !fast_retransmission_pending_)
    return {};
  return {.range = bytes_.prepare_retransmission(sender_mss_),
          .reason = TransmissionReason::fast_retransmit,
          .sender_generation = generation_};
}

PreparedTransmission Sender::prepare_timeout_retransmission(
    Clock::time_point now) const noexcept {
  if (!valid_ || !retransmission_deadline_ ||
      now < *retransmission_deadline_ ||
      failure_.service(now) == FailureAction::abort_connection)
    return {};
  const auto range = bytes_.prepare_retransmission(sender_mss_);
  if (!history_.can_record_retransmission(
          range.sequence, range.sequence + range.length, now))
    return {};
  return {.range = range,
          .reason = TransmissionReason::timeout_retransmit,
          .sender_generation = generation_};
}

std::optional<Sender::Clock::time_point> Sender::next_deadline() const noexcept {
  // All three deadlines are local to this connection. Returning their minimum
  // lets the owning shard sleep without polling and does not create a global
  // simulated event queue or change any timer state.
  auto result = retransmission_deadline_;
  const auto select = [&result](std::optional<Clock::time_point> candidate) {
    if (candidate && (!result || *candidate < *result))
      result = candidate;
  };
  select(persist_.deadline());
  select(sws_override_deadline_);
  return result;
}

bool Sender::current(const PreparedTransmission &intent) const noexcept {
  if (!intent || intent.sender_generation != generation_)
    return false;
  switch (intent.reason) {
  case TransmissionReason::new_data:
    return !intent.range.retransmission;
  case TransmissionReason::fast_retransmit:
    return intent.range.retransmission && fast_retransmission_pending_;
  case TransmissionReason::timeout_retransmit:
    return intent.range.retransmission && retransmission_deadline_.has_value();
  case TransmissionReason::persist_probe:
    return persist_.deadline().has_value();
  case TransmissionReason::sack_recovery:
    return sack_enabled_ && sack_.in_recovery();
  }
  return false;
}

bool Sender::copy(const PreparedTransmission &intent,
                  std::span<std::uint8_t> output) const noexcept {
  return current(intent) && bytes_.copy(intent.range, output);
}

void Sender::start_or_restart_timer(Clock::time_point now) noexcept {
  retransmission_deadline_ = now + retransmission_.timeout();
}

void Sender::mark_rtt_retransmitted(
    const PreparedSendRange &range) noexcept {
  if (!rtt_probe_present_)
    return;
  // Every repair currently begins at SND.UNA. If its range reaches any part
  // of the measured sequence interval, Karn's algorithm makes that sample
  // ambiguous unless a later timestamp echo identifies the transmission.
  const auto repair_end = range.sequence + range.length;
  if (sequence::after(repair_end, bytes_.send_unacknowledged()) &&
      sequence::after(rtt_sequence_end_, range.sequence))
    rtt_probe_retransmitted_ = true;
}

bool Sender::commit(const PreparedTransmission &intent,
                    Clock::time_point now) noexcept {
  if (!current(intent) ||
      (intent.reason == TransmissionReason::timeout_retransmit &&
       (!retransmission_deadline_ || now < *retransmission_deadline_)) ||
      (intent.reason == TransmissionReason::persist_probe &&
       !persist_.due(now)))
    return false;
  const auto previous_flight = bytes_.flight_size();
  const auto range_end = intent.range.sequence + intent.range.length;
  if (intent.reason == TransmissionReason::new_data &&
      !history_.can_record_original(intent.range.sequence, range_end, now))
    return false;
  if ((intent.reason == TransmissionReason::fast_retransmit ||
       intent.reason == TransmissionReason::timeout_retransmit) &&
      !history_.can_record_retransmission(intent.range.sequence, range_end,
                                          now))
    return false;
  if (intent.reason == TransmissionReason::persist_probe &&
      ((!intent.range.retransmission &&
        !history_.can_record_original(intent.range.sequence, range_end, now)) ||
       (intent.range.retransmission &&
        !history_.can_record_retransmission(intent.range.sequence, range_end,
                                            now))))
    return false;
  if (intent.reason == TransmissionReason::sack_recovery &&
      ((!intent.range.retransmission &&
        !history_.can_record_original(intent.range.sequence, range_end, now)) ||
       (intent.range.retransmission &&
        !history_.can_record_retransmission(intent.range.sequence, range_end,
                                            now))))
    return false;
  if (!bytes_.commit(intent.range))
    return false;

  switch (intent.reason) {
  case TransmissionReason::new_data:
    if (!history_.record_original(intent.range.sequence, range_end, now)) {
      valid_ = false;
      pending_failure_action_ = FailureAction::abort_connection;
      return false;
    }
    if (sack_.update(bytes_.send_unacknowledged(), bytes_.send_next(), {}) ==
        SackUpdateStatus::malformed) {
      valid_ = false;
      pending_failure_action_ = FailureAction::abort_connection;
      return false;
    }
    if (previous_flight == 0U)
      static_cast<void>(failure_.begin(intent.range.sequence, range_end, false,
                                       now));
    if (!rtt_probe_present_) {
      rtt_sequence_end_ = intent.range.sequence + intent.range.length;
      rtt_sent_at_ = now;
      rtt_probe_present_ = true;
      rtt_probe_retransmitted_ = false;
    }
    // RFC 6298 section 5.1 starts the timer only when data is actually sent
    // and no timer is running. Additional packets keep the original deadline.
    if (previous_flight == 0U)
      start_or_restart_timer(now);
    sws_override_deadline_.reset();
    break;
  case TransmissionReason::fast_retransmit:
    if (history_.record_retransmission(intent.range.sequence, range_end, now) ==
        0U) {
      valid_ = false;
      pending_failure_action_ = FailureAction::abort_connection;
      return false;
    }
    if (const auto action = failure_.retransmitted(
            intent.range.sequence, range_end, now);
        action == FailureAction::abort_connection ||
        (action == FailureAction::negative_ip_advice &&
         pending_failure_action_ == FailureAction::none))
      pending_failure_action_ = action;
    mark_rtt_retransmitted(intent.range);
    fast_retransmission_pending_ = false;
    break;
  case TransmissionReason::timeout_retransmit:
    if (history_.record_retransmission(intent.range.sequence, range_end, now) ==
        0U) {
      valid_ = false;
      pending_failure_action_ = FailureAction::abort_connection;
      return false;
    }
    if (const auto action = failure_.retransmitted(
            intent.range.sequence, range_end, now);
        action == FailureAction::abort_connection ||
        (action == FailureAction::negative_ip_advice &&
         pending_failure_action_ == FailureAction::none))
      pending_failure_action_ = action;
    mark_rtt_retransmitted(intent.range);
    congestion_.on_retransmission_timeout(previous_flight);
    sack_.on_retransmission_timeout();
    static_cast<void>(retransmission_.on_timeout(false));
    start_or_restart_timer(now);
    fast_retransmission_pending_ = false;
    break;
  case TransmissionReason::persist_probe:
    if (intent.range.retransmission) {
      if (history_.record_retransmission(intent.range.sequence, range_end,
                                         now) == 0U) {
        valid_ = false;
        pending_failure_action_ = FailureAction::abort_connection;
        return false;
      }
    } else if (!history_.record_original(intent.range.sequence, range_end,
                                         now)) {
      valid_ = false;
      pending_failure_action_ = FailureAction::abort_connection;
      return false;
    }
    if (!intent.range.retransmission &&
        sack_.update(bytes_.send_unacknowledged(), bytes_.send_next(), {}) ==
            SackUpdateStatus::malformed) {
      valid_ = false;
      pending_failure_action_ = FailureAction::abort_connection;
      return false;
    }
    mark_rtt_retransmitted(intent.range);
    if (!persist_.probe_committed(now))
      return false;
    // Persist probes test only the receive window. They neither back off the
    // data RTO nor reduce cwnd, and their one byte may remain unacknowledged.
    sws_override_deadline_.reset();
    break;
  case TransmissionReason::sack_recovery: {
    const SackNextSegment selected{
        .range = {.first = intent.range.sequence, .end = range_end},
        .reason = intent.sack_reason};
    const bool history_recorded = intent.range.retransmission
                                      ? history_.record_retransmission(
                                            intent.range.sequence, range_end,
                                            now) != 0U
                                      : history_.record_original(
                                            intent.range.sequence, range_end,
                                            now);
    if (!history_recorded || !sack_.commit(selected)) {
      valid_ = false;
      pending_failure_action_ = FailureAction::abort_connection;
      return false;
    }
    if (intent.range.retransmission) {
      if (const auto action = failure_.retransmitted(
              intent.range.sequence, range_end, now);
          action == FailureAction::abort_connection ||
          (action == FailureAction::negative_ip_advice &&
           pending_failure_action_ == FailureAction::none))
        pending_failure_action_ = action;
      mark_rtt_retransmitted(intent.range);
    } else if (previous_flight == 0U) {
      static_cast<void>(failure_.begin(intent.range.sequence, range_end, false,
                                       now));
      start_or_restart_timer(now);
    }
    break;
  }
  }
  ++generation_;
  return true;
}

SenderAcknowledgeResult Sender::acknowledge(
    std::uint32_t acknowledgment, std::uint32_t receiver_window,
    bool duplicate_ack_eligible, Clock::time_point now,
    std::optional<Clock::duration> timestamp_rtt,
    std::span<const SackBlock> sack_blocks) noexcept {
  if (!valid_)
    return {};
  const auto acknowledged = bytes_.acknowledge(acknowledgment);
  const bool sack_was_recovering = sack_.in_recovery();
  bool new_sack_information{};
  if (acknowledged.status != SendAcknowledgeStatus::beyond_sent &&
      acknowledged.status != SendAcknowledgeStatus::invalid) {
    auto sack_status = sack_.update(
        acknowledgment, bytes_.send_next(),
        sack_enabled_ ? sack_blocks : std::span<const SackBlock>{});
    if (sack_status == SackUpdateStatus::malformed ||
        sack_status == SackUpdateStatus::capacity_exhausted) {
      // SACK is advisory. An invalid or locally unrepresentable block cannot
      // veto a valid cumulative ACK, so advance HighACK without those blocks.
      sack_status = sack_.update(acknowledgment, bytes_.send_next(), {});
    }
    new_sack_information =
        sack_status != SackUpdateStatus::malformed &&
        sack_status != SackUpdateStatus::capacity_exhausted &&
        sack_.last_update_added_sack();
  }
  // An ACK beyond SND.NXT is unacceptable and therefore cannot update SND.WND.
  // The endpoint will answer it with the current ACK before discarding it.
  if (acknowledged.status != SendAcknowledgeStatus::beyond_sent &&
      acknowledged.status != SendAcknowledgeStatus::invalid) {
    receiver_window_ = receiver_window;
    maximum_receiver_window_ = std::max(maximum_receiver_window_, receiver_window);
  }
  if (acknowledged.status == SendAcknowledgeStatus::advanced) {
    history_.acknowledge(acknowledgment);
    failure_.acknowledge(acknowledgment);
    // Moving to another oldest segment retains its true first-transmission
    // time. Starting from ACK arrival would incorrectly extend the R2 horizon.
    if (!failure_.active() && receiver_window_ != 0U)
      if (const auto oldest = history_.oldest())
        static_cast<void>(failure_.begin(
            oldest->first, oldest->end, false,
            oldest->first_transmitted_at));
    if (sack_was_recovering)
      congestion_.on_sack_ack(!sack_.in_recovery());
    else
      congestion_.on_new_ack(acknowledged.newly_acknowledged);
    fast_retransmission_pending_ = false;

    if (timestamp_rtt) {
      // A timestamp echo identifies the actual transmission and removes the
      // ambiguity that would otherwise make a retransmitted sample unusable.
      static_cast<void>(
          retransmission_.observe(*timestamp_rtt, true, true));
    }
    if (rtt_probe_present_ &&
        !sequence::before(acknowledgment, rtt_sequence_end_)) {
      if (!timestamp_rtt)
        static_cast<void>(retransmission_.observe(
            now - rtt_sent_at_, rtt_probe_retransmitted_, false));
      rtt_probe_present_ = false;
      rtt_probe_retransmitted_ = false;
    }

    if (bytes_.flight_size() == 0U) {
      retransmission_deadline_.reset();
      rtt_probe_present_ = false;
    } else {
      // RFC 6298 section 5.3 restarts the timer when an ACK advances SND.UNA.
      start_or_restart_timer(now);
    }
    ++generation_;
  } else if (acknowledged.status == SendAcknowledgeStatus::duplicate &&
             !sack_enabled_ && duplicate_ack_eligible &&
             bytes_.flight_size() != 0U) {
    if (congestion_.on_duplicate_ack(bytes_.flight_size()) ==
        DuplicateAckAction::retransmit_oldest)
      fast_retransmission_pending_ = true;
    ++generation_;
  }
  if (sack_enabled_ && new_sack_information &&
      bytes_.flight_size() != 0U && !sack_.in_recovery() &&
      sack_.duplicate_ack(true)) {
    sack_.enter_recovery();
    congestion_.enter_sack_recovery(bytes_.flight_size());
    fast_retransmission_pending_ = false;
    ++generation_;
  }
  persist_.update(receiver_window_ == 0U, bytes_.queued_octets() != 0U,
                  retransmission_.timeout(), now);
  return {.status = acknowledged.status,
          .newly_acknowledged = acknowledged.newly_acknowledged,
          .fast_retransmission_ready = fast_retransmission_pending_,
          .sack_recovery_ready = sack_.in_recovery()};
}

FailureAction Sender::failure_action(Clock::time_point now) const noexcept {
  // A time-based R2 outranks an unconsumed earlier R1 notification. The owner
  // must close the connection instead of first attempting dead-gateway advice.
  const auto timed = failure_.service(now);
  return timed == FailureAction::abort_connection
             ? timed
             : pending_failure_action_;
}

FailureAction Sender::take_failure_action(Clock::time_point now) noexcept {
  const auto action = failure_action(now);
  if (action != FailureAction::none)
    pending_failure_action_ = FailureAction::none;
  return action;
}

SenderCheckpoint Sender::checkpoint(Clock::time_point now) const {
  const auto remaining = retransmission_deadline_ &&
                                 *retransmission_deadline_ > now
                             ? *retransmission_deadline_ - now
                             : Clock::duration::zero();
  const auto probe_age = rtt_probe_present_ && now >= rtt_sent_at_
                             ? now - rtt_sent_at_
                             : Clock::duration::zero();
  const auto sws_remaining = sws_override_deadline_ &&
                                     *sws_override_deadline_ > now
                                 ? *sws_override_deadline_ - now
                                 : Clock::duration::zero();
  return {.bytes = bytes_.checkpoint(),
          .history = history_.checkpoint(now),
          .failure = failure_.checkpoint(now),
          .sack = sack_.checkpoint(),
          .congestion = congestion_.checkpoint(),
          .retransmission = retransmission_.checkpoint(),
          .persist = persist_.checkpoint(now),
          .receiver_window = receiver_window_,
          .maximum_receiver_window = maximum_receiver_window_,
          .rtt_sequence_end = rtt_sequence_end_,
          .retransmission_remaining_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                  .count(),
          .rtt_probe_age_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(probe_age)
                  .count(),
          .sws_override_remaining_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  sws_remaining)
                  .count(),
          .generation = generation_,
          .pending_failure_action = pending_failure_action_,
          .retransmission_deadline_present =
              retransmission_deadline_.has_value(),
          .rtt_probe_present = rtt_probe_present_,
          .rtt_probe_retransmitted = rtt_probe_retransmitted_,
          .fast_retransmission_pending = fast_retransmission_pending_,
          .sws_override_deadline_present =
              sws_override_deadline_.has_value(),
          .nagle_enabled = nagle_enabled_,
          .sack_enabled = sack_enabled_};
}

bool Sender::restore(const SenderCheckpoint &state,
                     Clock::time_point now) noexcept {
  if (!valid_ || state.generation == 0U ||
      state.retransmission_remaining_nanoseconds < 0 ||
      state.rtt_probe_age_nanoseconds < 0 ||
      state.sws_override_remaining_nanoseconds < 0 ||
      (!state.retransmission_deadline_present &&
       state.retransmission_remaining_nanoseconds != 0) ||
      (!state.sws_override_deadline_present &&
       state.sws_override_remaining_nanoseconds != 0) ||
      (!state.rtt_probe_present &&
       (state.rtt_probe_age_nanoseconds != 0 ||
        state.rtt_probe_retransmitted)) ||
      static_cast<std::uint8_t>(state.pending_failure_action) >
          static_cast<std::uint8_t>(FailureAction::abort_connection) ||
      !CongestionController::validate_checkpoint(state.congestion) ||
      !RetransmissionEstimator::validate_checkpoint(state.retransmission) ||
      !FailureDetector::validate_checkpoint(state.failure) ||
      !SackScoreboard::validate_checkpoint(state.sack, sack_.capacity()) ||
      !TransmissionHistory::validate_checkpoint(
          state.history, history_.capacity(), now))
    return false;
  if (state.congestion.sender_mss != sender_mss_)
    return false;
  if (state.bytes.storage.size() != bytes_.capacity() ||
      state.bytes.head >= state.bytes.storage.size() ||
      state.bytes.generation == 0U)
    return false;
  const auto saved_flight =
      state.bytes.send_next - state.bytes.send_unacknowledged;
  const auto saved_queued =
      state.bytes.write_next - state.bytes.send_unacknowledged;
  const bool history_matches_flight =
      saved_flight == 0U
          ? state.history.records.empty()
          : !state.history.records.empty() &&
                state.history.records.front().first ==
                    state.bytes.send_unacknowledged &&
                state.history.records.back().end == state.bytes.send_next;
  const bool failure_matches_window =
      saved_flight == 0U || state.receiver_window == 0U
          ? !state.failure.active
          : state.failure.active && !state.history.records.empty() &&
                state.failure.segment_first ==
                    state.history.records.front().first &&
                state.failure.segment_end == state.history.records.front().end;
  if (saved_flight > saved_queued ||
      saved_queued > state.bytes.storage.size() ||
      !history_matches_flight || !failure_matches_window ||
      state.sack.high_ack != state.bytes.send_unacknowledged ||
      state.sack.high_data_end != state.bytes.send_next ||
      state.sack.recovery != state.congestion.sack_recovery ||
      (!state.sack_enabled &&
       (state.sack.recovery || !state.sack.ranges.empty())) ||
      state.maximum_receiver_window < state.receiver_window ||
      (saved_flight == 0U && state.retransmission_deadline_present) ||
      (saved_flight != 0U && !state.retransmission_deadline_present &&
       !state.persist.active) ||
      (state.sws_override_deadline_present &&
       state.bytes.send_next == state.bytes.write_next) ||
      (state.fast_retransmission_pending &&
       (!state.congestion.fast_recovery || saved_flight == 0U)) ||
      (state.rtt_probe_present &&
       (saved_flight == 0U ||
        sequence::after(state.rtt_sequence_end, state.bytes.send_next))))
    return false;
  const auto age = std::chrono::nanoseconds{state.rtt_probe_age_nanoseconds};
  if (age > now.time_since_epoch())
    return false;
  PersistTimer restored_persist;
  FailureDetector restored_failure;
  if (!restored_persist.restore(state.persist, now) ||
      !restored_failure.restore(state.failure, now))
    return false;
  if (!bytes_.restore(state.bytes) || !congestion_.restore(state.congestion) ||
      !retransmission_.restore(state.retransmission) ||
      !history_.restore(state.history, now) || !sack_.restore(state.sack))
    return false;
  persist_ = restored_persist;
  failure_ = restored_failure;
  receiver_window_ = state.receiver_window;
  maximum_receiver_window_ = state.maximum_receiver_window;
  rtt_sequence_end_ = state.rtt_sequence_end;
  generation_ = state.generation;
  pending_failure_action_ = state.pending_failure_action;
  rtt_probe_present_ = state.rtt_probe_present;
  rtt_probe_retransmitted_ = state.rtt_probe_retransmitted;
  fast_retransmission_pending_ = state.fast_retransmission_pending;
  nagle_enabled_ = state.nagle_enabled;
  sack_enabled_ = state.sack_enabled;
  rtt_sent_at_ = now - age;
  retransmission_deadline_ = state.retransmission_deadline_present
                                 ? std::optional{now + std::chrono::nanoseconds{
                                                           state.retransmission_remaining_nanoseconds}}
                                 : std::nullopt;
  sws_override_deadline_ = state.sws_override_deadline_present
                               ? std::optional{
                                     now + std::chrono::nanoseconds{
                                               state.sws_override_remaining_nanoseconds}}
                               : std::nullopt;
  return true;
}

} // namespace router::transport::tcp
