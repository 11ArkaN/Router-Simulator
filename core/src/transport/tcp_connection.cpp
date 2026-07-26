// TCP four-tuple handshake, option negotiation and transactional control
// transmission. The state machine is copied into a private candidate so even
// SYN, FIN and retransmission deadlines remain unchanged until queue admission.

#include "router/tcp_connection.hpp"

#include "router/ip_address.hpp"

#include <algorithm>

namespace router::transport::tcp {
namespace {

[[nodiscard]] bool has(std::uint8_t flags,
                       packet::tcp::Flag flag) noexcept {
  return (flags & static_cast<std::uint8_t>(flag)) != 0U;
}

[[nodiscard]] bool zero(const packet::Ipv4 &address) noexcept {
  return std::all_of(address.begin(), address.end(),
                     [](std::uint8_t octet) { return octet == 0U; });
}

} // namespace

Connection::Connection(const ConnectionTuple &tuple,
                       const ConnectionOptionPolicy &policy,
                       const ConnectionStorage &storage,
                       Clock::time_point timestamp_origin) noexcept
    : tuple_(tuple), policy_(policy), storage_(storage),
      timestamp_origin_(timestamp_origin),
      control_(tuple.local_port, tuple.remote_port, policy.receive_capacity,
               default_send_mss(tuple.family)),
      valid_(tuple_valid() && storage_valid() &&
             make_syn_offer(policy.maximum_transport_message,
                            policy.receive_capacity, policy.window_scaling,
                            policy.timestamps, policy.sack, 0U)
                 .has_value()) {}

bool Connection::storage_valid() const noexcept {
  // ReceiveBuffer validates the same bitmap relationship again at ownership
  // construction. Checking here prevents a connection from completing its
  // handshake and only then discovering that advertised storage never existed.
  return !storage_.send_bytes.empty() && !storage_.receive_bytes.empty() &&
         storage_.receive_bytes.size() <= 0x40000000U &&
         storage_.receive_bitmap.size() >=
             (storage_.receive_bytes.size() + 7U) / 8U &&
         !storage_.transmit_payload_scratch.empty() &&
         !storage_.transmission_history.empty() &&
         !storage_.sack_ranges.empty() &&
         storage_.sack_ranges.size() == storage_.sack_workspace.size() &&
         policy_.receive_capacity == storage_.receive_bytes.size();
}

bool Connection::tuple_valid() const noexcept {
  if (tuple_.local_port == 0U)
    return false;
  if (tuple_.family == InternetFamily::ipv4)
    return !zero(tuple_.local_ipv4) && !zero(tuple_.remote_ipv4);
  // Link-local TCP needs a stable RFC 4007 zone. Global IPv6 tuples keep a
  // zero interface ID because their address is unambiguous outside one link.
  if (ip::is_unspecified(tuple_.local_ipv6) ||
      ip::is_unspecified(tuple_.remote_ipv6) ||
      ip::is_multicast(tuple_.local_ipv6) ||
      ip::is_multicast(tuple_.remote_ipv6))
    return false;
  return (!ip::is_link_local(tuple_.local_ipv6) &&
          !ip::is_link_local(tuple_.remote_ipv6)) ||
         tuple_.interface_id != 0U;
}

SynOptionOffer Connection::offer(Clock::time_point now) const noexcept {
  auto value = *make_syn_offer(
      policy_.maximum_transport_message, policy_.receive_capacity,
      policy_.window_scaling, policy_.timestamps, policy_.sack,
      timestamp_value(now, timestamp_origin_, policy_.timestamp_offset));
  return value;
}

bool Connection::listen() noexcept {
  // LISTEN has no network output, so it needs no admission transaction. A
  // listener still has no remote port until an encoded SYN is received.
  return valid_ && !pending_ && !control_.passive_open().emit &&
         control_.state() == State::listen;
}

std::optional<std::size_t> Connection::encode(
    packet::tcp::Fields fields,
    const std::optional<SynOptionOffer> &local_offer,
    const std::optional<NegotiatedOptions> &negotiated,
    const TimestampState &timestamps, bool timestamp_state_present,
    std::span<const std::uint8_t> payload,
    std::span<std::uint8_t> output, Clock::time_point now) const noexcept {
  std::array<std::uint8_t, packet::tcp::maximum_option_octets> option_bytes{};
  std::size_t option_octets{};
  const bool syn_segment = has(fields.flags, packet::tcp::syn);

  if (syn_segment) {
    if (!local_offer)
      return std::nullopt;
    const auto encoded = encode_syn_options(option_bytes, *local_offer);
    if (!encoded)
      return std::nullopt;
    option_octets = *encoded;
  } else if (negotiated && negotiated->timestamps) {
    if (!timestamp_state_present)
      return std::nullopt;
    const auto timestamp = encode_timestamp_option(
        timestamp_value(now, timestamp_origin_, policy_.timestamp_offset),
        timestamps.echo_reply());
    std::copy(timestamp.begin(), timestamp.end(), option_bytes.begin());
    option_octets = timestamp.size();
  }

  if (!syn_segment && negotiated && negotiated->sack && receiver_) {
    // Timestamp consumes ten option octets. At most three SACK blocks then fit
    // under TCP's 40-octet option ceiling; without timestamps all four fit.
    std::array<SackBlock, 4> blocks{};
    const auto block_limit = negotiated->timestamps ? 3U : blocks.size();
    const auto block_count = receiver_->sack_blocks(
        std::span<SackBlock>{blocks}.first(block_limit));
    if (block_count != 0U) {
      const auto sack_size = encode_sack_option(
          std::span<std::uint8_t>{option_bytes}.subspan(option_octets),
          std::span<const SackBlock>{blocks}.first(block_count));
      if (!sack_size)
        return std::nullopt;
      option_octets += *sack_size;
    }
  }

  // Scaling never applies to SYN. All later packets use the negotiated local
  // shift, including pure ACK, FIN and retransmitted control segments.
  const auto receive_window = receive_window_
                                  ? receive_window_->advertised()
                                  : policy_.receive_capacity;
  if (negotiated)
    fields.window = encode_receive_window(receive_window,
                                          syn_segment, *negotiated);
  else
    fields.window = static_cast<std::uint16_t>(
        std::min(receive_window, 65535U));

  const auto options = std::span<const std::uint8_t>{option_bytes}.first(
      option_octets);
  if (tuple_.family == InternetFamily::ipv4)
    return packet::tcp::encode_ipv4(output, tuple_.local_ipv4,
                                    tuple_.remote_ipv4, fields, options, payload);
  return packet::tcp::encode_ipv6(output, tuple_.local_ipv6,
                                  tuple_.remote_ipv6, fields, options, payload);
}

ConnectionPrepareResult Connection::stage(
    ControlBlock candidate, const ControlResult &result,
    std::optional<SynOptionOffer> candidate_local_offer,
    std::optional<TypedOptions> candidate_peer_options,
    std::optional<NegotiatedOptions> candidate_negotiated,
    TimestampState candidate_timestamps, bool timestamp_state_present,
    std::span<std::uint8_t> output, Clock::time_point now) noexcept {
  if (pending_)
    return {.status = ConnectionPrepareStatus::pending_transmission};

  std::size_t octets{};
  if (result.emit) {
    const auto encoded = encode(result.segment, candidate_local_offer,
                                candidate_negotiated, candidate_timestamps,
                                timestamp_state_present, {}, output, now);
    if (!encoded)
      return {.status = ConnectionPrepareStatus::output_too_small};
    octets = *encoded;
  }

  auto token = next_token_++;
  if (token == 0U)
    token = next_token_++;
  pending_.emplace(PendingTransition{
      .control = std::move(candidate),
      .local_syn_offer = candidate_local_offer,
      .peer_syn_options = candidate_peer_options,
      .negotiated = candidate_negotiated,
      .timestamps = candidate_timestamps,
      .sender = sender_,
      .emitted_fields = result.segment,
      .token = token,
      .event = result.event,
      .timestamp_state_present = timestamp_state_present,
      .sender_transmission_present = false,
      .emitted = result.emit});
  return {.status = ConnectionPrepareStatus::prepared,
          .segment = {.token = token,
                      .octets = octets,
                      .event = result.event,
                      .emit = result.emit}};
}

ConnectionPrepareResult Connection::prepare_active_open(
    std::uint32_t initial_sequence, std::span<std::uint8_t> output,
    Clock::time_point now) noexcept {
  if (!valid_)
    return {.status = ConnectionPrepareStatus::invalid_connection};
  if (pending_)
    return {.status = ConnectionPrepareStatus::pending_transmission};
  auto candidate = control_;
  const auto result = candidate.active_open(initial_sequence, now);
  if (!result.emit)
    return {.status = ConnectionPrepareStatus::wrong_state};
  const auto local_offer = offer(now);
  return stage(std::move(candidate), result, local_offer, std::nullopt,
               std::nullopt, timestamps_, false, output, now);
}

ConnectionPrepareResult Connection::prepare_ingress(
    std::span<const std::uint8_t> segment,
    std::uint32_t passive_initial_sequence,
    std::span<std::uint8_t> output, Clock::time_point now) noexcept {
  if (!valid_)
    return {.status = ConnectionPrepareStatus::invalid_connection};
  if (pending_)
    return {.status = ConnectionPrepareStatus::pending_transmission};
  const auto parsed = tuple_.family == InternetFamily::ipv4
                          ? packet::tcp::parse_ipv4(
                                segment, tuple_.remote_ipv4, tuple_.local_ipv4)
                          : packet::tcp::parse_ipv6(
                                segment, tuple_.remote_ipv6, tuple_.local_ipv6);
  if (!parsed || parsed->source_port != tuple_.remote_port ||
      parsed->destination_port != tuple_.local_port)
    return {.status = ConnectionPrepareStatus::malformed_segment};
  const auto typed = parse_typed_options(parsed->options);
  if (!typed)
    return {.status = ConnectionPrepareStatus::malformed_segment};

  auto candidate = control_;
  auto candidate_local = local_syn_offer_;
  auto candidate_peer = peer_syn_options_;
  auto candidate_negotiated = negotiated_;
  auto candidate_timestamps = timestamps_;
  auto candidate_timestamp_present = timestamp_state_present_;
  const auto before = control_.state();
  const bool syn_segment = has(parsed->flags, packet::tcp::syn);
  const bool reset_segment = has(parsed->flags, packet::tcp::rst);

  if (syn_segment && before == State::listen) {
    candidate_peer = *typed;
    auto response_offer = offer(now);
    // RFC 7323 permits WS and TS in SYN,ACK only after the initial SYN offered
    // them. SACK-permitted is likewise bilateral capability negotiation.
    response_offer.offer_window_scale = typed->window_scale.has_value() &&
                                         response_offer.offer_window_scale;
    response_offer.offer_timestamps = typed->timestamp_value.has_value() &&
                                      response_offer.offer_timestamps;
    response_offer.offer_sack = typed->sack_permitted &&
                                response_offer.offer_sack;
    response_offer.timestamp_echo_reply =
        typed->timestamp_value.value_or(0U);
    candidate_local = response_offer;
    candidate_negotiated =
        negotiate_options(tuple_.family, response_offer, *typed);
    candidate_timestamps = TimestampState{candidate_negotiated->timestamps};
    candidate_timestamp_present = candidate_negotiated->timestamps;
    if (candidate_timestamp_present)
      static_cast<void>(candidate_timestamps.accept(
          false, typed->timestamp_value, parsed->sequence, now));
  } else if (syn_segment && before == State::syn_sent && candidate_local) {
    candidate_peer = *typed;
    candidate_negotiated =
        negotiate_options(tuple_.family, *candidate_local, *typed);
    candidate_timestamps = TimestampState{candidate_negotiated->timestamps};
    candidate_timestamp_present = candidate_negotiated->timestamps;
    if (candidate_timestamp_present)
      static_cast<void>(candidate_timestamps.accept(
          false, typed->timestamp_value, parsed->sequence, now));
  } else if (candidate_negotiated && candidate_negotiated->timestamps) {
    const auto accepted = candidate_timestamps.accept(
        reset_segment, typed->timestamp_value, parsed->sequence, now);
    if (accepted == TimestampAccept::missing_required)
      return {.status = ConnectionPrepareStatus::missing_timestamp};
    if (accepted == TimestampAccept::stale) {
      // PAWS treats a stale segment as unacceptable and sends the current ACK
      // without allowing its ACK field, payload or controls to mutate the TCB.
      return stage(control_, control_.current_acknowledgment(),
                   candidate_local, candidate_peer, candidate_negotiated,
                   timestamps_, timestamp_state_present_, output, now);
    }
  }

  const auto decoded_window = candidate_negotiated
                                  ? decode_peer_window(parsed->window,
                                                       syn_segment,
                                                       *candidate_negotiated)
                                  : parsed->window;
  const auto result = candidate.on_segment(*parsed, passive_initial_sequence,
                                           now, decoded_window);

  const bool stream_state = sender_ && receiver_ && receive_window_ &&
                            before != State::listen &&
                            before != State::syn_sent &&
                            before != State::syn_received;
  if (stream_state) {
    auto candidate_sender = *sender_;
    if (has(parsed->flags, packet::tcp::ack)) {
      // RFC 5681 duplicate ACK eligibility includes no payload, no SND.UNA
      // advance and an unchanged advertised window. SACK blocks are advisory
      // input to RFC 6675 but never bypass the cumulative ACK validation.
      const auto duplicate = parsed->payload.empty() &&
                             parsed->acknowledgment ==
                                 control_.send_unacknowledged() &&
                             decoded_window == control_.send_window();
      std::optional<Clock::duration> timestamp_rtt;
      if (candidate_negotiated && candidate_negotiated->timestamps &&
          typed->timestamp_echo_reply) {
        const auto current = timestamp_value(
            now, timestamp_origin_, policy_.timestamp_offset);
        timestamp_rtt = std::chrono::milliseconds{
            static_cast<std::uint32_t>(
                current - *typed->timestamp_echo_reply)};
      }
      const auto acknowledgment = candidate_sender.acknowledge(
          parsed->acknowledgment, decoded_window, duplicate, now,
          timestamp_rtt,
          std::span<const SackBlock>{typed->sack_blocks}.first(
              typed->sack_block_count));
      if (acknowledgment.status == SendAcknowledgeStatus::beyond_sent ||
          acknowledgment.status == SendAcknowledgeStatus::invalid) {
        // The TCB has already selected the standards-required corrective ACK.
        // Do not let an invalid cumulative value alter sender byte ownership.
        candidate_sender = *sender_;
      }
    }

    auto candidate_receiver = *receiver_;
    auto candidate_receive_window = *receive_window_;
    auto candidate_delayed_ack = delayed_ack_;
    auto response = result;
    if (result.event == ControlEvent::data_requires_stream_owner) {
      const auto old_next = candidate_receiver.receive_next();
      const auto insertion = candidate_receiver.accept(parsed->sequence,
                                                        parsed->payload);
      const auto advanced = insertion.receive_next - old_next;
      candidate_receive_window.receive_next_advanced(advanced);
      const auto fin_sequence = has(parsed->flags, packet::tcp::fin)
                                    ? std::optional{
                                          parsed->sequence +
                                          static_cast<std::uint32_t>(
                                              parsed->payload.size())}
                                    : std::nullopt;
      const auto committed = candidate.commit_received_data(
          insertion.receive_next, candidate_receive_window.advertised(),
          fin_sequence, now);
      if (!committed)
        return {.status =
                    ConnectionPrepareStatus::payload_requires_stream_owner};
      response = *committed;
      // A segment beginning at RCV.NXT can also close a hole and release bytes
      // that arrived earlier out of order. Delaying that ACK would hide the
      // cumulative recovery point from the sender. Only an advance contributed
      // entirely by this segment is the ordinary first in-order segment case.
      const auto in_order = parsed->sequence == old_next && advanced != 0U &&
                            advanced == parsed->payload.size();
      const auto schedule = candidate_delayed_ack.on_segment(
          in_order, static_cast<std::uint32_t>(parsed->payload.size()),
          has(parsed->flags, packet::tcp::fin), now);
      if (schedule != AckSchedule::immediate)
        response.emit = false;
    } else if (has(parsed->flags, packet::tcp::fin) && response.emit) {
      // FIN without payload is processed directly by the TCB. Retaining a
      // due-now ACK makes queue backpressure retryable after state publication.
      candidate_delayed_ack.request_immediate(now);
    }

    // A received segment has already crossed Ethernet, IP validation and the
    // endpoint RX queue. Publish its accepted effects now. Its response is a
    // separate admission transaction, so a full TX queue cannot roll back
    // received bytes, cumulative ACK progress or a peer FIN.
    control_ = std::move(candidate);
    sender_ = std::move(candidate_sender);
    receiver_ = std::move(candidate_receiver);
    receive_window_ = std::move(candidate_receive_window);
    delayed_ack_ = candidate_delayed_ack;
    timestamps_ = candidate_timestamps;
    timestamp_state_present_ = candidate_timestamp_present;
    if (!response.emit)
      return {.status = ConnectionPrepareStatus::no_action};
    return stage(control_, response, local_syn_offer_, peer_syn_options_,
                 negotiated_, timestamps_, timestamp_state_present_, output,
                 now);
  }

  // Even a pure ACK can update SND.UNA, SND.WND, WL1 and WL2 without changing
  // the public TCP state or emitting a response. Stage every valid processed
  // segment so these hidden but protocol-critical values are not discarded by
  // an over-aggressive state-only equality shortcut.
  return stage(std::move(candidate), result, candidate_local, candidate_peer,
               candidate_negotiated, candidate_timestamps,
               candidate_timestamp_present, output, now);
}

ConnectionPrepareResult Connection::prepare_close(
    std::span<std::uint8_t> output, Clock::time_point now) noexcept {
  if (!valid_)
    return {.status = ConnectionPrepareStatus::invalid_connection};
  if (pending_)
    return {.status = ConnectionPrepareStatus::pending_transmission};
  auto candidate = control_;
  const auto result = candidate.close(now);
  if (!result.emit && result.event == ControlEvent::none)
    return {.status = ConnectionPrepareStatus::wrong_state};
  return stage(std::move(candidate), result, local_syn_offer_,
               peer_syn_options_, negotiated_, timestamps_,
               timestamp_state_present_, output, now);
}

ConnectionPrepareResult Connection::prepare_deadline(
    std::span<std::uint8_t> output, Clock::time_point now) noexcept {
  if (!valid_)
    return {.status = ConnectionPrepareStatus::invalid_connection};
  if (pending_)
    return {.status = ConnectionPrepareStatus::pending_transmission};
  if (delayed_ack_.due(now))
    return prepare_current_ack(output, now);
  auto candidate = control_;
  const auto result = candidate.service_deadline(now);
  if (result.emit || result.event != ControlEvent::none)
    return stage(std::move(candidate), result, local_syn_offer_,
                 peer_syn_options_, negotiated_, timestamps_,
                 timestamp_state_present_, output, now);

  if (!sender_)
    return {.status = ConnectionPrepareStatus::no_action};
  // RFC 6298 timeout repair outranks persist and SWS deadlines. Persist is
  // mutually exclusive with an ordinary data RTO in Sender, while the order
  // still makes a corrupt or future extension fail on the conservative side.
  auto transmission = sender_->prepare_timeout_retransmission(now);
  if (!transmission)
    transmission = sender_->prepare_persist_probe(now);
  if (!transmission)
    transmission = sender_->prepare_new(now, true);
  return transmission
             ? prepare_sender_transmission(transmission, output, true, now)
             : ConnectionPrepareResult{
                   .status = ConnectionPrepareStatus::no_action};
}

ConnectionPrepareResult Connection::prepare_current_ack(
    std::span<std::uint8_t> output, Clock::time_point now) noexcept {
  return stage(control_, control_.current_acknowledgment(), local_syn_offer_,
               peer_syn_options_, negotiated_, timestamps_,
               timestamp_state_present_, output, now);
}

bool Connection::commit(const PreparedConnectionSegment &prepared,
                        Clock::time_point now) noexcept {
  if (!pending_ || !prepared || pending_->token != prepared.token ||
      pending_->emitted != prepared.emit)
    return false;
  if (pending_->emitted &&
      has(pending_->emitted_fields.flags, packet::tcp::ack) &&
      pending_->timestamp_state_present) {
    // Last.ACK.sent changes only after the segment entered the lower queue.
    // PAWS can therefore never learn sequence progress from a discarded ACK.
    pending_->timestamps.acknowledge_sent(
        pending_->emitted_fields.acknowledgment);
  }
  if (pending_->sender_transmission_present) {
    if (!pending_->sender ||
        !pending_->sender->commit(pending_->sender_transmission, now))
      return false;
  }
  control_ = pending_->control;
  local_syn_offer_ = pending_->local_syn_offer;
  peer_syn_options_ = pending_->peer_syn_options;
  negotiated_ = pending_->negotiated;
  timestamps_ = pending_->timestamps;
  sender_ = pending_->sender;
  timestamp_state_present_ = pending_->timestamp_state_present;
  // Sender and receiver begin at the post-SYN sequence coordinates. They are
  // constructed only after the admission that actually establishes the TCB.
  initialize_stream(now);
  if (pending_->emitted &&
      has(pending_->emitted_fields.flags, packet::tcp::ack))
    delayed_ack_.acknowledge_committed();
  pending_.reset();
  return true;
}

void Connection::initialize_stream(Clock::time_point now) noexcept {
  if (control_.state() != State::established || sender_ || !negotiated_)
    return;
  // TCP header sizes are protocol fields, not host container sizes. Keeping
  // this value in the transport API's uint32_t domain makes the narrowing
  // explicit and prevents 64-bit size_t from silently crossing the ABI.
  const auto header_octets = static_cast<std::uint32_t>(
      packet::tcp::minimum_header_octets +
      (negotiated_->timestamps ? 12U : 0U));
  const auto effective_mss = effective_send_mss(
      negotiated_->send_mss, policy_.maximum_transport_message,
      header_octets, 0U);
  if (effective_mss == 0U)
    return;
  sender_.emplace(storage_.send_bytes, storage_.transmission_history,
                  storage_.sack_ranges, storage_.sack_workspace,
                  control_.send_next(), effective_mss);
  sender_->set_sack_enabled(negotiated_->sack);
  sender_->update_receiver_window(control_.send_window(), now);
  receiver_.emplace(storage_.receive_bytes, storage_.receive_bitmap,
                    control_.receive_next());
  receive_window_.emplace(
      static_cast<std::uint32_t>(storage_.receive_bytes.size()),
      effective_mss);
  if (!sender_->valid() || !receiver_->valid() || !receive_window_->valid()) {
    sender_.reset();
    receiver_.reset();
    receive_window_.reset();
  }
}

bool Connection::reduce_maximum_transport_message(
    std::uint32_t maximum_transport_message) noexcept {
  if (maximum_transport_message <= packet::tcp::minimum_header_octets ||
      maximum_transport_message > policy_.maximum_transport_message)
    return false;
  if (maximum_transport_message == policy_.maximum_transport_message)
    return true;

  const auto header_octets = static_cast<std::uint32_t>(
      packet::tcp::minimum_header_octets +
      (negotiated_ && negotiated_->timestamps ? 12U : 0U));
  const auto peer_mss = negotiated_ ? negotiated_->send_mss
                                    : default_send_mss(tuple_.family);
  const auto sender_mss = effective_send_mss(
      peer_mss, maximum_transport_message, header_octets, 0U);
  if (sender_ && (sender_mss == 0U || !sender_->reduce_mss(sender_mss)))
    return false;
  policy_.maximum_transport_message = maximum_transport_message;
  return true;
}

std::size_t Connection::write(std::span<const std::uint8_t> bytes,
                              Clock::time_point now) noexcept {
  return sender_ ? sender_->write(bytes, now) : 0U;
}

std::size_t Connection::read(std::span<std::uint8_t> output,
                             Clock::time_point now) noexcept {
  if (!receiver_ || !receive_window_)
    return 0U;
  const auto count = receiver_->read(output);
  if (count != 0U && receive_window_->application_space_available(
                         receiver_->advertised_window())) {
    static_cast<void>(
        control_.set_receive_window(receive_window_->advertised()));
    delayed_ack_.request_immediate(now);
  }
  return count;
}

std::optional<Connection::Clock::time_point>
Connection::next_deadline() const noexcept {
  auto deadline = control_.next_deadline();
  const auto select = [&deadline](std::optional<Clock::time_point> candidate) {
    if (candidate && (!deadline || *candidate < *deadline))
      deadline = candidate;
  };
  select(delayed_ack_.deadline());
  if (sender_)
    select(sender_->next_deadline());
  return deadline;
}

std::optional<ConnectionCheckpoint>
Connection::checkpoint(Clock::time_point now) const {
  // A prepared segment has not entered the packet path and therefore is not
  // protocol state. Refusing the boundary forces the queue owner to commit or
  // discard first and prevents restore from inventing an admission result.
  if (!valid_ || pending_ || now < timestamp_origin_)
    return std::nullopt;
  return ConnectionCheckpoint{
      .tuple = tuple_,
      .policy = policy_,
      .control = control_.checkpoint(now),
      .local_syn_offer = local_syn_offer_,
      .peer_syn_options = peer_syn_options_,
      .negotiated = negotiated_,
      .timestamps = timestamps_.checkpoint(now),
      .sender = sender_ ? std::optional{sender_->checkpoint(now)}
                        : std::nullopt,
      .receiver = receiver_ ? std::optional{receiver_->checkpoint()}
                            : std::nullopt,
      .receive_window = receive_window_
                            ? std::optional{receive_window_->checkpoint()}
                            : std::nullopt,
      .delayed_ack = delayed_ack_.checkpoint(now),
      .timestamp_elapsed_nanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              now - timestamp_origin_)
              .count(),
      .next_token = next_token_,
      .timestamp_state_present = timestamp_state_present_};
}

bool Connection::restore(const ConnectionCheckpoint &state,
                         Clock::time_point now) noexcept {
  const bool stream_present = state.sender.has_value();
  const bool complete_stream =
      stream_present == state.receiver.has_value() &&
      stream_present == state.receive_window.has_value();
  const bool option_state_valid =
      state.timestamp_state_present ==
          (state.negotiated && state.negotiated->timestamps) &&
      (!stream_present || state.negotiated.has_value()) &&
      (!state.negotiated ||
       (state.local_syn_offer && state.peer_syn_options &&
        state.peer_syn_options->sack_block_count <=
            state.peer_syn_options->sack_blocks.size() &&
        state.local_syn_offer->receive_mss != 0U &&
        state.local_syn_offer->receive_window_shift <= 14U &&
        state.negotiated->send_mss != 0U &&
        state.negotiated->send_window_shift <= 14U &&
        state.negotiated->receive_window_shift <= 14U &&
        *state.negotiated == negotiate_options(
                                 tuple_.family, *state.local_syn_offer,
                                 *state.peer_syn_options)));
  if (!valid_ || pending_ || state.tuple != tuple_ ||
      state.policy != policy_ || state.next_token == 0U ||
      state.timestamp_elapsed_nanoseconds < 0 || !complete_stream ||
      !option_state_valid ||
      state.control.local_port != tuple_.local_port ||
      (state.control.remote_port != 0U &&
       state.control.remote_port != tuple_.remote_port) ||
      !ControlBlock::validate_checkpoint(state.control))
    return false;
  const auto timestamp_elapsed =
      std::chrono::nanoseconds{state.timestamp_elapsed_nanoseconds};
  if (timestamp_elapsed > now.time_since_epoch())
    return false;

  // Checkpoint restore is a cold owner operation, so retaining rollback copies
  // is acceptable. Component restore validates before publication, while this
  // backup also protects shared caller arenas if a later component rejects a
  // cross-component inconsistency.
  const auto old_control = control_.checkpoint(now);
  const auto old_timestamps = timestamps_.checkpoint(now);
  const auto old_sender = sender_ ? std::optional{sender_->checkpoint(now)}
                                  : std::nullopt;
  const auto old_receiver = receiver_ ? std::optional{receiver_->checkpoint()}
                                      : std::nullopt;
  const auto old_receive_window =
      receive_window_ ? std::optional{receive_window_->checkpoint()}
                      : std::nullopt;
  const auto old_delayed_ack = delayed_ack_.checkpoint(now);

  auto candidate_control = control_;
  TimestampState candidate_timestamps{state.timestamp_state_present};
  DelayedAcknowledger candidate_delayed_ack;
  std::optional<Sender> candidate_sender;
  std::optional<ReceiveBuffer> candidate_receiver;
  std::optional<ReceiveWindow> candidate_receive_window;

  bool restored = candidate_control.restore(state.control, now) &&
                  candidate_timestamps.restore(state.timestamps, now) &&
                  candidate_delayed_ack.restore(state.delayed_ack, now);
  if (restored && stream_present) {
    const auto header_octets = static_cast<std::uint32_t>(
        packet::tcp::minimum_header_octets +
        (state.negotiated->timestamps ? 12U : 0U));
    const auto effective_mss = effective_send_mss(
        state.negotiated->send_mss, policy_.maximum_transport_message,
        header_octets, 0U);
    if (effective_mss == 0U) {
      restored = false;
    } else {
      candidate_sender.emplace(
          storage_.send_bytes, storage_.transmission_history,
          storage_.sack_ranges, storage_.sack_workspace,
          state.sender->bytes.send_unacknowledged, effective_mss);
      candidate_receiver.emplace(
          storage_.receive_bytes, storage_.receive_bitmap,
          state.receiver->read_sequence);
      candidate_receive_window.emplace(
          static_cast<std::uint32_t>(storage_.receive_bytes.size()),
          effective_mss);
      restored = candidate_sender->restore(*state.sender, now) &&
                 candidate_receiver->restore(*state.receiver) &&
                 candidate_receive_window->restore(*state.receive_window);
    }
  }

  if (!restored) {
    // These values were produced by this live connection immediately above.
    // Rollback failure therefore indicates internal memory corruption. Marking
    // the connection invalid is safer than exposing a partially restored TCB.
    bool rolled_back = control_.restore(old_control, now) &&
                       timestamps_.restore(old_timestamps, now) &&
                       delayed_ack_.restore(old_delayed_ack, now);
    if (sender_ && old_sender)
      rolled_back = sender_->restore(*old_sender, now) && rolled_back;
    if (receiver_ && old_receiver)
      rolled_back = receiver_->restore(*old_receiver) && rolled_back;
    if (receive_window_ && old_receive_window)
      rolled_back = receive_window_->restore(*old_receive_window) &&
                    rolled_back;
    if (!rolled_back)
      valid_ = false;
    return false;
  }

  control_ = std::move(candidate_control);
  local_syn_offer_ = state.local_syn_offer;
  peer_syn_options_ = state.peer_syn_options;
  negotiated_ = state.negotiated;
  timestamps_ = candidate_timestamps;
  sender_ = std::move(candidate_sender);
  receiver_ = std::move(candidate_receiver);
  receive_window_ = std::move(candidate_receive_window);
  delayed_ack_ = candidate_delayed_ack;
  timestamp_origin_ = now - timestamp_elapsed;
  next_token_ = state.next_token;
  timestamp_state_present_ = state.timestamp_state_present;
  pending_.reset();
  return true;
}

ConnectionPrepareResult Connection::prepare_sender_transmission(
    const PreparedTransmission &transmission,
    std::span<std::uint8_t> output, bool pushed,
    Clock::time_point now) noexcept {
  if (transmission.range.length > storage_.transmit_payload_scratch.size() ||
      !sender_->copy(transmission,
                     storage_.transmit_payload_scratch.first(
                         transmission.range.length)))
    return {.status = ConnectionPrepareStatus::output_too_small};

  auto candidate_control = control_;
  // New data, including a first zero-window probe, consumes fresh sequence
  // space. Repair segments refer to sequence space already owned by SND.NXT.
  if (!transmission.range.retransmission &&
      !candidate_control.commit_sent_data(transmission.range.sequence,
                                          transmission.range.length))
    return {.status = ConnectionPrepareStatus::wrong_state};
  auto fields = control_.current_acknowledgment().segment;
  fields.sequence = transmission.range.sequence;
  if (pushed && transmission.reason == TransmissionReason::new_data)
    fields.flags = static_cast<std::uint8_t>(fields.flags | packet::tcp::psh);
  const auto payload = std::span<const std::uint8_t>{
      storage_.transmit_payload_scratch}
                           .first(transmission.range.length);
  const auto encoded = encode(fields, local_syn_offer_, negotiated_, timestamps_,
                              timestamp_state_present_, payload, output, now);
  if (!encoded)
    return {.status = ConnectionPrepareStatus::output_too_small};

  auto token = next_token_++;
  if (token == 0U)
    token = next_token_++;
  pending_.emplace(PendingTransition{
      .control = std::move(candidate_control),
      .local_syn_offer = local_syn_offer_,
      .peer_syn_options = peer_syn_options_,
      .negotiated = negotiated_,
      .timestamps = timestamps_,
      .sender = sender_,
      .sender_transmission = transmission,
      .emitted_fields = fields,
      .token = token,
      .event = ControlEvent::none,
      .timestamp_state_present = timestamp_state_present_,
      .sender_transmission_present = true,
      .emitted = true});
  return {.status = ConnectionPrepareStatus::prepared,
          .segment = {.token = token,
                      .octets = *encoded,
                      .event = ControlEvent::none,
                      .emit = true}};
}

ConnectionPrepareResult Connection::prepare_data(
    std::span<std::uint8_t> output, bool pushed,
    Clock::time_point now) noexcept {
  if (!valid_)
    return {.status = ConnectionPrepareStatus::invalid_connection};
  if (pending_)
    return {.status = ConnectionPrepareStatus::pending_transmission};
  if (!sender_ || !receiver_ || !receive_window_ ||
      (control_.state() != State::established &&
       control_.state() != State::close_wait))
    return {.status = ConnectionPrepareStatus::wrong_state};

  // Loss repair has priority over fresh bytes. RFC 6675 recovery chooses the
  // exact SACK hole, Reno chooses the oldest range after three duplicate ACKs,
  // and only then may ordinary cwnd/rwnd-controlled transmission proceed.
  auto transmission = sender_->prepare_sack_recovery(now);
  if (!transmission)
    transmission = sender_->prepare_fast_retransmission();
  if (!transmission)
    transmission = sender_->prepare_new(now, pushed);
  return transmission
             ? prepare_sender_transmission(transmission, output, pushed, now)
             : ConnectionPrepareResult{
                   .status = ConnectionPrepareStatus::no_action};
}

bool Connection::discard(
    const PreparedConnectionSegment &prepared) noexcept {
  if (!pending_ || !prepared || pending_->token != prepared.token)
    return false;
  pending_.reset();
  return true;
}

} // namespace router::transport::tcp
