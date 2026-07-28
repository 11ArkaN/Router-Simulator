// RFC 8156 failover codec and endpoint conformance tests.
//
// Responsibility: exercise byte-exact framing, malformed-input rejection and
// state transitions whose client responsiveness affects lease safety. The
// suite supplies every clock observation so it cannot hide a simulated global
// scheduler inside the protocol owner.

#include "router/dhcpv6_failover.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace {

using namespace router::dhcpv6::failover;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void codec_round_trip_and_validation() {
  // RFC 8156 section 5.5.16 assigns these bytes directly to
  // OPTION_F_SERVER_STATE. Pin every value because reordering a C++ enum would
  // otherwise produce a valid TLV carrying the wrong protocol state.
  require(static_cast<std::uint8_t>(State::startup) == 1U &&
              static_cast<std::uint8_t>(State::normal) == 2U &&
              static_cast<std::uint8_t>(
                  State::communications_interrupted) == 3U &&
              static_cast<std::uint8_t>(State::partner_down) == 4U &&
              static_cast<std::uint8_t>(State::potential_conflict) == 5U &&
              static_cast<std::uint8_t>(State::recover) == 6U &&
              static_cast<std::uint8_t>(State::recover_wait) == 7U &&
              static_cast<std::uint8_t>(State::recover_done) == 8U &&
              static_cast<std::uint8_t>(
                  State::resolution_interrupted) == 9U &&
              static_cast<std::uint8_t>(State::conflict_done) == 10U,
          "RFC 8156 server-state wire registry changed");

  std::array<std::uint8_t, 256U> body{};
  Encoder encoder{body};
  require(encoder.begin(MessageType::connect, 0x010203U, 0x04050607U),
          "failover CONNECT header encode failed");
  const std::array<std::uint8_t, 4U> name{'l', 'a', 'b', '1'};
  require(encoder.option(
              static_cast<std::uint16_t>(OptionCode::relationship_name), name),
          "failover relationship-name encode failed");

  const auto decoded = decode(encoder.message());
  require(decoded.status == DecodeStatus::accepted,
          "valid RFC 8156 CONNECT was rejected");
  require(decoded.message.transaction_id == 0x010203U,
          "failover transaction ID did not round-trip");
  require(decoded.message.sent_time == 0x04050607U,
          "failover sent-time did not round-trip");
  require(decoded.message.first(static_cast<std::uint16_t>(
              OptionCode::relationship_name))
              .has_value(),
          "CONNECT lost relationship identity");

  std::array<std::uint8_t, 258U> framed{};
  const auto used = frame(encoder.message(), framed);
  require(used && *used == encoder.message().size() + 2U,
          "RFC 5460 failover frame length is wrong");
  require(framed[0U] == 0U &&
              framed[1U] == static_cast<std::uint8_t>(
                                encoder.message().size()),
          "RFC 5460 frame prefix is not network byte order");

  auto zero_transaction = encoder.message();
  std::array<std::uint8_t, 256U> malformed{};
  std::copy(zero_transaction.begin(), zero_transaction.end(),
            malformed.begin());
  malformed[1U] = malformed[2U] = malformed[3U] = 0U;
  require(decode(std::span<const std::uint8_t>{
                     malformed.data(), zero_transaction.size()})
              .status == DecodeStatus::invalid_transaction_id,
          "zero failover transaction ID was accepted");

  Encoder missing_name{body};
  require(missing_name.begin(MessageType::connect, 1U, 2U),
          "second CONNECT header encode failed");
  require(decode(missing_name.message()).status ==
              DecodeStatus::invalid_message_options,
          "CONNECT without relationship name was accepted");
}

void stream_decoder_handles_fragmented_and_coalesced_frames() {
  std::array<std::uint8_t, 256U> body{};
  Encoder encoder{body};
  require(encoder.begin(MessageType::contact, 7U, 8U),
          "CONTACT stream fixture failed");
  const auto payload = encoder.message();
  std::array<std::uint8_t, 258U> framed{};
  const auto framed_size = frame(payload, framed);
  require(framed_size.has_value(), "CONTACT framing failed");

  StreamDecoder decoder;
  auto prefix = decoder.ingest(
      std::span<const std::uint8_t>{framed}.first(1U));
  require(prefix.status == StreamStatus::need_more,
          "partial RFC 5460 length was not retained");
  auto middle = decoder.ingest(
      std::span<const std::uint8_t>{framed}.subspan(1U, 3U));
  require(middle.status == StreamStatus::need_more,
          "fragmented failover payload was not retained");
  const auto partial = decoder.checkpoint();
  StreamDecoder restored;
  require(restored.restore(partial),
          "fragmented RFC 5460 stream checkpoint was rejected");

  std::array<std::uint8_t, 520U> coalesced{};
  const auto remainder = *framed_size - 4U;
  std::copy_n(framed.begin() + 4, remainder, coalesced.begin());
  std::copy_n(framed.begin(), *framed_size,
              coalesced.begin() + static_cast<std::ptrdiff_t>(remainder));
  auto complete = restored.ingest(
      std::span<const std::uint8_t>{coalesced}.first(
          remainder + *framed_size));
  require(complete.status == StreamStatus::message_ready &&
              complete.accepted_octets == remainder &&
              complete.message.size() == payload.size() &&
              decode(complete.message).status == DecodeStatus::accepted,
          "RFC 5460 decoder crossed a message boundary");
  restored.consume();
  auto next = restored.ingest(
      std::span<const std::uint8_t>{coalesced}.subspan(
          remainder, *framed_size));
  require(next.status == StreamStatus::message_ready &&
              decode(next.message).status == DecodeStatus::accepted,
          "coalesced second RFC 5460 message was not decoded");
}

void negotiation_and_state_messages_use_rfc_option_shapes() {
  const Configuration configuration{
      .relationship_name = "access-pair",
      .role = Role::primary,
      .maximum_client_lead_time_seconds = 3600U,
      .keepalive_seconds = 60U,
      .maximum_response_delay_seconds = 60U,
      .auto_partner_down_seconds = std::nullopt,
      .maximum_unacked_updates = 64U};
  std::array<std::uint8_t, 512U> storage{};
  const auto connected = encode_negotiation(
      MessageType::connect, 0x010203U, 100U, configuration, 1U, storage);
  require(connected.has_value(), "CONNECT negotiation encode failed");
  auto decoded = decode(
      std::span<const std::uint8_t>{storage}.first(*connected));
  require(decoded.status == DecodeStatus::accepted,
          "encoded CONNECT negotiation was rejected");
  NegotiatedParameters negotiated;
  require(validate_negotiation(decoded.message, configuration, false,
                               negotiated) ==
              NegotiationStatus::accepted &&
              negotiated.maximum_client_lead_time_seconds == 3600U &&
              negotiated.keepalive_seconds == 60U &&
              negotiated.maximum_unacked_updates == 64U &&
              negotiated.connect_flags == 1U,
          "CONNECT mandatory options did not round-trip");

  const auto advertised = encode_state(
      0x010204U, 101U,
      {.state = State::partner_down,
       .flags = 1U,
       .started_at = 90U,
       .partner_down_at = 91U},
      storage);
  require(advertised.has_value(), "STATE encode failed");
  decoded = decode(
      std::span<const std::uint8_t>{storage}.first(*advertised));
  const auto state = decoded.status == DecodeStatus::accepted
                         ? parse_state(decoded.message)
                         : std::nullopt;
  require(state && state->state == State::partner_down &&
              state->flags == 1U && state->started_at == 90U &&
              state->partner_down_at == 91U,
          "STATE mandatory options did not round-trip");

  // PARTNER-DOWN-TIME is conditionally mandatory. Its presence in NORMAL is
  // just as malformed as its absence in PARTNER-DOWN.
  require(!encode_state(
              0x010205U, 102U,
              {.state = State::normal,
               .flags = 1U,
               .started_at = 100U,
               .partner_down_at = 91U},
              storage),
          "NORMAL STATE accepted PARTNER-DOWN-TIME");
}

void binding_updates_preserve_client_and_prefix_identity() {
  std::array<std::uint8_t, 2048U> storage{};
  const std::array<std::uint8_t, 10U> duid{
      0U, 4U, 0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U, 0x80U};
  const router::packet::Ipv6 address{
      0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 1U,
      0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x44U};
  const BindingUpdate active{
      .client_identifier = duid,
      .value = address,
      .association = IdentityAssociationType::non_temporary,
      .status = BindingStatus::active,
      .iaid = 0x01020304U,
      .t1 = 900U,
      .t2 = 1440U,
      .preferred_lifetime = 1800U,
      .valid_lifetime = 3600U,
      .base_time = 1000U,
      .start_time_of_state = 990U,
      .state_expiration_time = 4600U,
      .client_last_transaction_time = 10U,
      .partner_lifetime = 4300U,
      .partner_raw_client_last_transaction_time = 985U,
      .expiration_time = 4600U,
      .prefix_length = 128U};
  const auto encoded = encode_binding(
      MessageType::binding_update, 0x010203U, 1000U, active, storage);
  require(encoded.has_value(), "RFC 8156 address BNDUPD encode failed");
  const auto decoded =
      decode(std::span<const std::uint8_t>{storage}.first(*encoded));
  require(decoded.status == DecodeStatus::accepted,
          "encoded address BNDUPD failed outer validation");
  std::array<BindingUpdateView, 4U> bindings{};
  const auto parsed = parse_bindings(decoded.message, bindings);
  require(parsed.status == BindingParseStatus::accepted &&
              parsed.bindings == 1U &&
              bindings[0U].client_identifier.size() == duid.size() &&
              std::equal(bindings[0U].client_identifier.begin(),
                         bindings[0U].client_identifier.end(),
                         duid.begin()) &&
              bindings[0U].association ==
                  IdentityAssociationType::non_temporary &&
              bindings[0U].iaid == active.iaid &&
              bindings[0U].value == address &&
              bindings[0U].status == BindingStatus::active &&
              bindings[0U].state_expiration_time ==
                  active.state_expiration_time,
          "RFC 8156 address binding identity did not round-trip");

  // One BNDREPLY acknowledges every resource of the committed transaction.
  // This is not merely a codec round-trip: it protects the repository owner's
  // atomicity contract by proving that a two-resource request cannot receive a
  // one-resource success response.
  std::array<BindingUpdateView, 2U> acknowledged_resources{
      BindingUpdateView{
          .client_identifier = duid,
          .value = address,
          .association = IdentityAssociationType::non_temporary,
          .status = BindingStatus::active,
          .iaid = active.iaid,
          .t1 = active.t1,
          .t2 = active.t2,
          .preferred_lifetime = active.preferred_lifetime,
          .valid_lifetime = active.valid_lifetime,
          .base_time = active.base_time,
          .start_time_of_state = active.start_time_of_state,
          .state_expiration_time = active.state_expiration_time,
          .client_last_transaction_time =
              active.client_last_transaction_time,
          .partner_lifetime = active.partner_lifetime,
          .partner_raw_client_last_transaction_time =
              active.partner_raw_client_last_transaction_time,
          .expiration_time = active.expiration_time,
          .prefix_length = active.prefix_length},
      BindingUpdateView{
          .client_identifier = duid,
          .value = router::packet::Ipv6{
              0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 1U,
              0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x45U},
          .association = IdentityAssociationType::non_temporary,
          .status = BindingStatus::active,
          .iaid = active.iaid,
          .t1 = active.t1,
          .t2 = active.t2,
          .preferred_lifetime = active.preferred_lifetime,
          .valid_lifetime = active.valid_lifetime,
          .base_time = active.base_time,
          .start_time_of_state = active.start_time_of_state,
          .state_expiration_time = active.state_expiration_time,
          .client_last_transaction_time =
              active.client_last_transaction_time,
          .partner_lifetime = active.partner_lifetime,
          .partner_raw_client_last_transaction_time =
              active.partner_raw_client_last_transaction_time,
          .expiration_time = active.expiration_time,
          .prefix_length = active.prefix_length}};
  std::array<std::uint8_t, maximum_message_octets> reply_storage{};
  const auto reply = encode_binding_reply(
      0x010203U, 1001U, acknowledged_resources, reply_storage);
  require(reply.has_value(), "multi-resource BNDREPLY encode failed");
  const auto reply_decoded =
      decode(std::span<const std::uint8_t>{reply_storage}.first(*reply));
  std::array<BindingUpdateView, 3U> reply_bindings{};
  const auto reply_parsed =
      reply_decoded.status == DecodeStatus::accepted
          ? parse_bindings(reply_decoded.message, reply_bindings)
          : BindingParseResult{};
  require(reply_decoded.status == DecodeStatus::accepted &&
              reply_decoded.message.type == MessageType::binding_reply &&
              reply_parsed.status == BindingParseStatus::accepted &&
              reply_parsed.bindings == acknowledged_resources.size() &&
              reply_bindings[0U].value ==
                  acknowledged_resources[0U].value &&
              reply_bindings[1U].value ==
                  acknowledged_resources[1U].value,
          "BNDREPLY omitted or reordered a committed resource");

  const router::packet::Ipv6 prefix{
      0x20U, 0x01U, 0x0dU, 0xb8U, 0x12U, 0x34U, 0U, 0U,
      0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
  const BindingUpdate free_prefix{
      .client_identifier = {},
      .value = prefix,
      .association = IdentityAssociationType::unassociated_prefix,
      .status = BindingStatus::free_backup,
      .iaid = 0U,
      .t1 = 0U,
      .t2 = 0U,
      .preferred_lifetime = 0U,
      .valid_lifetime = 0U,
      .base_time = 2000U,
      .start_time_of_state = 1990U,
      .state_expiration_time = std::nullopt,
      .client_last_transaction_time = std::nullopt,
      .partner_lifetime = std::nullopt,
      .partner_raw_client_last_transaction_time = std::nullopt,
      .expiration_time = std::nullopt,
      .prefix_length = 56U};
  const auto prefix_encoded =
      encode_binding(MessageType::binding_update, 0x010204U, 2000U,
                     free_prefix, storage);
  require(prefix_encoded.has_value(),
          "RFC 8156 unassociated prefix BNDUPD encode failed");
  const auto prefix_decoded =
      decode(std::span<const std::uint8_t>{storage}.first(*prefix_encoded));
  const auto prefix_parsed =
      prefix_decoded.status == DecodeStatus::accepted
          ? parse_bindings(prefix_decoded.message, bindings)
          : BindingParseResult{};
  require(prefix_parsed.status == BindingParseStatus::accepted &&
              prefix_parsed.bindings == 1U &&
              bindings[0U].association ==
                  IdentityAssociationType::unassociated_prefix &&
              bindings[0U].client_identifier.empty() &&
              bindings[0U].value == prefix &&
              bindings[0U].prefix_length == 56U &&
              bindings[0U].status == BindingStatus::free_backup,
          "RFC 8156 unassociated prefix identity did not round-trip");

  auto incomplete_timeout = active;
  incomplete_timeout.partner_lifetime.reset();
  require(!encode_binding(MessageType::binding_update, 0x010205U, 2001U,
                          incomplete_timeout, storage),
          "partial RFC 8156 timeout group was encoded");
}

void session_negotiates_and_synchronizes_without_peer_shortcuts() {
  const auto now = Session::Clock::time_point{};
  Session primary;
  Session secondary;
  require(primary.configure(
              {.relationship_name = "base-pair",
               .role = Role::primary,
               .maximum_client_lead_time_seconds = 3600U,
               .keepalive_seconds = 30U,
               .maximum_response_delay_seconds = 90U,
               .auto_partner_down_seconds = std::nullopt,
               .maximum_unacked_updates = 64U},
              0U, 100U, now),
          "primary RFC 8156 session configuration failed");
  require(secondary.configure(
              {.relationship_name = "base-pair",
               .role = Role::secondary,
               .maximum_client_lead_time_seconds = 3600U,
               .keepalive_seconds = 30U,
               .maximum_response_delay_seconds = 90U,
               .auto_partner_down_seconds = std::nullopt,
               .maximum_unacked_updates = 64U},
              0U, 100U, now),
          "secondary RFC 8156 session configuration failed");
  primary.transport_connected(100U, now);
  secondary.transport_connected(100U, now);

  std::array<std::uint8_t, 1024U> wire{};
  const auto connect = primary.prepare_next(wire, 100U, now);
  require(connect.has_value(), "primary did not produce CONNECT");
  auto decoded =
      decode(std::span<const std::uint8_t>{wire}.first(*connect));
  require(decoded.status == DecodeStatus::accepted &&
              decoded.message.type == MessageType::connect,
          "primary session emitted an invalid CONNECT");
  require(secondary.receive(decoded.message, 100U, now).kind ==
              SessionEventKind::none,
          "secondary rejected a valid CONNECT");

  // A restored relationship must retain CONNECTREPLY before STATE and
  // UPDREQALL. This catches checkpoints that keep endpoint state but discard
  // the application conversation queued above TCP.
  const auto saved_secondary = secondary.checkpoint(now);
  Session restored_secondary;
  require(restored_secondary.restore(saved_secondary, now),
          "secondary RFC 8156 session checkpoint restore failed");
  const auto reply = restored_secondary.prepare_next(wire, 100U, now);
  require(reply.has_value(), "secondary did not produce CONNECTREPLY");
  decoded = decode(std::span<const std::uint8_t>{wire}.first(*reply));
  require(decoded.status == DecodeStatus::accepted &&
              decoded.message.type == MessageType::connect_reply,
          "secondary session emitted an invalid CONNECTREPLY");
  require(primary.receive(decoded.message, 100U, now).kind ==
              SessionEventKind::none,
          "primary rejected a valid CONNECTREPLY");
  require(primary.phase() == SessionPhase::synchronizing &&
              secondary.phase() == SessionPhase::synchronizing,
          "negotiated sessions did not enter synchronization");

  // Each side sends STATE before UPDREQALL. These are real application bytes
  // that the RouterForwarder TCP adapter must frame and route.
  const auto state = primary.prepare_next(wire, 100U, now);
  require(state.has_value(), "primary did not advertise STATE");
  decoded = decode(std::span<const std::uint8_t>{wire}.first(*state));
  require(decoded.status == DecodeStatus::accepted &&
              decoded.message.type == MessageType::state &&
              secondary.receive(decoded.message, 100U, now).kind ==
                  SessionEventKind::partner_state_changed,
          "secondary did not process primary STATE");

  const auto request = primary.prepare_next(wire, 100U, now);
  require(request.has_value(), "primary did not request full synchronization");
  decoded = decode(std::span<const std::uint8_t>{wire}.first(*request));
  require(decoded.status == DecodeStatus::accepted &&
              decoded.message.type == MessageType::update_request_all,
          "primary synchronization request is malformed");
  const auto request_xid = decoded.message.transaction_id;
  require(secondary.receive(decoded.message, 100U, now).kind ==
              SessionEventKind::synchronization_requested,
          "secondary did not expose synchronization work");
  require(secondary.finish_synchronization(request_xid),
          "secondary could not queue UPDDONE after repository completion");
}

void state_machine_preserves_rfc_recovery_semantics() {
  Endpoint endpoint;
  const auto start = Endpoint::Clock::time_point{};
  require(endpoint.configure(
              {.relationship_name = "lab",
               .role = Role::secondary,
               .maximum_client_lead_time_seconds = 60U,
               .keepalive_seconds = 10U,
               .maximum_response_delay_seconds = 30U,
               .auto_partner_down_seconds = 120U,
               .maximum_unacked_updates = 64U},
              100U, start),
          "valid failover relationship was rejected");
  require(endpoint.responsiveness() == Responsiveness::unresponsive,
          "STARTUP endpoint answered clients");

  endpoint.communication_changed(true, 101U, start);
  endpoint.partner_state_changed(State::normal, 101U, start);
  require(endpoint.state() == State::recover,
          "STARTUP did not enter RECOVER after partner contact");
  endpoint.update_request_finished(102U, start);
  require(endpoint.state() == State::recover_wait,
          "UPDDONE did not enter RECOVER-WAIT");

  endpoint.communication_changed(false, 103U, start);
  require(endpoint.state() == State::recover_wait,
          "RECOVER-WAIT incorrectly left state after communication failure");
  endpoint.service(163U, start + std::chrono::seconds{60});
  require(endpoint.state() == State::recover_done,
          "MCLT expiry did not enter RECOVER-DONE");
  require(endpoint.responsiveness() == Responsiveness::renew_responsive,
          "RECOVER-DONE is not renew-responsive");

  const auto saved = endpoint.checkpoint(start + std::chrono::seconds{60});
  Endpoint restored;
  require(restored.restore(saved, start + std::chrono::seconds{600}),
          "valid failover checkpoint was rejected");
  require(restored.state() == State::recover_done,
          "failover checkpoint changed endpoint state");
}

} // namespace

void dhcpv6_failover_tests() {
  codec_round_trip_and_validation();
  stream_decoder_handles_fragmented_and_coalesced_frames();
  negotiation_and_state_messages_use_rfc_option_shapes();
  binding_updates_preserve_client_and_prefix_identity();
  session_negotiates_and_synchronizes_without_peer_shortcuts();
  state_machine_preserves_rfc_recovery_semantics();
}
