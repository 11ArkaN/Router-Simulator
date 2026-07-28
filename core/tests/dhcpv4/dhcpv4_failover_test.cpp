// draft-ietf-dhc-failover-12 codec and shared-secret authentication tests.
//
// Responsibility: pin the historical on-wire header, ordered TLV admission,
// framing limits and HMAC-MD5 behavior. These checks are intentionally
// independent of a lease owner and modeled TCP connection.

#include "router/dhcpv4_failover.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>

namespace {

using namespace router::dhcpv4::failover;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void codec_and_digest_round_trip() {
  std::array<std::uint8_t, maximum_message_octets> storage{};
  Encoder encoder{storage};
  require(encoder.begin(MessageType::connect, 1'722'000'000U, 42U),
          "DHCPv4 failover CONNECT header failed");
  std::array<std::uint8_t, 17U> digest{};
  digest[0U] = 1U;
  require(encoder.option(
              static_cast<std::uint16_t>(OptionCode::message_digest), digest),
          "DHCPv4 failover digest option failed");
  const std::array<std::uint8_t, 1U> protocol_version{1U};
  const std::array<std::uint8_t, 4U> relationship{'l', 'a', 'b', '1'};
  require(encoder.option(
              static_cast<std::uint16_t>(OptionCode::protocol_version),
              protocol_version) &&
              encoder.option(static_cast<std::uint16_t>(
                                 OptionCode::relationship_name),
                             relationship),
          "DHCPv4 failover CONNECT negotiation options failed");
  const auto encoded = encoder.message();
  auto message = std::span<std::uint8_t>{storage}.first(encoded.size());
  require(message.size() == 46U,
          "DHCPv4 failover message length changed");
  require(message[0U] == 0U && message[1U] == 46U &&
              message[2U] == static_cast<std::uint8_t>(MessageType::connect) &&
              message[3U] == version_one_payload_offset,
          "DHCPv4 failover fixed header is not draft-12 format");

  const std::array<std::uint8_t, 12U> secret{
      's', 'h', 'a', 'r', 'e', 'd', '-', 'k', 'e', 'y', '-', '1'};
  require(sign_hmac_md5(message, secret) == DigestStatus::accepted,
          "DHCPv4 failover HMAC-MD5 signing failed");
  require(verify_hmac_md5(message, secret) == DigestStatus::accepted,
          "DHCPv4 failover HMAC-MD5 verification failed");
  message.back() ^= 1U;
  require(verify_hmac_md5(message, secret) == DigestStatus::mismatch,
          "modified failover message passed HMAC-MD5");

  std::array<std::uint8_t, maximum_message_octets> inserted_storage{};
  Encoder unsigned_encoder{inserted_storage};
  require(unsigned_encoder.begin(MessageType::contact, 1'722'000'001U, 43U),
          "unsigned CONTACT header failed");
  const auto unsigned_message = unsigned_encoder.message();
  const auto authenticated = insert_hmac_md5(
      inserted_storage, unsigned_message.size(), secret);
  require(authenticated.has_value() &&
              verify_hmac_md5(
                  std::span<std::uint8_t>{inserted_storage}.first(
                      *authenticated),
                  secret) == DigestStatus::accepted &&
              decode(std::span<const std::uint8_t>{inserted_storage}.first(
                         *authenticated))
                      .status == DecodeStatus::accepted,
          "allocation-free failover digest insertion changed the message");
}

void decoder_rejects_invalid_framing_and_order() {
  std::array<std::uint8_t, 128U> storage{};
  Encoder encoder{storage};
  require(encoder.begin(MessageType::connect, 1U, 2U),
          "CONNECT header encode failed");
  const std::array<std::uint8_t, 1U> version{1U};
  const std::array<std::uint8_t, 1U> name{'x'};
  require(encoder.option(
              static_cast<std::uint16_t>(OptionCode::protocol_version),
              version) &&
              encoder.option(
                  static_cast<std::uint16_t>(OptionCode::relationship_name),
                  name),
          "CONNECT option encode failed");
  const auto encoded = encoder.message();
  auto message = std::span<std::uint8_t>{storage}.first(encoded.size());
  require(decode(message).status == DecodeStatus::accepted,
          "valid draft-12 message was rejected");
  message[1U] -= 1U;
  require(decode(message).status == DecodeStatus::invalid_length,
          "mismatched failover frame length was accepted");

  Encoder misplaced_digest{storage};
  require(misplaced_digest.begin(MessageType::contact, 1U, 3U),
          "CONTACT header encode failed");
  require(misplaced_digest.option(
              static_cast<std::uint16_t>(OptionCode::message), name),
          "message option encode failed");
  std::array<std::uint8_t, 17U> digest{};
  digest[0U] = 1U;
  require(misplaced_digest.option(
              static_cast<std::uint16_t>(OptionCode::message_digest), digest),
          "misplaced digest encode failed");
  const auto misplaced_encoded = misplaced_digest.message();
  auto misplaced_message =
      std::span<std::uint8_t>{storage}.first(misplaced_encoded.size());
  require(sign_hmac_md5(misplaced_message, name) ==
              DigestStatus::not_first,
          "non-leading message digest was accepted");
}

void stream_decoder_preserves_tcp_message_boundaries() {
  std::array<std::uint8_t, 128U> storage{};
  Encoder encoder{storage};
  require(encoder.begin(MessageType::contact, 10U, 99U),
          "CONTACT stream fixture header failed");
  const std::array<std::uint8_t, 1U> state{2U};
  require(encoder.option(
              static_cast<std::uint16_t>(OptionCode::server_state), state),
          "CONTACT stream fixture option failed");
  const auto message = encoder.message();

  // Split both the two-octet length and the body. This is the TCP shape which
  // a datagram-style test misses and which previously had no application
  // owner in the failover module.
  StreamDecoder decoder;
  auto first = decoder.ingest(message.first(1U));
  require(first.status == StreamStatus::need_more &&
              first.accepted_octets == 1U,
          "one length octet was not retained");
  auto second = decoder.ingest(message.subspan(1U, 4U));
  require(second.status == StreamStatus::need_more &&
              second.accepted_octets == 4U,
          "split failover body was not retained");
  const auto partial = decoder.checkpoint();
  StreamDecoder restored;
  require(restored.restore(partial),
          "fragmented draft-12 stream checkpoint was rejected");

  std::array<std::uint8_t, 256U> coalesced{};
  const auto remaining = message.size() - 5U;
  std::copy(message.begin() + 5, message.end(), coalesced.begin());
  std::copy(message.begin(), message.end(),
            coalesced.begin() + static_cast<std::ptrdiff_t>(remaining));
  auto complete = restored.ingest(
      std::span<const std::uint8_t>{coalesced}.first(
          remaining + message.size()));
  require(complete.status == StreamStatus::message_ready &&
              complete.accepted_octets == remaining &&
              decode(complete.message).status == DecodeStatus::accepted,
          "decoder consumed bytes from a coalesced next TCP message");
  restored.consume();
  auto next = restored.ingest(
      std::span<const std::uint8_t>{coalesced}.subspan(
          remaining, message.size()));
  require(next.status == StreamStatus::message_ready &&
              decode(next.message).status == DecodeStatus::accepted,
          "second coalesced failover message was lost");
}

void negotiation_and_state_messages_follow_draft_option_sets() {
  const Configuration configuration{
      .relationship_name = "access-pair",
      .role = Role::primary,
      .maximum_client_lead_time_seconds = 3600U,
      .startup_seconds = 10U,
      .maximum_response_delay_seconds = 30U,
      .safe_period_seconds = 120U,
      .maximum_unacked_updates = 64U};
  NegotiationParameters parameters{
      .vendor_class_identifier = "router-simulator",
      .tls_request = TlsRequest::desired};
  // RFC 3074 assigns the odd buckets to the secondary in this fixture. The
  // value remains a wire bitmap so the test also pins byte and bit order.
  parameters.secondary_hash_buckets.fill(0x55U);

  std::array<std::uint8_t, maximum_message_octets> storage{};
  const auto encoded =
      encode_negotiation(MessageType::connect, 1'722'000'000U, 77U,
                         configuration, parameters, false, storage);
  require(encoded.has_value(), "CONNECT negotiation encode failed");
  const auto decoded =
      decode(std::span<const std::uint8_t>{storage}.first(*encoded));
  require(decoded.status == DecodeStatus::accepted,
          "CONNECT negotiation decode failed");
  NegotiatedParameters accepted;
  require(validate_negotiation(decoded.message, configuration, false, false,
                               accepted) ==
              NegotiationStatus::accepted,
          "valid CONNECT negotiation was rejected");
  require(accepted.maximum_client_lead_time_seconds == 3600U &&
              accepted.receive_timer_seconds == 30U &&
              accepted.maximum_unacked_updates == 64U &&
              accepted.tls_request == TlsRequest::desired &&
              accepted.secondary_hash_buckets[0U] == 0x55U,
          "CONNECT negotiation changed a draft option value");

  const auto state_size =
      encode_state(1'722'000'001U, 78U,
                   {.state = ServerState::recover_done,
                    .startup = true,
                    .started_at = 1'721'999'900U},
                   storage);
  require(state_size.has_value(), "STATE encode failed");
  const auto state_message =
      decode(std::span<const std::uint8_t>{storage}.first(*state_size));
  require(state_message.status == DecodeStatus::accepted,
          "STATE decode failed");
  const auto state = parse_state(state_message.message);
  require(state && state->state == ServerState::recover_done &&
              state->startup && state->started_at == 1'721'999'900U,
          "STATE options did not round trip");
  require(!encode_state(1U, 2U,
                        {.state = ServerState::startup,
                         .startup = true,
                         .started_at = 1U},
                        storage),
          "STARTUP was incorrectly sent as a server-state value");
}

void binding_update_and_ack_preserve_binding_identity() {
  std::array<std::uint8_t, maximum_message_octets> storage{};
  const std::array<std::uint8_t, 7U> hardware{
      1U, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};
  const std::array<std::uint8_t, 5U> client{
      0xffU, 0x01U, 0x02U, 0x03U, 0x04U};
  const auto encoded = encode_binding(
      MessageType::binding_update, 10'000U, 91U,
      {.address = {192U, 0U, 2U, 10U},
       .status = BindingStatus::active,
       .client_identifier = client,
       .client_hardware_address = hardware,
       .lease_expiration_time = 13'600U,
       .potential_expiration_time = 17'200U,
       .client_last_transaction_time = 9'999U,
       .start_time_of_state = 9'998U,
       .reject_reason = std::nullopt},
      storage);
  require(encoded.has_value(), "BNDUPD encode failed");
  const auto decoded =
      decode(std::span<const std::uint8_t>{storage}.first(*encoded));
  require(decoded.status == DecodeStatus::accepted,
          "BNDUPD decode failed");
  const auto binding = next_binding(decoded.message);
  require(binding.status == BindingParseStatus::accepted &&
              binding.update.address ==
                  router::packet::Ipv4{192U, 0U, 2U, 10U} &&
              binding.update.status == BindingStatus::active &&
              binding.update.client_identifier.size() == client.size() &&
              binding.update.client_hardware_address.size() ==
                  hardware.size() &&
              binding.update.lease_expiration_time == 13'600U &&
              binding.update.potential_expiration_time == 17'200U &&
              binding.next_offset == decoded.message.options.size(),
          "BNDUPD changed binding data");
  require(next_binding(decoded.message, binding.next_offset).status ==
              BindingParseStatus::end,
          "BNDUPD iterator did not terminate");

  const auto acknowledged = encode_binding(
      MessageType::binding_ack, 10'001U, 91U,
      {.address = {192U, 0U, 2U, 10U},
       .status = BindingStatus::active,
       .client_identifier = {},
       .client_hardware_address = {},
       .lease_expiration_time = std::nullopt,
       .potential_expiration_time = std::nullopt,
       .client_last_transaction_time = std::nullopt,
       .start_time_of_state = std::nullopt,
       .reject_reason = std::nullopt},
      storage);
  require(acknowledged.has_value(), "BNDACK encode failed");
  const auto ack =
      decode(std::span<const std::uint8_t>{storage}.first(*acknowledged));
  const auto ack_binding = next_binding(ack.message);
  require(ack.status == DecodeStatus::accepted &&
              ack_binding.status == BindingParseStatus::accepted &&
              !ack_binding.update.reject_reason,
          "accepting BNDACK was not address-only");
}

void session_negotiates_and_waits_for_peer_state() {
  const auto now = Session::Clock::time_point{};
  const Configuration primary_configuration{
      .relationship_name = "access-pair",
      .role = Role::primary,
      .maximum_client_lead_time_seconds = 3600U,
      .startup_seconds = 10U,
      .maximum_response_delay_seconds = 30U,
      .safe_period_seconds = 120U,
      .maximum_unacked_updates = 64U};
  auto secondary_configuration = primary_configuration;
  secondary_configuration.role = Role::secondary;
  NegotiationParameters negotiation{
      .vendor_class_identifier = "router-simulator",
      .tls_request = TlsRequest::disabled};
  negotiation.secondary_hash_buckets.fill(0x55U);

  Session primary;
  Session secondary;
  require(primary.configure(primary_configuration, negotiation, false, 100U,
                            now),
          "primary draft-12 session configuration failed");
  require(secondary.configure(secondary_configuration, negotiation, false,
                              100U, now),
          "secondary draft-12 session configuration failed");
  primary.transport_connected(100U, now);
  secondary.transport_connected(100U, now);

  std::array<std::uint8_t, maximum_message_octets> wire{};
  const auto connect = primary.prepare_next(wire, 100U, now);
  require(connect.has_value(), "primary did not produce CONNECT");
  auto decoded =
      decode(std::span<const std::uint8_t>{wire}.first(*connect));
  require(decoded.status == DecodeStatus::accepted &&
              decoded.message.type == MessageType::connect &&
              secondary.receive(decoded.message, 100U, now).kind ==
                  SessionEventKind::none,
          "secondary rejected the draft-12 CONNECT");

  // CONNECT queues CONNECTACK followed by STATE. Restore between receive and
  // transmit to prove that checkpointing preserves the protocol order rather
  // than merely recreating an endpoint in the same broad state.
  const auto saved_secondary = secondary.checkpoint(now);
  Session restored_secondary;
  require(restored_secondary.restore(
              saved_secondary, now + std::chrono::seconds{5}),
          "secondary session checkpoint restore failed");
  const auto ack = restored_secondary.prepare_next(
      wire, 105U, now + std::chrono::seconds{5});
  require(ack.has_value(), "secondary did not produce CONNECTACK");
  decoded = decode(std::span<const std::uint8_t>{wire}.first(*ack));
  require(decoded.status == DecodeStatus::accepted &&
              decoded.message.type == MessageType::connect_ack &&
              primary.receive(decoded.message, 100U, now).kind ==
                  SessionEventKind::none,
          "primary rejected the draft-12 CONNECTACK");

  // Draft section 8.3 requires STATE reception before communications is OK.
  // Merely completing TCP and CONNECT/CONNECTACK must not make leases usable.
  require(!primary.endpoint().communications_ok() &&
              !secondary.endpoint().communications_ok(),
          "CONNECT negotiation bypassed mandatory STATE reception");
  const auto primary_state = primary.prepare_next(wire, 105U, now);
  require(primary_state.has_value(), "primary did not send second-message STATE");
  decoded =
      decode(std::span<const std::uint8_t>{wire}.first(*primary_state));
  require(decoded.status == DecodeStatus::accepted &&
              decoded.message.type == MessageType::state &&
              secondary.receive(decoded.message, 100U, now).kind ==
                  SessionEventKind::partner_state_changed &&
              secondary.endpoint().communications_ok(),
          "secondary did not establish communications from peer STATE");
}

void endpoint_preserves_recovery_and_safe_periods() {
  Endpoint endpoint;
  const auto start = Endpoint::Clock::time_point{};
  require(endpoint.configure(
              {.relationship_name = "access-pair",
               .role = Role::secondary,
               .maximum_client_lead_time_seconds = 60U,
               .startup_seconds = 10U,
               .maximum_response_delay_seconds = 30U,
               .safe_period_seconds = 120U,
               .maximum_unacked_updates = 64U},
              100U, start),
          "valid DHCPv4 failover relationship was rejected");
  require(endpoint.state() == State::startup &&
              endpoint.responsiveness() == Responsiveness::unresponsive,
          "STARTUP endpoint served DHCP clients");

  endpoint.communication_changed(true, 101U, start);
  endpoint.partner_state_changed(State::normal, 101U, start);
  require(endpoint.state() == State::recover,
          "partner contact did not enter RECOVER");
  endpoint.update_request_finished(102U, start);
  require(endpoint.state() == State::recover_wait,
          "UPDDONE did not enter RECOVER-WAIT");

  endpoint.communication_changed(false, 103U, start);
  endpoint.service(162U, start + std::chrono::seconds{60});
  require(endpoint.state() == State::recover_done &&
              endpoint.responsiveness() ==
                  Responsiveness::renew_responsive,
          "MCLT recovery interlock did not finish safely");

  const auto saved =
      endpoint.checkpoint(start + std::chrono::seconds{60});
  Endpoint restored;
  require(restored.restore(saved, start + std::chrono::seconds{600}) &&
              restored.state() == State::recover_done,
          "DHCPv4 failover checkpoint changed relationship state");

  Endpoint isolated;
  require(isolated.configure(
              {.relationship_name = "isolated-pair",
               .role = Role::primary,
               .maximum_client_lead_time_seconds = 60U,
               .startup_seconds = 10U,
               .maximum_response_delay_seconds = 30U,
               .safe_period_seconds = 120U,
               .maximum_unacked_updates = 64U},
              200U, start),
          "isolated relationship configuration failed");
  isolated.communication_changed(true, 201U, start);
  isolated.partner_state_changed(State::normal, 201U, start);
  isolated.update_request_finished(202U, start);
  isolated.service(262U, start + std::chrono::seconds{60});
  // No partner traffic was received during the response-delay interval, so
  // service correctly marked the old connection unavailable. A real
  // reconnect precedes the partner STATE that completes the interlock.
  isolated.partner_state_changed(State::recover_done, 263U,
                                 start + std::chrono::seconds{60});
  isolated.communication_changed(true, 263U,
                                 start + std::chrono::seconds{60});
  require(isolated.state() == State::normal,
          "recovery endpoints did not interlock into NORMAL");
  isolated.communication_changed(false, 264U,
                                 start + std::chrono::seconds{60});
  require(isolated.state() == State::communications_interrupted,
          "lost connection did not enter COMMUNICATIONS-INTERRUPTED");
  isolated.service(384U, start + std::chrono::seconds{180});
  require(isolated.state() == State::partner_down &&
              isolated.responsiveness() == Responsiveness::responsive,
          "safe period did not enter PARTNER-DOWN");
}

} // namespace

void dhcpv4_failover_tests() {
  codec_and_digest_round_trip();
  decoder_rejects_invalid_framing_and_order();
  stream_decoder_preserves_tcp_message_boundaries();
  negotiation_and_state_messages_follow_draft_option_sets();
  binding_update_and_ack_preserve_binding_identity();
  session_negotiates_and_waits_for_peer_state();
  endpoint_preserves_recovery_and_safe_periods();
}
