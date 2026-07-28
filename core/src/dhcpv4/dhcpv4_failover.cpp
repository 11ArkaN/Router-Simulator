// Historical DHCPv4 failover draft-12 codec implementation.
//
// The decoder validates framing before returning borrowed option views. It
// deliberately does not normalize ordered binding groups, authenticate a
// digest or change lease state. Those operations require relationship-owned
// policy and must occur only after the complete message is admitted.

#include "router/dhcpv4_failover.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace router::dhcpv4::failover {
namespace {

std::uint16_t u16(std::span<const std::uint8_t> bytes) noexcept {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[0U]) << 8U | bytes[1U]);
}

std::uint32_t u32(std::span<const std::uint8_t> bytes) noexcept {
  return static_cast<std::uint32_t>(bytes[0U]) << 24U |
         static_cast<std::uint32_t>(bytes[1U]) << 16U |
         static_cast<std::uint32_t>(bytes[2U]) << 8U | bytes[3U];
}

void put_u16(std::span<std::uint8_t> output, std::uint16_t value) noexcept {
  output[0U] = static_cast<std::uint8_t>(value >> 8U);
  output[1U] = static_cast<std::uint8_t>(value);
}

void put_u32(std::span<std::uint8_t> output, std::uint32_t value) noexcept {
  output[0U] = static_cast<std::uint8_t>(value >> 24U);
  output[1U] = static_cast<std::uint8_t>(value >> 16U);
  output[2U] = static_cast<std::uint8_t>(value >> 8U);
  output[3U] = static_cast<std::uint8_t>(value);
}

std::optional<MessageType> known_type(std::uint8_t value) noexcept {
  if (value < static_cast<std::uint8_t>(MessageType::pool_request) ||
      value > static_cast<std::uint8_t>(MessageType::disconnect))
    return std::nullopt;
  return static_cast<MessageType>(value);
}

bool may_repeat(MessageType type, std::uint16_t code) noexcept {
  // Draft section 6.2 permits repetitions only where a BNDUPD or BNDACK
  // carries several ordered binding groups. Each group starts with an
  // assigned address and the following binding fields apply to that address.
  return (type == MessageType::binding_update ||
          type == MessageType::binding_ack) &&
         code >= static_cast<std::uint16_t>(OptionCode::assigned_ip_address) &&
         code <=
             static_cast<std::uint16_t>(OptionCode::start_time_of_state);
}

struct DigestLocation {
  std::span<std::uint8_t> digest;
};

std::optional<DigestLocation>
digest_location(std::span<std::uint8_t> message,
                DigestStatus &failure) noexcept {
  if (message.size() < fixed_header_octets ||
      u16(std::span<const std::uint8_t>{message}.first(2U)) !=
          message.size()) {
    failure = DigestStatus::malformed;
    return std::nullopt;
  }
  const auto option_start = static_cast<std::size_t>(message[3U]) + 4U;
  if (option_start + 4U > message.size()) {
    failure = DigestStatus::malformed;
    return std::nullopt;
  }
  const auto first = std::span<const std::uint8_t>{message}.subspan(
      option_start);
  if (u16(first.first(2U)) !=
      static_cast<std::uint16_t>(OptionCode::message_digest)) {
    // Distinguish a missing digest from one placed later in the option list.
    // The distinction maps directly to draft reject reasons 21 and 20.
    std::size_t offset{};
    while (offset + 4U <= first.size()) {
      const auto code = u16(first.subspan(offset, 2U));
      const auto size = u16(first.subspan(offset + 2U, 2U));
      offset += 4U;
      if (size > first.size() - offset) {
        failure = DigestStatus::malformed;
        return std::nullopt;
      }
      if (code == static_cast<std::uint16_t>(OptionCode::message_digest)) {
        failure = DigestStatus::not_first;
        return std::nullopt;
      }
      offset += size;
    }
    failure = DigestStatus::missing;
    return std::nullopt;
  }
  const auto size = u16(first.subspan(2U, 2U));
  if (size != 17U || first.size() < 4U + size) {
    failure = DigestStatus::malformed;
    return std::nullopt;
  }
  if (first[4U] != 1U) {
    failure = DigestStatus::unsupported_type;
    return std::nullopt;
  }
  return DigestLocation{
      message.subspan(option_start + 5U, 16U)};
}

bool calculate_digest(std::span<const std::uint8_t> message,
                      std::span<const std::uint8_t> secret,
                      std::span<std::uint8_t, 16U> output) noexcept {
  if (secret.empty())
    return false;
  EVP_MAC *raw_mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  if (!raw_mac)
    return false;
  EVP_MAC_CTX *context = EVP_MAC_CTX_new(raw_mac);
  EVP_MAC_free(raw_mac);
  if (!context)
    return false;

  char digest_name[] = "MD5";
  OSSL_PARAM parameters[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0U),
      OSSL_PARAM_construct_end()};
  std::size_t produced{};
  const auto ok =
      EVP_MAC_init(context, secret.data(), secret.size(), parameters) == 1 &&
      EVP_MAC_update(context, message.data(), message.size()) == 1 &&
      // draft-12 authenticates the message concatenated with the shared
      // secret, in addition to using that secret as the HMAC key.
      EVP_MAC_update(context, secret.data(), secret.size()) == 1 &&
      EVP_MAC_final(context, output.data(), &produced, output.size()) == 1 &&
      produced == output.size();
  EVP_MAC_CTX_free(context);
  return ok;
}

bool valid_state(State state) noexcept {
  switch (state) {
  case State::startup:
  case State::normal:
  case State::communications_interrupted:
  case State::partner_down:
  case State::potential_conflict:
  case State::recover:
  case State::recover_wait:
  case State::recover_done:
  case State::resolution_interrupted:
  case State::conflict_done:
  case State::paused:
  case State::shutdown:
    return true;
  }
  return false;
}

bool valid_server_state(ServerState state) noexcept {
  const auto wire = static_cast<std::uint8_t>(state);
  return wire >= static_cast<std::uint8_t>(ServerState::startup) &&
         wire <= static_cast<std::uint8_t>(ServerState::conflict_done);
}

State local_state(ServerState state) noexcept {
  switch (state) {
  case ServerState::startup:
    return State::startup;
  case ServerState::normal:
    return State::normal;
  case ServerState::communications_interrupted:
    return State::communications_interrupted;
  case ServerState::partner_down:
    return State::partner_down;
  case ServerState::potential_conflict:
    return State::potential_conflict;
  case ServerState::recover:
    return State::recover;
  case ServerState::paused:
    return State::paused;
  case ServerState::shutdown:
    return State::shutdown;
  case ServerState::recover_done:
    return State::recover_done;
  case ServerState::resolution_interrupted:
    return State::resolution_interrupted;
  case ServerState::conflict_done:
    return State::conflict_done;
  }
  return State::startup;
}

std::optional<std::uint32_t>
option_u32(const MessageView &message, OptionCode code) noexcept {
  const auto option =
      message.first(static_cast<std::uint16_t>(code));
  if (!option || option->value.size() != 4U)
    return std::nullopt;
  return u32(option->value);
}

} // namespace

StreamIngestResult
StreamDecoder::ingest(std::span<const std::uint8_t> input) noexcept {
  if (failed_)
    return {.status = StreamStatus::overflow};
  if (ready_)
    return {.status = StreamStatus::message_ready,
            .message = std::span<const std::uint8_t>{storage_}.first(
                expected_)};

  std::size_t accepted{};
  while (accepted < input.size()) {
    // The draft length is inclusive of its own two octets. Read no payload
    // byte until both length octets are present, because a one-byte TCP split
    // must not be interpreted using stale storage from an earlier message.
    if (expected_ == 0U && occupied_ < 2U) {
      const auto needed = 2U - occupied_;
      const auto copied = std::min(needed, input.size() - accepted);
      std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(accepted),
                  copied,
                  storage_.begin() + static_cast<std::ptrdiff_t>(occupied_));
      occupied_ += copied;
      accepted += copied;
      if (occupied_ < 2U)
        break;
      expected_ =
          u16(std::span<const std::uint8_t>{storage_}.first(2U));
      if (expected_ < fixed_header_octets ||
          expected_ > maximum_message_octets) {
        failed_ = true;
        return {.status = StreamStatus::invalid_length,
                .accepted_octets = accepted};
      }
    }

    const auto needed = expected_ - occupied_;
    const auto copied = std::min(needed, input.size() - accepted);
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(accepted), copied,
                storage_.begin() + static_cast<std::ptrdiff_t>(occupied_));
    occupied_ += copied;
    accepted += copied;
    if (occupied_ == expected_) {
      ready_ = true;
      return {.status = StreamStatus::message_ready,
              .accepted_octets = accepted,
              .message = std::span<const std::uint8_t>{storage_}.first(
                  expected_)};
    }
  }
  return {.status = StreamStatus::need_more, .accepted_octets = accepted};
}

StreamDecoderCheckpoint StreamDecoder::checkpoint() const {
  return {
      .bytes = std::vector<std::uint8_t>{storage_.begin(),
                                        storage_.begin() +
                                            static_cast<std::ptrdiff_t>(
                                                occupied_)},
      .expected = expected_,
      .ready = ready_,
      .failed = failed_};
}

bool StreamDecoder::restore(
    const StreamDecoderCheckpoint &state) noexcept {
  // Before the length prefix is complete, expected is zero and at most one
  // octet may be retained. Afterwards occupied cannot exceed the advertised
  // bounded frame. A ready checkpoint must contain the complete message.
  const auto valid_partial_prefix =
      state.expected == 0U && state.bytes.size() <= 1U && !state.ready;
  const auto valid_body =
      state.expected >= fixed_header_octets &&
      state.expected <= maximum_message_octets &&
      state.bytes.size() <= state.expected &&
      state.ready == (state.bytes.size() == state.expected);
  if ((!valid_partial_prefix && !valid_body) ||
      (state.failed && state.ready))
    return false;
  std::copy(state.bytes.begin(), state.bytes.end(), storage_.begin());
  occupied_ = state.bytes.size();
  expected_ = state.expected;
  ready_ = state.ready;
  failed_ = state.failed;
  return true;
}

void StreamDecoder::consume() noexcept {
  // consume is the only legal lifetime boundary for MessageView spans returned
  // by decode(). Clearing counters makes the entire fixed buffer available to
  // the next framed message without allocating or shifting TCP bytes.
  if (!ready_)
    return;
  occupied_ = 0U;
  expected_ = 0U;
  ready_ = false;
}

std::optional<OptionView>
MessageView::first(std::uint16_t wanted) const noexcept {
  std::size_t offset{};
  while (offset + 4U <= options.size()) {
    const auto code = u16(options.subspan(offset, 2U));
    const auto size = u16(options.subspan(offset + 2U, 2U));
    offset += 4U;
    if (size > options.size() - offset)
      return std::nullopt;
    if (code == wanted)
      return OptionView{code, options.subspan(offset, size)};
    offset += size;
  }
  return std::nullopt;
}

DecodeResult decode(std::span<const std::uint8_t> message) noexcept {
  if (message.size() < fixed_header_octets)
    return {.status = DecodeStatus::truncated_header};
  const auto encoded_size = u16(message.first(2U));
  if (encoded_size < fixed_header_octets ||
      encoded_size > maximum_message_octets ||
      encoded_size != message.size())
    return {.status = DecodeStatus::invalid_length};

  const auto type = known_type(message[2U]);
  if (!type) {
    // Draft section 6.1 reserves 128 through 255 for optional extensions that
    // an implementation should ignore. Unknown required messages close the
    // connection and are reported separately to the relationship owner.
    return {.status = message[2U] >= 128U
                          ? DecodeStatus::optional_message_ignored
                          : DecodeStatus::unknown_required_message};
  }
  const auto payload_offset = message[3U];
  if (payload_offset < version_one_payload_offset ||
      static_cast<std::size_t>(payload_offset) + 4U > message.size())
    return {.status = DecodeStatus::invalid_payload_offset};
  const auto transaction_id = u32(message.subspan(8U, 4U));
  if (transaction_id == 0U)
    return {.status = DecodeStatus::invalid_transaction_id};

  const auto option_start = static_cast<std::size_t>(payload_offset) + 4U;
  const auto options = message.subspan(option_start);
  std::array<std::uint16_t,
             device_catalog::dhcp_failover_options_per_message>
      seen{};
  std::size_t seen_count{};
  std::size_t option_count{};
  std::size_t offset{};
  while (offset < options.size()) {
    if (options.size() - offset < 4U)
      return {.status = DecodeStatus::malformed_option};
    const auto code = u16(options.subspan(offset, 2U));
    const auto size = u16(options.subspan(offset + 2U, 2U));
    offset += 4U;
    if (size > options.size() - offset)
      return {.status = DecodeStatus::malformed_option};
    if (++option_count >
        device_catalog::dhcp_failover_options_per_message)
      return {.status = DecodeStatus::too_many_options};
    if (!may_repeat(*type, code)) {
      if (std::find(seen.begin(),
                    seen.begin() + static_cast<std::ptrdiff_t>(seen_count),
                    code) !=
          seen.begin() + static_cast<std::ptrdiff_t>(seen_count))
        return {.status = DecodeStatus::duplicate_option};
      seen[seen_count++] = code;
    }
    offset += size;
  }

  MessageView view{*type,
                   payload_offset,
                   u32(message.subspan(4U, 4U)),
                   transaction_id,
                   message.subspan(fixed_header_octets,
                                   option_start - fixed_header_octets),
                   options};
  if ((*type == MessageType::connect ||
       *type == MessageType::connect_ack) &&
      (!view.first(static_cast<std::uint16_t>(
           OptionCode::relationship_name)) ||
       !view.first(
           static_cast<std::uint16_t>(OptionCode::protocol_version))))
    return {.status = DecodeStatus::invalid_message_options};
  return {.status = DecodeStatus::accepted,
          .message = view,
          .option_count = option_count};
}

DigestStatus sign_hmac_md5(std::span<std::uint8_t> message,
                           std::span<const std::uint8_t> secret) noexcept {
  DigestStatus failure{DigestStatus::malformed};
  const auto location = digest_location(message, failure);
  if (!location)
    return failure;
  std::fill(location->digest.begin(), location->digest.end(), 0U);
  std::array<std::uint8_t, 16U> calculated{};
  if (!calculate_digest(message, secret, calculated))
    return DigestStatus::cryptographic_failure;
  std::copy(calculated.begin(), calculated.end(), location->digest.begin());
  return DigestStatus::accepted;
}

DigestStatus verify_hmac_md5(std::span<std::uint8_t> message,
                             std::span<const std::uint8_t> secret) noexcept {
  DigestStatus failure{DigestStatus::malformed};
  const auto location = digest_location(message, failure);
  if (!location)
    return failure;
  std::array<std::uint8_t, 16U> received{};
  std::copy(location->digest.begin(), location->digest.end(), received.begin());
  std::fill(location->digest.begin(), location->digest.end(), 0U);
  std::array<std::uint8_t, 16U> calculated{};
  const auto calculated_ok = calculate_digest(message, secret, calculated);
  std::copy(received.begin(), received.end(), location->digest.begin());
  if (!calculated_ok)
    return DigestStatus::cryptographic_failure;
  return CRYPTO_memcmp(received.data(), calculated.data(), received.size()) == 0
             ? DigestStatus::accepted
             : DigestStatus::mismatch;
}

std::optional<std::size_t>
insert_hmac_md5(std::span<std::uint8_t> storage,
                std::size_t message_octets,
                std::span<const std::uint8_t> secret) noexcept {
  constexpr std::size_t digest_tlv_octets = 21U;
  if (secret.empty() || message_octets < fixed_header_octets ||
      message_octets > maximum_message_octets - digest_tlv_octets ||
      storage.size() < message_octets + digest_tlv_octets)
    return std::nullopt;
  const auto option_offset =
      static_cast<std::size_t>(storage[3U]) + 4U;
  if (option_offset > message_octets)
    return std::nullopt;

  std::move_backward(
      storage.begin() + static_cast<std::ptrdiff_t>(option_offset),
      storage.begin() + static_cast<std::ptrdiff_t>(message_octets),
      storage.begin() +
          static_cast<std::ptrdiff_t>(message_octets + digest_tlv_octets));
  const auto write_u16 = [&](std::size_t offset, std::uint16_t value) {
    storage[offset] = static_cast<std::uint8_t>(value >> 8U);
    storage[offset + 1U] = static_cast<std::uint8_t>(value);
  };
  write_u16(option_offset,
            static_cast<std::uint16_t>(OptionCode::message_digest));
  write_u16(option_offset + 2U, 17U);
  storage[option_offset + 4U] = 1U;
  std::fill_n(storage.begin() +
                  static_cast<std::ptrdiff_t>(option_offset + 5U),
              16U, 0U);
  const auto result_octets = message_octets + digest_tlv_octets;
  write_u16(0U, static_cast<std::uint16_t>(result_octets));
  return sign_hmac_md5(storage.first(result_octets), secret) ==
                 DigestStatus::accepted
             ? std::optional{result_octets}
             : std::nullopt;
}

Encoder::Encoder(std::span<std::uint8_t> output) noexcept : output_(output) {}

bool Encoder::begin(MessageType type, std::uint32_t sent_time,
                    std::uint32_t transaction_id) noexcept {
  if (begun_ || failed_ || output_.size() < fixed_header_octets ||
      transaction_id == 0U) {
    failed_ = true;
    return false;
  }
  output_[0U] = output_[1U] = 0U;
  output_[2U] = static_cast<std::uint8_t>(type);
  output_[3U] = version_one_payload_offset;
  put_u32(output_.subspan(4U, 4U), sent_time);
  put_u32(output_.subspan(8U, 4U), transaction_id);
  occupied_ = fixed_header_octets;
  begun_ = true;
  return true;
}

bool Encoder::option(std::uint16_t code,
                     std::span<const std::uint8_t> value) noexcept {
  if (!begun_ || failed_ ||
      option_count_ >=
          device_catalog::dhcp_failover_options_per_message ||
      value.size() > std::numeric_limits<std::uint16_t>::max() ||
      occupied_ + 4U + value.size() > maximum_message_octets ||
      output_.size() - occupied_ < 4U + value.size()) {
    failed_ = true;
    return false;
  }
  put_u16(output_.subspan(occupied_, 2U), code);
  put_u16(output_.subspan(occupied_ + 2U, 2U),
          static_cast<std::uint16_t>(value.size()));
  std::copy(value.begin(), value.end(),
            output_.begin() + static_cast<std::ptrdiff_t>(occupied_ + 4U));
  occupied_ += 4U + value.size();
  ++option_count_;
  return true;
}

std::span<const std::uint8_t> Encoder::message() noexcept {
  if (!begun_ || failed_ ||
      occupied_ > std::numeric_limits<std::uint16_t>::max())
    return {};
  put_u16(output_.first(2U), static_cast<std::uint16_t>(occupied_));
  return output_.first(occupied_);
}

NegotiationStatus validate_negotiation(
    const MessageView &message, const Configuration &local, bool reply,
    bool secured_transport, NegotiatedParameters &negotiated) noexcept {
  const auto expected =
      reply ? MessageType::connect_ack : MessageType::connect;
  if (message.type != expected)
    return NegotiationStatus::wrong_message;

  const auto name = message.first(
      static_cast<std::uint16_t>(OptionCode::relationship_name));
  const auto version = message.first(
      static_cast<std::uint16_t>(OptionCode::protocol_version));
  const auto maximum =
      option_u32(message, OptionCode::maximum_unacked_binding_updates);
  const auto receive_timer =
      option_u32(message, OptionCode::receive_timer);
  const auto vendor = message.first(
      static_cast<std::uint16_t>(OptionCode::vendor_class_identifier));
  if (!name || !version || !maximum || !receive_timer || !vendor)
    return NegotiationStatus::missing_required_option;
  if (name->value.empty() || version->value.size() != 1U ||
      vendor->value.empty() || *maximum == 0U ||
      *maximum > device_catalog::dhcp_failover_updates_in_flight ||
      *receive_timer == 0U)
    return NegotiationStatus::malformed_option;
  if (name->value.size() != local.relationship_name.size() ||
      !std::equal(name->value.begin(), name->value.end(),
                  local.relationship_name.begin()))
    return NegotiationStatus::relationship_mismatch;
  if (version->value[0U] != 1U)
    return NegotiationStatus::protocol_version_mismatch;

  auto tls = TlsRequest::disabled;
  const auto tls_code =
      reply ? OptionCode::tls_reply : OptionCode::tls_request;
  const auto tls_option =
      message.first(static_cast<std::uint16_t>(tls_code));
  if (secured_transport) {
    // After TLS negotiation the repeated CONNECT and CONNECTACK omit both TLS
    // options. Seeing one here indicates that the peer restarted negotiation
    // inside a protected application stream.
    if (tls_option)
      return NegotiationStatus::unsupported_tls_request;
  } else {
    if (!tls_option || tls_option->value.size() != 1U)
      return NegotiationStatus::missing_required_option;
    const auto value = tls_option->value[0U];
    if ((!reply && value > static_cast<std::uint8_t>(TlsRequest::required)) ||
        (reply && value > 1U))
      return NegotiationStatus::unsupported_tls_request;
    tls = static_cast<TlsRequest>(value);
  }

  std::array<std::uint8_t, 32U> hash_buckets{};
  std::uint32_t mclt = local.maximum_client_lead_time_seconds;
  if (!reply) {
    const auto remote_mclt =
        option_u32(message, OptionCode::maximum_client_lead_time);
    const auto hba = message.first(
        static_cast<std::uint16_t>(OptionCode::hash_bucket_assignment));
    if (!remote_mclt || !hba)
      return NegotiationStatus::missing_required_option;
    if (*remote_mclt == 0U || hba->value.size() != hash_buckets.size())
      return NegotiationStatus::malformed_option;
    std::copy(hba->value.begin(), hba->value.end(), hash_buckets.begin());
    mclt = *remote_mclt;
  }

  negotiated = {.maximum_client_lead_time_seconds = mclt,
                .receive_timer_seconds = *receive_timer,
                .maximum_unacked_updates = *maximum,
                .tls_request = tls,
                .secondary_hash_buckets = hash_buckets};
  return NegotiationStatus::accepted;
}

std::optional<std::size_t> encode_negotiation(
    MessageType type, std::uint32_t sent_time, std::uint32_t transaction_id,
    const Configuration &configuration,
    const NegotiationParameters &parameters, bool secured_transport,
    std::span<std::uint8_t> output) noexcept {
  const auto reply = type == MessageType::connect_ack;
  if ((!reply && type != MessageType::connect) ||
      configuration.relationship_name.empty() ||
      configuration.maximum_client_lead_time_seconds == 0U ||
      configuration.maximum_response_delay_seconds == 0U ||
      configuration.maximum_unacked_updates == 0U ||
      parameters.vendor_class_identifier.empty() ||
      parameters.vendor_class_identifier.size() >
          std::numeric_limits<std::uint16_t>::max() ||
      (reply && parameters.tls_request == TlsRequest::required))
    return std::nullopt;

  std::array<std::uint8_t, 4U> maximum{};
  std::array<std::uint8_t, 4U> receive_timer{};
  std::array<std::uint8_t, 4U> mclt{};
  std::array<std::uint8_t, 1U> version{1U};
  std::array<std::uint8_t, 1U> tls{
      static_cast<std::uint8_t>(parameters.tls_request)};
  put_u32(maximum, configuration.maximum_unacked_updates);
  put_u32(receive_timer, configuration.maximum_response_delay_seconds);
  put_u32(mclt, configuration.maximum_client_lead_time_seconds);
  const auto name = std::span<const std::uint8_t>{
      reinterpret_cast<const std::uint8_t *>(
          configuration.relationship_name.data()),
      configuration.relationship_name.size()};
  const auto vendor = std::span<const std::uint8_t>{
      reinterpret_cast<const std::uint8_t *>(
          parameters.vendor_class_identifier.data()),
      parameters.vendor_class_identifier.size()};

  Encoder encoder{output};
  if (!encoder.begin(type, sent_time, transaction_id) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::relationship_name), name) ||
      !encoder.option(static_cast<std::uint16_t>(
                          OptionCode::maximum_unacked_binding_updates),
                      maximum) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::receive_timer),
          receive_timer) ||
      !encoder.option(static_cast<std::uint16_t>(
                          OptionCode::vendor_class_identifier),
                      vendor) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::protocol_version), version) ||
      (!secured_transport &&
       !encoder.option(
           static_cast<std::uint16_t>(
               reply ? OptionCode::tls_reply : OptionCode::tls_request),
           tls)) ||
      (!reply &&
       (!encoder.option(
            static_cast<std::uint16_t>(
                OptionCode::maximum_client_lead_time),
            mclt) ||
        !encoder.option(
            static_cast<std::uint16_t>(OptionCode::hash_bucket_assignment),
            parameters.secondary_hash_buckets))))
    return std::nullopt;
  return encoder.message().size();
}

std::optional<std::size_t>
encode_state(std::uint32_t sent_time, std::uint32_t transaction_id,
             const StateAdvertisement &state,
             std::span<std::uint8_t> output) noexcept {
  // STARTUP is never sent as the wire state. During STARTUP the owner supplies
  // the durable pre-restart state and sets startup=true.
  if (!valid_server_state(state.state) ||
      state.state == ServerState::startup)
    return std::nullopt;
  std::array<std::uint8_t, 1U> wire_state{
      static_cast<std::uint8_t>(state.state)};
  std::array<std::uint8_t, 1U> flags{
      static_cast<std::uint8_t>(state.startup ? 1U : 0U)};
  std::array<std::uint8_t, 4U> started{};
  put_u32(started, state.started_at);
  Encoder encoder{output};
  if (!encoder.begin(MessageType::state, sent_time, transaction_id) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::server_state),
          wire_state) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::server_flags), flags) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::start_time_of_state),
          started))
    return std::nullopt;
  return encoder.message().size();
}

std::optional<StateAdvertisement>
parse_state(const MessageView &message) noexcept {
  if (message.type != MessageType::state)
    return std::nullopt;
  const auto state = message.first(
      static_cast<std::uint16_t>(OptionCode::server_state));
  const auto flags = message.first(
      static_cast<std::uint16_t>(OptionCode::server_flags));
  const auto started =
      option_u32(message, OptionCode::start_time_of_state);
  if (!state || state->value.size() != 1U || !flags ||
      flags->value.size() != 1U || !started ||
      (flags->value[0U] & 0xfeU) != 0U)
    return std::nullopt;
  const auto decoded = static_cast<ServerState>(state->value[0U]);
  if (!valid_server_state(decoded) || decoded == ServerState::startup)
    return std::nullopt;
  return StateAdvertisement{.state = decoded,
                            .startup = (flags->value[0U] & 1U) != 0U,
                            .started_at = *started};
}

BindingParseResult next_binding(const MessageView &message,
                                std::size_t offset) noexcept {
  if (message.type != MessageType::binding_update &&
      message.type != MessageType::binding_ack)
    return {.status = BindingParseStatus::wrong_message};
  if (offset == message.options.size())
    return {.status = BindingParseStatus::end,
            .next_offset = offset};
  if (offset > message.options.size() ||
      message.options.size() - offset < 8U)
    return {.status = BindingParseStatus::malformed};

  const auto option = [&](std::size_t at)
      -> std::optional<std::pair<std::uint16_t,
                                 std::span<const std::uint8_t>>> {
    if (message.options.size() - at < 4U)
      return std::nullopt;
    const auto code = u16(message.options.subspan(at, 2U));
    const auto size = u16(message.options.subspan(at + 2U, 2U));
    if (size > message.options.size() - at - 4U)
      return std::nullopt;
    return std::pair{
        code, message.options.subspan(at + 4U, size)};
  };

  const auto assigned = option(offset);
  if (!assigned ||
      assigned->first !=
          static_cast<std::uint16_t>(OptionCode::assigned_ip_address) ||
      assigned->second.size() != 4U)
    return {.status = BindingParseStatus::missing_required_option};
  BindingUpdateView update{
      .address = {assigned->second[0U], assigned->second[1U],
                  assigned->second[2U], assigned->second[3U]},
      .status = BindingStatus::free,
      .client_identifier = {},
      .client_hardware_address = {},
      .lease_expiration_time = std::nullopt,
      .potential_expiration_time = std::nullopt,
      .client_last_transaction_time = std::nullopt,
      .start_time_of_state = std::nullopt,
      .reject_reason = std::nullopt};
  std::array<std::uint16_t, 16U> seen{};
  std::size_t seen_count{};
  auto cursor = offset + 8U;
  bool has_status{};
  while (cursor < message.options.size()) {
    const auto current = option(cursor);
    if (!current)
      return {.status = BindingParseStatus::malformed};
    if (current->first ==
        static_cast<std::uint16_t>(OptionCode::assigned_ip_address))
      break;
    if (seen_count == seen.size() ||
        std::find(seen.begin(),
                  seen.begin() + static_cast<std::ptrdiff_t>(seen_count),
                  current->first) !=
            seen.begin() + static_cast<std::ptrdiff_t>(seen_count))
      return {.status = BindingParseStatus::malformed};
    seen[seen_count++] = current->first;

    const auto scalar_u32 = [&]() -> std::optional<std::uint32_t> {
      return current->second.size() == 4U
                 ? std::optional<std::uint32_t>{u32(current->second)}
                 : std::nullopt;
    };
    if (current->first ==
        static_cast<std::uint16_t>(OptionCode::binding_status)) {
      if (current->second.size() != 1U ||
          current->second[0U] <
              static_cast<std::uint8_t>(BindingStatus::free) ||
          current->second[0U] >
              static_cast<std::uint8_t>(BindingStatus::backup))
        return {.status = BindingParseStatus::malformed};
      update.status =
          static_cast<BindingStatus>(current->second[0U]);
      has_status = true;
    } else if (current->first ==
               static_cast<std::uint16_t>(
                   OptionCode::client_identifier)) {
      if (current->second.empty())
        return {.status = BindingParseStatus::malformed};
      update.client_identifier = current->second;
    } else if (current->first ==
               static_cast<std::uint16_t>(
                   OptionCode::client_hardware_address)) {
      // One hardware type octet followed by at least one hardware address
      // octet is the exact draft representation.
      if (current->second.size() < 2U ||
          current->second.size() > 17U)
        return {.status = BindingParseStatus::malformed};
      update.client_hardware_address = current->second;
    } else if (current->first ==
               static_cast<std::uint16_t>(
                   OptionCode::lease_expiration_time)) {
      update.lease_expiration_time = scalar_u32();
      if (!update.lease_expiration_time)
        return {.status = BindingParseStatus::malformed};
    } else if (current->first ==
               static_cast<std::uint16_t>(
                   OptionCode::potential_expiration_time)) {
      update.potential_expiration_time = scalar_u32();
      if (!update.potential_expiration_time)
        return {.status = BindingParseStatus::malformed};
    } else if (current->first ==
               static_cast<std::uint16_t>(
                   OptionCode::client_last_transaction_time)) {
      update.client_last_transaction_time = scalar_u32();
      if (!update.client_last_transaction_time)
        return {.status = BindingParseStatus::malformed};
    } else if (current->first ==
               static_cast<std::uint16_t>(
                   OptionCode::start_time_of_state)) {
      update.start_time_of_state = scalar_u32();
      if (!update.start_time_of_state)
        return {.status = BindingParseStatus::malformed};
    } else if (current->first ==
               static_cast<std::uint16_t>(OptionCode::reject_reason)) {
      if (current->second.size() != 1U)
        return {.status = BindingParseStatus::malformed};
      update.reject_reason = current->second[0U];
    }
    cursor += 4U + current->second.size();
  }

  if (message.type == MessageType::binding_ack)
    return {.status = BindingParseStatus::accepted,
            .update = update,
            .next_offset = cursor};
  if (!has_status ||
      (update.status == BindingStatus::active &&
       (update.client_hardware_address.empty() ||
        !update.lease_expiration_time ||
        !update.potential_expiration_time ||
        !update.client_last_transaction_time)) ||
      (update.status == BindingStatus::abandoned &&
       (!update.client_hardware_address.empty() ||
        !update.client_identifier.empty())))
    return {.status = BindingParseStatus::missing_required_option};
  return {.status = BindingParseStatus::accepted,
          .update = update,
          .next_offset = cursor};
}

std::optional<std::size_t> encode_binding(
    MessageType type, std::uint32_t sent_time, std::uint32_t transaction_id,
    const BindingUpdate &binding,
    std::span<std::uint8_t> output) noexcept {
  if (type != MessageType::binding_update &&
      type != MessageType::binding_ack)
    return std::nullopt;
  const auto wire_status = static_cast<std::uint8_t>(binding.status);
  if (wire_status < static_cast<std::uint8_t>(BindingStatus::free) ||
      wire_status > static_cast<std::uint8_t>(BindingStatus::backup) ||
      binding.client_identifier.size() >
          maximum_client_identifier_octets ||
      (!binding.client_hardware_address.empty() &&
       (binding.client_hardware_address.size() < 2U ||
        binding.client_hardware_address.size() > 17U)))
    return std::nullopt;
  if (type == MessageType::binding_update &&
      ((binding.status == BindingStatus::active &&
        (binding.client_hardware_address.empty() ||
         !binding.lease_expiration_time ||
         !binding.potential_expiration_time ||
         !binding.client_last_transaction_time)) ||
       (binding.status == BindingStatus::abandoned &&
        (!binding.client_hardware_address.empty() ||
         !binding.client_identifier.empty()))))
    return std::nullopt;

  Encoder encoder{output};
  const std::array<std::uint8_t, 4U> address{
      binding.address[0U], binding.address[1U], binding.address[2U],
      binding.address[3U]};
  if (!encoder.begin(type, sent_time, transaction_id) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::assigned_ip_address),
          address))
    return std::nullopt;
  if (type == MessageType::binding_ack) {
    if (binding.reject_reason) {
      const std::array<std::uint8_t, 1U> reason{*binding.reject_reason};
      if (!encoder.option(
              static_cast<std::uint16_t>(OptionCode::reject_reason), reason))
        return std::nullopt;
    }
    return encoder.message().size();
  }

  const std::array<std::uint8_t, 1U> status{wire_status};
  if (!encoder.option(
          static_cast<std::uint16_t>(OptionCode::binding_status), status) ||
      (!binding.client_identifier.empty() &&
       !encoder.option(
           static_cast<std::uint16_t>(OptionCode::client_identifier),
           binding.client_identifier)) ||
      (!binding.client_hardware_address.empty() &&
       !encoder.option(
           static_cast<std::uint16_t>(
               OptionCode::client_hardware_address),
           binding.client_hardware_address)))
    return std::nullopt;
  const auto append_u32 = [&](OptionCode code,
                              std::optional<std::uint32_t> value) {
    if (!value)
      return true;
    std::array<std::uint8_t, 4U> bytes{};
    put_u32(bytes, *value);
    return encoder.option(static_cast<std::uint16_t>(code), bytes);
  };
  if (!append_u32(OptionCode::lease_expiration_time,
                  binding.lease_expiration_time) ||
      !append_u32(OptionCode::potential_expiration_time,
                  binding.potential_expiration_time) ||
      !append_u32(OptionCode::client_last_transaction_time,
                  binding.client_last_transaction_time) ||
      !append_u32(OptionCode::start_time_of_state,
                  binding.start_time_of_state))
    return std::nullopt;
  return encoder.message().size();
}

std::optional<std::size_t> encode_binding_ack(
    std::uint32_t sent_time, std::uint32_t transaction_id,
    std::span<const BindingUpdateView> bindings,
    std::span<std::uint8_t> output) noexcept {
  if (bindings.empty() ||
      bindings.size() > device_catalog::dhcp_failover_updates_in_flight)
    return std::nullopt;
  Encoder encoder{output};
  if (!encoder.begin(MessageType::binding_ack, sent_time, transaction_id))
    return std::nullopt;
  for (const auto &binding : bindings) {
    const std::array<std::uint8_t, 4U> address{
        binding.address[0U], binding.address[1U], binding.address[2U],
        binding.address[3U]};
    const std::array<std::uint8_t, 1U> status{
        static_cast<std::uint8_t>(binding.status)};
    if (!encoder.option(
            static_cast<std::uint16_t>(OptionCode::assigned_ip_address),
            address) ||
        !encoder.option(
            static_cast<std::uint16_t>(OptionCode::binding_status), status))
      return std::nullopt;
  }
  return encoder.message().size();
}

bool Endpoint::configure(Configuration configuration,
                         std::uint32_t absolute_now,
                         Clock::time_point now) {
  if (configuration.relationship_name.empty() ||
      configuration.relationship_name.size() > 128U ||
      configuration.maximum_client_lead_time_seconds == 0U ||
      configuration.startup_seconds == 0U ||
      configuration.maximum_response_delay_seconds == 0U ||
      configuration.maximum_unacked_updates == 0U ||
      configuration.maximum_unacked_updates >
          device_catalog::dhcp_failover_updates_in_flight ||
      (configuration.safe_period_seconds &&
       *configuration.safe_period_seconds == 0U))
    return false;
  configuration_ = std::move(configuration);
  configured_ = true;
  communications_ok_ = false;
  partner_state_.reset();
  update_request_complete_ = false;
  // Draft-12 section 9.3 makes the startup duration implementation-dependent
  // and recommends making it configurable. The profile-facing owner supplies
  // that explicit value, so this protocol primitive never hides a timer.
  transition(State::startup, absolute_now, now,
             std::chrono::seconds{configuration_.startup_seconds});
  return true;
}

void Endpoint::communication_changed(bool available,
                                     std::uint32_t absolute_now,
                                     Clock::time_point now) noexcept {
  if (!configured_ || available == communications_ok_)
    return;
  communications_ok_ = available;
  contact_deadline_ =
      available
          ? now + std::chrono::seconds{
                      configuration_.maximum_response_delay_seconds}
          : Clock::time_point::max();
  evaluate(absolute_now, now);
}

void Endpoint::partner_state_changed(State state,
                                     std::uint32_t absolute_now,
                                     Clock::time_point now) noexcept {
  if (!configured_ || !valid_state(state))
    return;
  partner_state_ = state;
  evaluate(absolute_now, now);
}

void Endpoint::update_request_finished(std::uint32_t absolute_now,
                                       Clock::time_point now) noexcept {
  if (!configured_)
    return;
  update_request_complete_ = true;
  evaluate(absolute_now, now);
}

bool Endpoint::request_partner_down(std::uint32_t absolute_now,
                                    Clock::time_point now) noexcept {
  if (!configured_ ||
      (state_ != State::normal &&
       state_ != State::communications_interrupted &&
       state_ != State::resolution_interrupted))
    return false;
  // Address ownership from the partner cannot be consumed until this MCLT
  // deadline expires. The allocator reads the state and transition age rather
  // than bypassing the relationship owner.
  transition(State::partner_down, absolute_now, now,
             std::chrono::seconds{
                 configuration_.maximum_client_lead_time_seconds});
  return true;
}

void Endpoint::service(std::uint32_t absolute_now,
                       Clock::time_point now) noexcept {
  if (!configured_)
    return;
  if (communications_ok_ && now >= contact_deadline_) {
    // Section 8.3 permits application-level liveness to fail while TCP still
    // exists. Missing all accepted partner traffic through the configured
    // response delay is therefore real communications evidence.
    communications_ok_ = false;
    contact_deadline_ = Clock::time_point::max();
  }
  evaluate(absolute_now, now);
}

std::uint32_t Endpoint::allocate_transaction_id() noexcept {
  auto value = next_transaction_id_;
  if (value == 0U)
    value = 1U;
  next_transaction_id_ =
      value == std::numeric_limits<std::uint32_t>::max() ? 1U : value + 1U;
  return value;
}

Responsiveness Endpoint::responsiveness() const noexcept {
  switch (state_) {
  case State::normal:
  case State::communications_interrupted:
  case State::partner_down:
  case State::resolution_interrupted:
  case State::conflict_done:
    return Responsiveness::responsive;
  case State::recover_done:
    // Section 9.7.1 permits only RENEWING and REBINDING requests while the
    // recovery interlock completes.
    return Responsiveness::renew_responsive;
  case State::startup:
  case State::potential_conflict:
  case State::recover:
  case State::recover_wait:
  case State::paused:
  case State::shutdown:
    return Responsiveness::unresponsive;
  }
  return Responsiveness::unresponsive;
}

Checkpoint Endpoint::checkpoint(Clock::time_point now) const {
  const auto remaining = [now](Clock::time_point deadline) {
    if (deadline == Clock::time_point::max())
      return std::int64_t{-1};
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               deadline > now ? deadline - now : Clock::duration::zero())
        .count();
  };
  return {.configuration = configuration_,
          .state = state_,
          .partner_state = partner_state_,
          .state_started_absolute = state_started_absolute_,
          .state_remaining_nanoseconds = remaining(state_deadline_),
          .contact_remaining_nanoseconds = remaining(contact_deadline_),
          .next_transaction_id = next_transaction_id_,
          .communications_ok = communications_ok_,
          .update_request_complete = update_request_complete_};
}

bool Endpoint::restore(const Checkpoint &value,
                       Clock::time_point now) noexcept {
  if (value.configuration.relationship_name.empty() ||
      value.configuration.relationship_name.size() > 128U ||
      value.configuration.maximum_client_lead_time_seconds == 0U ||
      value.configuration.startup_seconds == 0U ||
      value.configuration.maximum_response_delay_seconds == 0U ||
      value.configuration.maximum_unacked_updates == 0U ||
      value.configuration.maximum_unacked_updates >
          device_catalog::dhcp_failover_updates_in_flight ||
      (value.configuration.safe_period_seconds &&
       *value.configuration.safe_period_seconds == 0U) ||
      !valid_state(value.state) ||
      (value.partner_state && !valid_state(*value.partner_state)) ||
      value.next_transaction_id == 0U ||
      value.state_remaining_nanoseconds < -1 ||
      value.contact_remaining_nanoseconds < -1)
    return false;
  configuration_ = value.configuration;
  state_ = value.state;
  partner_state_ = value.partner_state;
  state_started_absolute_ = value.state_started_absolute;
  next_transaction_id_ = value.next_transaction_id;
  communications_ok_ = value.communications_ok;
  update_request_complete_ = value.update_request_complete;
  configured_ = true;
  const auto deadline = [now](std::int64_t remaining) {
    return remaining < 0
               ? Clock::time_point::max()
               : now + std::chrono::nanoseconds{remaining};
  };
  state_deadline_ = deadline(value.state_remaining_nanoseconds);
  contact_deadline_ = deadline(value.contact_remaining_nanoseconds);
  return true;
}

void Endpoint::evaluate(std::uint32_t absolute_now,
                        Clock::time_point now) noexcept {
  switch (state_) {
  case State::startup:
    if (communications_ok_ && partner_state_) {
      update_request_complete_ = false;
      transition(State::recover, absolute_now, now);
    } else if (!communications_ok_ && now >= state_deadline_ &&
               configuration_.safe_period_seconds) {
      // Section 9.3.2 permits a configured first-start escape when the peer is
      // unavailable. Reusing the explicit safe period avoids an undocumented
      // second automatic-partner-down timer.
      transition(State::partner_down, absolute_now, now,
                 std::chrono::seconds{
                     configuration_.maximum_client_lead_time_seconds});
    }
    break;
  case State::recover:
    if (communications_ok_ && partner_state_ &&
        (*partner_state_ == State::potential_conflict ||
         *partner_state_ == State::resolution_interrupted ||
         *partner_state_ == State::conflict_done)) {
      update_request_complete_ = false;
      transition(State::potential_conflict, absolute_now, now);
    } else if (communications_ok_ && update_request_complete_) {
      transition(State::recover_wait, absolute_now, now,
                 std::chrono::seconds{
                     configuration_.maximum_client_lead_time_seconds});
    }
    break;
  case State::recover_wait:
    // Section 9.6 keeps the MCLT timer running even if the TCP relationship
    // fails. That prevents a network outage from extending recovery forever.
    if (now >= state_deadline_)
      transition(State::recover_done, absolute_now, now);
    break;
  case State::recover_done:
    if (communications_ok_ && partner_state_ &&
        (*partner_state_ == State::normal ||
         *partner_state_ == State::recover_done)) {
      transition(State::normal, absolute_now, now);
    } else if (communications_ok_ && partner_state_ &&
               *partner_state_ == State::potential_conflict) {
      update_request_complete_ = false;
      transition(State::potential_conflict, absolute_now, now);
    }
    break;
  case State::normal:
    if (!communications_ok_) {
      const auto delay =
          configuration_.safe_period_seconds
              ? std::optional<std::chrono::seconds>{
                    std::chrono::seconds{
                        *configuration_.safe_period_seconds}}
              : std::nullopt;
      transition(State::communications_interrupted, absolute_now, now, delay);
    } else if (partner_state_ && *partner_state_ == State::shutdown) {
      transition(State::partner_down, absolute_now, now,
                 std::chrono::seconds{
                     configuration_.maximum_client_lead_time_seconds});
    } else if (partner_state_ && *partner_state_ != State::normal) {
      transition(State::communications_interrupted, absolute_now, now);
    }
    break;
  case State::communications_interrupted:
    if (communications_ok_) {
      if (partner_state_ &&
          (*partner_state_ == State::normal ||
           *partner_state_ == State::communications_interrupted ||
           *partner_state_ == State::recover_done)) {
        transition(State::normal, absolute_now, now);
      } else if (partner_state_ &&
                 (*partner_state_ == State::partner_down ||
                  *partner_state_ == State::potential_conflict ||
                  *partner_state_ == State::conflict_done ||
                  *partner_state_ == State::resolution_interrupted)) {
        update_request_complete_ = false;
        transition(State::potential_conflict, absolute_now, now);
      } else if (partner_state_ && *partner_state_ == State::shutdown) {
        transition(State::partner_down, absolute_now, now,
                   std::chrono::seconds{
                       configuration_.maximum_client_lead_time_seconds});
      }
    } else if (state_deadline_ != Clock::time_point::max() &&
               now >= state_deadline_) {
      transition(State::partner_down, absolute_now, now,
                 std::chrono::seconds{
                     configuration_.maximum_client_lead_time_seconds});
    }
    break;
  case State::partner_down:
    if (communications_ok_ && partner_state_ &&
        *partner_state_ == State::recover_done) {
      transition(State::normal, absolute_now, now);
    } else if (communications_ok_ && partner_state_ &&
               *partner_state_ != State::recover &&
               *partner_state_ != State::recover_wait &&
               *partner_state_ != State::startup &&
               *partner_state_ != State::paused &&
               *partner_state_ != State::shutdown) {
      update_request_complete_ = false;
      transition(State::potential_conflict, absolute_now, now);
    }
    break;
  case State::potential_conflict:
    if (!communications_ok_) {
      transition(State::resolution_interrupted, absolute_now, now);
    } else if (update_request_complete_) {
      transition(configuration_.role == Role::primary ? State::conflict_done
                                                      : State::normal,
                 absolute_now, now);
    }
    break;
  case State::resolution_interrupted:
    if (communications_ok_) {
      update_request_complete_ = false;
      transition(State::potential_conflict, absolute_now, now);
    }
    break;
  case State::conflict_done:
    if (communications_ok_ && partner_state_ &&
        *partner_state_ == State::normal)
      transition(State::normal, absolute_now, now);
    break;
  case State::paused:
  case State::shutdown:
    // These locally commanded terminal states persist until the management
    // owner explicitly restarts or reconfigures the relationship.
    break;
  }
}

void Endpoint::transition(
    State state, std::uint32_t absolute_now, Clock::time_point now,
    std::optional<std::chrono::seconds> duration) noexcept {
  state_ = state;
  state_started_absolute_ = absolute_now;
  state_deadline_ = duration ? now + *duration : Clock::time_point::max();
}

bool Session::configure(Configuration configuration,
                        NegotiationParameters negotiation,
                        bool secured_transport,
                        std::uint32_t absolute_now,
                        Clock::time_point now) {
  if (negotiation.vendor_class_identifier.empty() ||
      negotiation.vendor_class_identifier.size() > 255U)
    return false;
  Endpoint staged;
  if (!staged.configure(configuration, absolute_now, now))
    return false;
  configuration_ = std::move(configuration);
  negotiation_ = std::move(negotiation);
  endpoint_ = std::move(staged);
  pending_head_ = 0U;
  pending_count_ = 0U;
  synchronization_transaction_id_ = 0U;
  send_interval_seconds_ = 0U;
  phase_ = SessionPhase::disconnected;
  configured_ = true;
  secured_transport_ = secured_transport;
  return true;
}

bool Session::enqueue(MessageType type,
                      std::uint32_t transaction_id) noexcept {
  if (pending_count_ == pending_.size())
    return false;
  const auto tail = (pending_head_ + pending_count_) % pending_.size();
  pending_[tail] = {.type = type, .transaction_id = transaction_id};
  ++pending_count_;
  return true;
}

void Session::transport_connected(std::uint32_t absolute_now,
                                  Clock::time_point now) noexcept {
  if (!configured_)
    return;
  pending_head_ = 0U;
  pending_count_ = 0U;
  synchronization_transaction_id_ = 0U;
  last_transmit_ = now;
  if (configuration_.role == Role::primary) {
    phase_ = SessionPhase::awaiting_connect_ack;
    if (!enqueue(MessageType::connect))
      fail(absolute_now, now);
  } else {
    phase_ = SessionPhase::awaiting_connect;
  }
}

void Session::transport_closed(std::uint32_t absolute_now,
                               Clock::time_point now) noexcept {
  if (!configured_)
    return;
  endpoint_.communication_changed(false, absolute_now, now);
  pending_head_ = 0U;
  pending_count_ = 0U;
  synchronization_transaction_id_ = 0U;
  phase_ = SessionPhase::disconnected;
}

void Session::fail(std::uint32_t absolute_now,
                   Clock::time_point now) noexcept {
  endpoint_.communication_changed(false, absolute_now, now);
  pending_head_ = 0U;
  pending_count_ = 0U;
  phase_ = SessionPhase::disconnected;
}

SessionEvent Session::receive(const MessageView &message,
                              std::uint32_t absolute_now,
                              Clock::time_point now) noexcept {
  if (!configured_ || phase_ == SessionPhase::disconnected)
    return {.kind = SessionEventKind::protocol_error};

  if (phase_ == SessionPhase::awaiting_connect) {
    NegotiatedParameters negotiated;
    if (validate_negotiation(message, configuration_, false,
                             secured_transport_, negotiated) !=
        NegotiationStatus::accepted) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    configuration_.maximum_client_lead_time_seconds =
        negotiated.maximum_client_lead_time_seconds;
    configuration_.maximum_response_delay_seconds =
        negotiated.receive_timer_seconds;
    configuration_.maximum_unacked_updates =
        static_cast<std::uint16_t>(negotiated.maximum_unacked_updates);
    negotiation_.secondary_hash_buckets =
        negotiated.secondary_hash_buckets;
    negotiation_.tls_request = negotiated.tls_request;
    if (!endpoint_.configure(configuration_, absolute_now, now) ||
        !enqueue(MessageType::connect_ack, message.transaction_id) ||
        !enqueue(MessageType::state)) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    // Draft section 7.9.1 recommends the secondary tSend at approximately
    // one third of the peer receive timer.
    send_interval_seconds_ =
        std::max<std::uint32_t>(1U,
                               negotiated.receive_timer_seconds / 3U);
    phase_ = SessionPhase::synchronizing;
    return {};
  }

  if (phase_ == SessionPhase::awaiting_connect_ack) {
    NegotiatedParameters negotiated;
    if (validate_negotiation(message, configuration_, true,
                             secured_transport_, negotiated) !=
        NegotiationStatus::accepted) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    configuration_.maximum_response_delay_seconds =
        negotiated.receive_timer_seconds;
    configuration_.maximum_unacked_updates =
        static_cast<std::uint16_t>(negotiated.maximum_unacked_updates);
    if (!endpoint_.configure(configuration_, absolute_now, now) ||
        !enqueue(MessageType::state)) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    // Draft section 7.9.2 recommends the primary tSend at approximately one
    // fifth of the receive timer negotiated in CONNECTACK.
    send_interval_seconds_ =
        std::max<std::uint32_t>(1U,
                               negotiated.receive_timer_seconds / 5U);
    phase_ = SessionPhase::synchronizing;
    return {};
  }

  switch (message.type) {
  case MessageType::binding_update:
    return {.kind = SessionEventKind::binding_update, .message = message};
  case MessageType::binding_ack:
    return {.kind = SessionEventKind::binding_ack, .message = message};
  case MessageType::pool_request:
    return {.kind = SessionEventKind::pool_request, .message = message};
  case MessageType::pool_response:
    return {.kind = SessionEventKind::pool_response, .message = message};
  case MessageType::update_request:
  case MessageType::update_request_all:
    return {.kind = SessionEventKind::synchronization_requested,
            .message = message};
  case MessageType::update_done:
    if (message.transaction_id != synchronization_transaction_id_) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    synchronization_transaction_id_ = 0U;
    endpoint_.update_request_finished(absolute_now, now);
    phase_ = SessionPhase::established;
    return {.kind = SessionEventKind::synchronization_complete,
            .message = message};
  case MessageType::state: {
    const auto state = parse_state(message);
    if (!state) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    endpoint_.partner_state_changed(local_state(state->state), absolute_now,
                                    now);
    endpoint_.communication_changed(true, absolute_now, now);
    if (synchronization_transaction_id_ == 0U) {
      synchronization_transaction_id_ =
          endpoint_.allocate_transaction_id();
      if (!enqueue(MessageType::update_request_all,
                   synchronization_transaction_id_)) {
        fail(absolute_now, now);
        return {.kind = SessionEventKind::protocol_error};
      }
    }
    return {.kind = SessionEventKind::partner_state_changed,
            .message = message};
  }
  case MessageType::contact:
    endpoint_.communication_changed(true, absolute_now, now);
    return {};
  case MessageType::disconnect:
    transport_closed(absolute_now, now);
    return {.kind = SessionEventKind::peer_disconnected,
            .message = message};
  case MessageType::connect:
  case MessageType::connect_ack:
    fail(absolute_now, now);
    return {.kind = SessionEventKind::protocol_error};
  }
  fail(absolute_now, now);
  return {.kind = SessionEventKind::protocol_error};
}

void Session::service(std::uint32_t absolute_now,
                      Clock::time_point now) noexcept {
  if (!configured_ || phase_ == SessionPhase::disconnected)
    return;
  endpoint_.service(absolute_now, now);
  if (!endpoint_.communications_ok() &&
      phase_ != SessionPhase::awaiting_connect &&
      phase_ != SessionPhase::awaiting_connect_ack) {
    phase_ = SessionPhase::disconnected;
    pending_head_ = 0U;
    pending_count_ = 0U;
    return;
  }
  if (send_interval_seconds_ != 0U && pending_count_ == 0U &&
      now - last_transmit_ >=
          std::chrono::seconds{send_interval_seconds_} &&
      !enqueue(MessageType::contact))
    fail(absolute_now, now);
}

bool Session::finish_synchronization(
    std::uint32_t request_transaction_id) noexcept {
  return configured_ && request_transaction_id != 0U &&
         enqueue(MessageType::update_done, request_transaction_id);
}

SessionCheckpoint Session::checkpoint(Clock::time_point now) const {
  SessionCheckpoint state{
      .configuration = configuration_,
      .negotiation = negotiation_,
      .endpoint = endpoint_.checkpoint(now),
      .pending = {},
      .transmit_remaining_nanoseconds = 0,
      .synchronization_transaction_id =
          synchronization_transaction_id_,
      .send_interval_seconds = send_interval_seconds_,
      .phase = phase_,
      .secured_transport = secured_transport_};
  state.pending.reserve(pending_count_);
  for (std::size_t offset = 0U; offset < pending_count_; ++offset) {
    const auto &pending =
        pending_[(pending_head_ + offset) % pending_.size()];
    state.pending.push_back(
        {.type = pending.type,
         .transaction_id = pending.transaction_id});
  }
  if (send_interval_seconds_ != 0U) {
    const auto deadline =
        last_transmit_ + std::chrono::seconds{send_interval_seconds_};
    state.transmit_remaining_nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            deadline > now ? deadline - now : Clock::duration::zero())
            .count();
  }
  return state;
}

bool Session::restore(const SessionCheckpoint &state,
                      Clock::time_point now) noexcept {
  if (state.pending.size() > pending_.size() ||
      state.transmit_remaining_nanoseconds < 0 ||
      static_cast<std::uint8_t>(state.phase) >
          static_cast<std::uint8_t>(SessionPhase::established))
    return false;

  Session staged;
  if (!staged.configure(state.configuration, state.negotiation,
                        state.secured_transport,
                        state.endpoint.state_started_absolute, now) ||
      !staged.endpoint_.restore(state.endpoint, now))
    return false;
  for (const auto &pending : state.pending) {
    if (!known_type(static_cast<std::uint8_t>(pending.type)) ||
        !staged.enqueue(pending.type, pending.transaction_id))
      return false;
  }
  staged.synchronization_transaction_id_ =
      state.synchronization_transaction_id;
  staged.send_interval_seconds_ = state.send_interval_seconds;
  staged.phase_ = state.phase;
  const auto interval =
      std::chrono::seconds{state.send_interval_seconds};
  const auto remaining =
      std::chrono::nanoseconds{state.transmit_remaining_nanoseconds};
  if (remaining > interval)
    return false;
  staged.last_transmit_ = now + remaining - interval;
  *this = std::move(staged);
  return true;
}

std::optional<std::size_t>
Session::prepare_next(std::span<std::uint8_t> output,
                      std::uint32_t absolute_now,
                      Clock::time_point now) noexcept {
  if (!configured_ || pending_count_ == 0U)
    return std::nullopt;
  auto pending = pending_[pending_head_];
  if (pending.transaction_id == 0U)
    pending.transaction_id = endpoint_.allocate_transaction_id();

  std::optional<std::size_t> encoded;
  if (pending.type == MessageType::connect ||
      pending.type == MessageType::connect_ack) {
    encoded = encode_negotiation(
        pending.type, absolute_now, pending.transaction_id, configuration_,
        negotiation_, secured_transport_, output);
  } else if (pending.type == MessageType::state) {
    const auto checkpoint = endpoint_.checkpoint(now);
    const bool startup = checkpoint.state == State::startup;
    auto advertised = ServerState::normal;
    switch (checkpoint.state) {
    case State::startup:
    case State::normal:
      advertised = ServerState::normal;
      break;
    case State::communications_interrupted:
      advertised = ServerState::communications_interrupted;
      break;
    case State::partner_down:
      advertised = ServerState::partner_down;
      break;
    case State::potential_conflict:
      advertised = ServerState::potential_conflict;
      break;
    case State::recover:
    case State::recover_wait:
      advertised = ServerState::recover;
      break;
    case State::recover_done:
      advertised = ServerState::recover_done;
      break;
    case State::resolution_interrupted:
      advertised = ServerState::resolution_interrupted;
      break;
    case State::conflict_done:
      advertised = ServerState::conflict_done;
      break;
    case State::paused:
      advertised = ServerState::paused;
      break;
    case State::shutdown:
      advertised = ServerState::shutdown;
      break;
    }
    encoded = encode_state(
        absolute_now, pending.transaction_id,
        {.state = advertised,
         .startup = startup,
         .started_at = checkpoint.state_started_absolute},
        output);
  } else {
    Encoder encoder{output};
    if (encoder.begin(pending.type, absolute_now,
                      pending.transaction_id))
      encoded = encoder.message().size();
  }
  if (!encoded)
    return std::nullopt;
  pending_head_ = (pending_head_ + 1U) % pending_.size();
  --pending_count_;
  last_transmit_ = now;
  return encoded;
}

} // namespace router::dhcpv4::failover
