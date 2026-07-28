// RFC 8156 DHCPv6 failover codec and relationship state implementation.
// The TCP and lease owners remain outside this file; no peer communication is
// synthesized by a state transition.

#include "router/dhcpv6_failover.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace router::dhcpv6::failover {
namespace {

std::uint16_t u16(std::span<const std::uint8_t> bytes) noexcept {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[0U]) << 8U | bytes[1U]);
}

std::uint32_t u24(std::span<const std::uint8_t> bytes) noexcept {
  return static_cast<std::uint32_t>(bytes[0U]) << 16U |
         static_cast<std::uint32_t>(bytes[1U]) << 8U | bytes[2U];
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

void put_u24(std::span<std::uint8_t> output, std::uint32_t value) noexcept {
  output[0U] = static_cast<std::uint8_t>(value >> 16U);
  output[1U] = static_cast<std::uint8_t>(value >> 8U);
  output[2U] = static_cast<std::uint8_t>(value);
}

void put_u32(std::span<std::uint8_t> output, std::uint32_t value) noexcept {
  output[0U] = static_cast<std::uint8_t>(value >> 24U);
  output[1U] = static_cast<std::uint8_t>(value >> 16U);
  output[2U] = static_cast<std::uint8_t>(value >> 8U);
  output[3U] = static_cast<std::uint8_t>(value);
}

std::optional<MessageType> message_type(std::uint8_t value) noexcept {
  if (value < static_cast<std::uint8_t>(MessageType::binding_update) ||
      value > static_cast<std::uint8_t>(MessageType::contact))
    return std::nullopt;
  return static_cast<MessageType>(value);
}

bool singleton(std::uint16_t code) noexcept {
  // Every F option except the DNS removal container is scalar or a single
  // relationship identity in RFC 8156. Existing DHCPv6 client-data children
  // may repeat and are intentionally not classified here.
  return code >= static_cast<std::uint16_t>(OptionCode::binding_status) &&
         code <=
             static_cast<std::uint16_t>(OptionCode::state_expiration_time) &&
         code != static_cast<std::uint16_t>(OptionCode::dns_removal_info);
}

bool valid_state(State value) noexcept {
  return value >= State::startup && value <= State::conflict_done;
}

std::optional<std::uint32_t>
option_u32(const MessageView &message, OptionCode code) noexcept {
  const auto option =
      message.first(static_cast<std::uint16_t>(code));
  if (!option || option->value.size() != 4U)
    return std::nullopt;
  return u32(option->value);
}

bool append_tlv(std::span<std::uint8_t> output, std::size_t &occupied,
                std::uint16_t code,
                std::span<const std::uint8_t> value) noexcept {
  if (value.size() > std::numeric_limits<std::uint16_t>::max() ||
      occupied > output.size() ||
      output.size() - occupied < 4U + value.size())
    return false;
  put_u16(output.subspan(occupied, 2U), code);
  put_u16(output.subspan(occupied + 2U, 2U),
          static_cast<std::uint16_t>(value.size()));
  std::copy(value.begin(), value.end(),
            output.begin() + static_cast<std::ptrdiff_t>(occupied + 4U));
  occupied += 4U + value.size();
  return true;
}

struct BindingMetadata {
  BindingStatus status{BindingStatus::reserved};
  std::uint32_t started{};
  std::optional<std::uint32_t> state_expires;
  std::optional<std::uint32_t> client_last_transaction;
  std::optional<std::uint32_t> partner_lifetime;
  std::optional<std::uint32_t> partner_raw_client_last_transaction;
  std::optional<std::uint32_t> expiration;
};

std::optional<BindingMetadata>
parse_binding_metadata(std::span<const std::uint8_t> options) noexcept {
  BindingMetadata result;
  bool saw_status{};
  bool saw_started{};
  std::array<std::uint16_t, 7U> seen{};
  std::size_t seen_count{};
  packet::dhcpv6::OptionCursor cursor{options};
  while (const auto option = cursor.next()) {
    const auto code = option->code;
    const bool known =
        code == static_cast<std::uint16_t>(OptionCode::binding_status) ||
        code == static_cast<std::uint16_t>(OptionCode::start_time_of_state) ||
        code == static_cast<std::uint16_t>(OptionCode::state_expiration_time) ||
        code == static_cast<std::uint16_t>(
                    packet::dhcpv6::OptionCode::
                        client_last_transaction_time) ||
        code == static_cast<std::uint16_t>(OptionCode::partner_lifetime) ||
        code == static_cast<std::uint16_t>(
                    OptionCode::partner_raw_client_last_transaction_time) ||
        code == static_cast<std::uint16_t>(OptionCode::expiration_time);
    if (!known)
      continue;
    if (std::find(seen.begin(),
                  seen.begin() + static_cast<std::ptrdiff_t>(seen_count),
                  code) !=
        seen.begin() + static_cast<std::ptrdiff_t>(seen_count))
      return std::nullopt;
    seen[seen_count++] = code;

    if (code == static_cast<std::uint16_t>(OptionCode::binding_status)) {
      if (option->data.size() != 1U ||
          option->data[0U] >
              static_cast<std::uint8_t>(BindingStatus::reset))
        return std::nullopt;
      result.status = static_cast<BindingStatus>(option->data[0U]);
      saw_status = true;
      continue;
    }
    if (option->data.size() != 4U)
      return std::nullopt;
    const auto value = u32(option->data);
    if (code ==
        static_cast<std::uint16_t>(OptionCode::start_time_of_state)) {
      result.started = value;
      saw_started = true;
    } else if (code ==
               static_cast<std::uint16_t>(
                   OptionCode::state_expiration_time)) {
      result.state_expires = value;
    } else if (code ==
               static_cast<std::uint16_t>(
                   packet::dhcpv6::OptionCode::
                       client_last_transaction_time)) {
      result.client_last_transaction = value;
    } else if (code ==
               static_cast<std::uint16_t>(OptionCode::partner_lifetime)) {
      result.partner_lifetime = value;
    } else if (code ==
               static_cast<std::uint16_t>(
                   OptionCode::partner_raw_client_last_transaction_time)) {
      result.partner_raw_client_last_transaction = value;
    } else {
      result.expiration = value;
    }
  }
  if (!cursor.valid() || !saw_status || !saw_started)
    return std::nullopt;

  // RFC 8156 marks the three timeout values as one conditional group. A peer
  // cannot provide only part of the group because the receiver would then be
  // unable to apply the MCLT and state-expiry rules consistently.
  const auto timeout_values =
      static_cast<unsigned>(result.state_expires.has_value()) +
      static_cast<unsigned>(result.partner_lifetime.has_value()) +
      static_cast<unsigned>(result.expiration.has_value());
  if (timeout_values != 0U && timeout_values != 3U)
    return std::nullopt;
  if (result.status == BindingStatus::active && timeout_values != 3U)
    return std::nullopt;
  return result;
}

bool append_u32_tlv(std::span<std::uint8_t> output, std::size_t &occupied,
                    std::uint16_t code, std::uint32_t value) noexcept {
  std::array<std::uint8_t, 4U> bytes{};
  put_u32(bytes, value);
  return append_tlv(output, occupied, code, bytes);
}

bool append_binding_metadata(std::span<std::uint8_t> output,
                             std::size_t &occupied,
                             const BindingUpdate &binding) noexcept {
  const auto timeout_values =
      static_cast<unsigned>(binding.state_expiration_time.has_value()) +
      static_cast<unsigned>(binding.partner_lifetime.has_value()) +
      static_cast<unsigned>(binding.expiration_time.has_value());
  if (binding.status > BindingStatus::reset ||
      (timeout_values != 0U && timeout_values != 3U) ||
      (binding.status == BindingStatus::active && timeout_values != 3U))
    return false;
  const std::array<std::uint8_t, 1U> status{
      static_cast<std::uint8_t>(binding.status)};
  if (!append_tlv(output, occupied,
                  static_cast<std::uint16_t>(OptionCode::binding_status),
                  status) ||
      !append_u32_tlv(
          output, occupied,
          static_cast<std::uint16_t>(OptionCode::start_time_of_state),
          binding.start_time_of_state))
    return false;
  if (binding.state_expiration_time &&
      !append_u32_tlv(
          output, occupied,
          static_cast<std::uint16_t>(OptionCode::state_expiration_time),
          *binding.state_expiration_time))
    return false;
  if (binding.client_last_transaction_time &&
      !append_u32_tlv(
          output, occupied,
          static_cast<std::uint16_t>(
              packet::dhcpv6::OptionCode::client_last_transaction_time),
          *binding.client_last_transaction_time))
    return false;
  if (binding.partner_lifetime &&
      !append_u32_tlv(
          output, occupied,
          static_cast<std::uint16_t>(OptionCode::partner_lifetime),
          *binding.partner_lifetime))
    return false;
  if (binding.partner_raw_client_last_transaction_time &&
      !append_u32_tlv(
          output, occupied,
          static_cast<std::uint16_t>(
              OptionCode::partner_raw_client_last_transaction_time),
          *binding.partner_raw_client_last_transaction_time))
    return false;
  return !binding.expiration_time ||
         append_u32_tlv(
             output, occupied,
             static_cast<std::uint16_t>(OptionCode::expiration_time),
             *binding.expiration_time);
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
    if (expected_ == 0U && occupied_ < frame_prefix_octets) {
      const auto needed = frame_prefix_octets - occupied_;
      const auto copied = std::min(needed, input.size() - accepted);
      std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(accepted),
                  copied,
                  storage_.begin() + static_cast<std::ptrdiff_t>(occupied_));
      occupied_ += copied;
      accepted += copied;
      if (occupied_ < frame_prefix_octets)
        break;
      expected_ =
          u16(std::span<const std::uint8_t>{storage_}.first(2U));
      if (expected_ < header_octets ||
          expected_ > maximum_message_octets) {
        failed_ = true;
        return {.status = StreamStatus::invalid_length,
                .accepted_octets = accepted};
      }
      // The fixed repository stores only the body. Once the prefix has been
      // interpreted, reuse its two octets as the start of the body so a valid
      // maximum-length frame still fits exactly one bounded allocation.
      occupied_ = 0U;
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
  const auto valid_partial_prefix =
      state.expected == 0U &&
      state.bytes.size() < frame_prefix_octets && !state.ready;
  const auto valid_body =
      state.expected >= header_octets &&
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

DecodeResult decode(std::span<const std::uint8_t> payload) noexcept {
  if (payload.size() < header_octets)
    return {.status = DecodeStatus::truncated_header};
  const auto type = message_type(payload[0U]);
  if (!type)
    return {.status = DecodeStatus::unknown_message_type};
  const auto transaction_id = u24(payload.subspan(1U, 3U));
  // RFC 8156 replies copy the request ID, while all initiators allocate an
  // outstanding nonzero ID. Zero therefore cannot correlate either class.
  if (transaction_id == 0U)
    return {.status = DecodeStatus::invalid_transaction_id};

  const auto options = payload.subspan(header_octets);
  std::array<std::uint16_t,
             device_catalog::dhcp_failover_options_per_message>
      seen_singletons{};
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
    if (singleton(code)) {
      if (std::find(seen_singletons.begin(),
                    seen_singletons.begin() +
                        static_cast<std::ptrdiff_t>(seen_count),
                    code) !=
          seen_singletons.begin() +
              static_cast<std::ptrdiff_t>(seen_count))
        return {.status = DecodeStatus::invalid_message_options};
      seen_singletons[seen_count++] = code;
    }
    offset += size;
  }

  // CONNECT exchanges establish relationship identity and negotiation. A
  // missing name cannot be repaired by selecting a relationship from storage
  // order and must be rejected before state-machine dispatch.
  MessageView result{*type, transaction_id, u32(payload.subspan(4U, 4U)),
                     options};
  if ((*type == MessageType::connect ||
       *type == MessageType::connect_reply) &&
      !result.first(
          static_cast<std::uint16_t>(OptionCode::relationship_name)))
    return {.status = DecodeStatus::invalid_message_options};
  return {.status = DecodeStatus::accepted,
          .message = result,
          .option_count = option_count};
}

Encoder::Encoder(std::span<std::uint8_t> output) noexcept : output_(output) {}

bool Encoder::begin(MessageType type, std::uint32_t transaction_id,
                    std::uint32_t sent_time) noexcept {
  if (begun_ || failed_ || output_.size() < header_octets ||
      transaction_id == 0U || transaction_id > 0x00ffffffU) {
    failed_ = true;
    return false;
  }
  output_[0U] = static_cast<std::uint8_t>(type);
  put_u24(output_.subspan(1U, 3U), transaction_id);
  put_u32(output_.subspan(4U, 4U), sent_time);
  occupied_ = header_octets;
  begun_ = true;
  return true;
}

bool Encoder::option(std::uint16_t code,
                     std::span<const std::uint8_t> value) noexcept {
  if (!begun_ || failed_ ||
      option_count_ >=
          device_catalog::dhcp_failover_options_per_message ||
      value.size() > std::numeric_limits<std::uint16_t>::max() ||
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

std::span<const std::uint8_t> Encoder::message() const noexcept {
  return begun_ && !failed_ ? output_.first(occupied_)
                            : std::span<const std::uint8_t>{};
}

std::optional<std::size_t>
frame(std::span<const std::uint8_t> message,
      std::span<std::uint8_t> output) noexcept {
  if (message.empty() ||
      message.size() > std::numeric_limits<std::uint16_t>::max() ||
      output.size() < message.size() + frame_prefix_octets)
    return std::nullopt;
  put_u16(output.first(2U), static_cast<std::uint16_t>(message.size()));
  std::copy(message.begin(), message.end(), output.begin() + 2);
  return message.size() + frame_prefix_octets;
}

NegotiationStatus validate_negotiation(
    const MessageView &message, const Configuration &local, bool reply,
    NegotiatedParameters &negotiated) noexcept {
  const auto expected_type =
      reply ? MessageType::connect_reply : MessageType::connect;
  if (message.type != expected_type)
    return NegotiationStatus::wrong_message;

  const auto name = message.first(
      static_cast<std::uint16_t>(OptionCode::relationship_name));
  const auto version = message.first(
      static_cast<std::uint16_t>(OptionCode::protocol_version));
  const auto mclt = option_u32(
      message, OptionCode::maximum_client_lead_time);
  const auto keepalive =
      option_u32(message, OptionCode::keepalive_time);
  const auto maximum =
      option_u32(message, OptionCode::maximum_unacked_binding_updates);
  const auto flags = message.first(
      static_cast<std::uint16_t>(OptionCode::connect_flags));
  if (!name || !version || !mclt || !keepalive || !maximum || !flags)
    return NegotiationStatus::missing_required_option;
  if (version->value.size() != 4U || flags->value.size() != 2U ||
      *mclt == 0U || *keepalive == 0U || *maximum == 0U ||
      *maximum > device_catalog::dhcp_failover_updates_in_flight)
    return NegotiationStatus::malformed_option;
  if (name->value.size() != local.relationship_name.size() ||
      !std::equal(name->value.begin(), name->value.end(),
                  local.relationship_name.begin()))
    return NegotiationStatus::relationship_mismatch;
  if (u16(version->value.first(2U)) != 1U ||
      u16(version->value.subspan(2U, 2U)) != 0U)
    return NegotiationStatus::protocol_version_mismatch;
  // RFC 8156 defines only FIXED_PD_LENGTH in the least-significant bit.
  // Rejecting every MBZ bit prevents silent feature negotiation drift.
  const auto decoded_flags = u16(flags->value);
  if ((decoded_flags & 0xfffeU) != 0U)
    return NegotiationStatus::unsupported_connect_flags;
  if (reply && *mclt != local.maximum_client_lead_time_seconds)
    return NegotiationStatus::mclt_mismatch;

  negotiated = {.maximum_client_lead_time_seconds = *mclt,
                .keepalive_seconds = *keepalive,
                .maximum_unacked_updates = *maximum,
                .connect_flags = decoded_flags};
  return NegotiationStatus::accepted;
}

std::optional<std::size_t> encode_negotiation(
    MessageType type, std::uint32_t transaction_id, std::uint32_t sent_time,
    const Configuration &configuration, std::uint16_t connect_flags,
    std::span<std::uint8_t> output) noexcept {
  if ((type != MessageType::connect &&
       type != MessageType::connect_reply) ||
      configuration.relationship_name.empty() ||
      configuration.maximum_client_lead_time_seconds == 0U ||
      configuration.keepalive_seconds == 0U ||
      configuration.maximum_unacked_updates == 0U ||
      (connect_flags & 0xfffeU) != 0U)
    return std::nullopt;

  std::array<std::uint8_t, 4U> version{0U, 1U, 0U, 0U};
  std::array<std::uint8_t, 4U> mclt{};
  std::array<std::uint8_t, 4U> keepalive{};
  std::array<std::uint8_t, 4U> maximum{};
  std::array<std::uint8_t, 2U> flags{};
  put_u32(mclt, configuration.maximum_client_lead_time_seconds);
  put_u32(keepalive, configuration.keepalive_seconds);
  put_u32(maximum, configuration.maximum_unacked_updates);
  put_u16(flags, connect_flags);
  Encoder encoder{output};
  const auto name = std::span<const std::uint8_t>{
      reinterpret_cast<const std::uint8_t *>(
          configuration.relationship_name.data()),
      configuration.relationship_name.size()};
  if (!encoder.begin(type, transaction_id, sent_time) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::protocol_version),
          version) ||
      !encoder.option(
          static_cast<std::uint16_t>(
              OptionCode::maximum_client_lead_time),
          mclt) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::keepalive_time),
          keepalive) ||
      !encoder.option(
          static_cast<std::uint16_t>(
              OptionCode::maximum_unacked_binding_updates),
          maximum) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::relationship_name),
          name) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::connect_flags), flags))
    return std::nullopt;
  return encoder.message().size();
}

std::optional<std::size_t>
encode_state(std::uint32_t transaction_id, std::uint32_t sent_time,
             const StateAdvertisement &state,
             std::span<std::uint8_t> output) noexcept {
  if (!valid_state(state.state) ||
      // STARTUP is signaled by the S flag and is never placed in the state
      // option itself. Its transmitted state byte remains the previous
      // durable state, which the session owner must supply.
      state.state == State::startup ||
      (state.flags & 0xf8U) != 0U ||
      (state.partner_down_at.has_value() !=
       (state.state == State::partner_down)))
    return std::nullopt;
  std::array<std::uint8_t, 1U> wire_state{
      static_cast<std::uint8_t>(state.state)};
  std::array<std::uint8_t, 1U> flags{state.flags};
  std::array<std::uint8_t, 4U> started{};
  std::array<std::uint8_t, 4U> partner_down{};
  put_u32(started, state.started_at);
  if (state.partner_down_at)
    put_u32(partner_down, *state.partner_down_at);
  Encoder encoder{output};
  if (!encoder.begin(MessageType::state, transaction_id, sent_time) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::server_state),
          wire_state) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::server_flags), flags) ||
      !encoder.option(
          static_cast<std::uint16_t>(OptionCode::start_time_of_state),
          started) ||
      (state.partner_down_at &&
       !encoder.option(
           static_cast<std::uint16_t>(OptionCode::partner_down_time),
           partner_down)))
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
  const auto partner_down =
      option_u32(message, OptionCode::partner_down_time);
  if (!state || state->value.size() != 1U || !flags ||
      flags->value.size() != 1U || !started ||
      (flags->value[0U] & 0xf8U) != 0U)
    return std::nullopt;
  const auto decoded = static_cast<State>(state->value[0U]);
  if (!valid_state(decoded) || decoded == State::startup ||
      (partner_down.has_value() != (decoded == State::partner_down)))
    return std::nullopt;
  return StateAdvertisement{.state = decoded,
                            .flags = flags->value[0U],
                            .started_at = *started,
                            .partner_down_at = partner_down};
}

BindingParseResult
parse_bindings(const MessageView &message,
               std::span<BindingUpdateView> output) noexcept {
  if (message.type != MessageType::binding_update &&
      message.type != MessageType::binding_reply)
    return {.status = BindingParseStatus::wrong_message};

  const auto client_data = message.first(
      static_cast<std::uint16_t>(
          packet::dhcpv6::OptionCode::client_data));
  const auto unassociated_prefix = message.first(
      static_cast<std::uint16_t>(
          packet::dhcpv6::OptionCode::ia_prefix));
  if (client_data.has_value() == unassociated_prefix.has_value())
    return {.status = BindingParseStatus::missing_required_option};
  std::size_t client_data_count{};
  std::size_t unassociated_prefix_count{};
  packet::dhcpv6::OptionCursor top_cursor{message.options};
  while (const auto option = top_cursor.next()) {
    client_data_count +=
        option->code ==
        static_cast<std::uint16_t>(
            packet::dhcpv6::OptionCode::client_data);
    unassociated_prefix_count +=
        option->code ==
        static_cast<std::uint16_t>(
            packet::dhcpv6::OptionCode::ia_prefix);
  }
  if (!top_cursor.valid() || client_data_count > 1U ||
      unassociated_prefix_count > 1U)
    return {.status = BindingParseStatus::malformed};

  std::size_t produced{};
  const auto emit_resource =
      [&](std::span<const std::uint8_t> client_identifier,
          IdentityAssociationType association, std::uint32_t iaid,
          std::uint32_t t1, std::uint32_t t2, packet::Ipv6 value,
          std::uint8_t prefix_length, std::uint32_t preferred_lifetime,
          std::uint32_t valid_lifetime, std::uint32_t base_time,
          std::span<const std::uint8_t> metadata_options) {
        const auto metadata = parse_binding_metadata(metadata_options);
        if (!metadata)
          return BindingParseStatus::malformed;
        if (produced == output.size())
          return BindingParseStatus::resource_exhausted;
        output[produced++] = {
            .client_identifier = client_identifier,
            .value = value,
            .association = association,
            .status = metadata->status,
            .iaid = iaid,
            .t1 = t1,
            .t2 = t2,
            .preferred_lifetime = preferred_lifetime,
            .valid_lifetime = valid_lifetime,
            .base_time = base_time,
            .start_time_of_state = metadata->started,
            .state_expiration_time = metadata->state_expires,
            .client_last_transaction_time =
                metadata->client_last_transaction,
            .partner_lifetime = metadata->partner_lifetime,
            .partner_raw_client_last_transaction_time =
                metadata->partner_raw_client_last_transaction,
            .expiration_time = metadata->expiration,
            .prefix_length = prefix_length};
        return BindingParseStatus::accepted;
      };

  if (unassociated_prefix) {
    const auto prefix =
        packet::dhcpv6::parse_ia_prefix(unassociated_prefix->value);
    if (!prefix)
      return {.status = BindingParseStatus::malformed};
    std::optional<std::uint32_t> base_time;
    packet::dhcpv6::OptionCursor cursor{prefix->options};
    while (const auto option = cursor.next())
      if (option->code ==
          static_cast<std::uint16_t>(
              packet::dhcpv6::OptionCode::leasequery_base_time)) {
        if (base_time || option->data.size() != 4U)
          return {.status = BindingParseStatus::malformed};
        base_time = u32(option->data);
      }
    if (!cursor.valid() || !base_time)
      return {.status = BindingParseStatus::missing_required_option};
    const auto status = emit_resource(
        {}, IdentityAssociationType::unassociated_prefix, 0U, 0U, 0U,
        prefix->prefix, prefix->prefix_length, prefix->preferred_lifetime,
        prefix->valid_lifetime, *base_time, prefix->options);
    return {.status = status, .bindings = produced};
  }

  std::span<const std::uint8_t> client_identifier;
  std::optional<std::uint32_t> base_time;
  std::size_t ia_count{};
  packet::dhcpv6::OptionCursor client_cursor{client_data->value};
  while (const auto child = client_cursor.next()) {
    if (child->code ==
        static_cast<std::uint16_t>(
            packet::dhcpv6::OptionCode::client_identifier)) {
      if (!client_identifier.empty() || child->data.empty() ||
          child->data.size() > packet::dhcpv6::maximum_duid_octets)
        return {.status = BindingParseStatus::malformed};
      client_identifier = child->data;
      continue;
    }
    if (child->code ==
        static_cast<std::uint16_t>(
            packet::dhcpv6::OptionCode::leasequery_base_time)) {
      if (base_time || child->data.size() != 4U)
        return {.status = BindingParseStatus::malformed};
      base_time = u32(child->data);
      continue;
    }

    const auto association =
        child->code ==
                static_cast<std::uint16_t>(
                    packet::dhcpv6::OptionCode::ia_na)
            ? std::optional{IdentityAssociationType::non_temporary}
        : child->code ==
                  static_cast<std::uint16_t>(
                      packet::dhcpv6::OptionCode::ia_ta)
            ? std::optional{IdentityAssociationType::temporary}
        : child->code ==
                  static_cast<std::uint16_t>(
                      packet::dhcpv6::OptionCode::ia_pd)
            ? std::optional{IdentityAssociationType::delegated_prefix}
            : std::nullopt;
    if (!association)
      continue;
    ++ia_count;

    std::uint32_t iaid{};
    std::uint32_t t1{};
    std::uint32_t t2{};
    std::span<const std::uint8_t> resources;
    if (*association == IdentityAssociationType::temporary) {
      const auto ia = packet::dhcpv6::parse_ia_ta(child->data);
      if (!ia)
        return {.status = BindingParseStatus::malformed};
      iaid = ia->iaid;
      resources = ia->options;
    } else {
      const auto ia = packet::dhcpv6::parse_ia_na_or_pd(child->data);
      if (!ia)
        return {.status = BindingParseStatus::malformed};
      iaid = ia->iaid;
      t1 = ia->t1;
      t2 = ia->t2;
      resources = ia->options;
    }

    std::size_t resources_in_ia{};
    packet::dhcpv6::OptionCursor resource_cursor{resources};
    while (const auto resource = resource_cursor.next()) {
      if (*association == IdentityAssociationType::delegated_prefix) {
        if (resource->code !=
            static_cast<std::uint16_t>(
                packet::dhcpv6::OptionCode::ia_prefix))
          continue;
        const auto prefix = packet::dhcpv6::parse_ia_prefix(resource->data);
        if (!prefix)
          return {.status = BindingParseStatus::malformed};
        const auto status = emit_resource(
            client_identifier, *association, iaid, t1, t2, prefix->prefix,
            prefix->prefix_length, prefix->preferred_lifetime,
            prefix->valid_lifetime, base_time.value_or(0U), prefix->options);
        if (status != BindingParseStatus::accepted)
          return {.status = status, .bindings = produced};
      } else {
        if (resource->code !=
            static_cast<std::uint16_t>(
                packet::dhcpv6::OptionCode::ia_address))
          continue;
        const auto address =
            packet::dhcpv6::parse_ia_address(resource->data);
        if (!address)
          return {.status = BindingParseStatus::malformed};
        const auto status = emit_resource(
            client_identifier, *association, iaid, t1, t2, address->address,
            128U, address->preferred_lifetime, address->valid_lifetime,
            base_time.value_or(0U), address->options);
        if (status != BindingParseStatus::accepted)
          return {.status = status, .bindings = produced};
      }
      ++resources_in_ia;
    }
    if (!resource_cursor.valid() || resources_in_ia == 0U)
      return {.status = BindingParseStatus::missing_required_option,
              .bindings = produced};
  }
  if (!client_cursor.valid())
    return {.status = BindingParseStatus::malformed,
            .bindings = produced};
  if (client_identifier.empty() || !base_time || ia_count == 0U ||
      produced == 0U)
    return {.status = BindingParseStatus::missing_required_option,
            .bindings = produced};
  // Every resource shares the enclosing CLIENT_DATA base time. It was not
  // known while a peer-ordered IA appeared before OPTION_LQ_BASE_TIME.
  for (std::size_t index{}; index < produced; ++index)
    output[index].base_time = *base_time;
  return {.status = BindingParseStatus::accepted, .bindings = produced};
}

std::optional<std::size_t>
encode_binding(MessageType type, std::uint32_t transaction_id,
               std::uint32_t sent_time, const BindingUpdate &binding,
               std::span<std::uint8_t> output) noexcept {
  if ((type != MessageType::binding_update &&
       type != MessageType::binding_reply) ||
      binding.prefix_length > 128U ||
      (binding.association == IdentityAssociationType::unassociated_prefix &&
       !binding.client_identifier.empty()) ||
      (binding.association != IdentityAssociationType::unassociated_prefix &&
       (binding.client_identifier.empty() ||
        binding.client_identifier.size() >
            packet::dhcpv6::maximum_duid_octets)))
    return std::nullopt;

  // One outbound binding has a protocol-derived upper bound: one maximum DUID,
  // one IA wrapper, one address or prefix resource, and seven scalar failover
  // suboptions. This stack storage is independent from peer input size.
  std::array<std::uint8_t, 512U> metadata{};
  std::size_t metadata_octets{};
  if (!append_binding_metadata(metadata, metadata_octets, binding))
    return std::nullopt;

  std::array<std::uint8_t, 512U> resource{};
  const auto resource_octets =
      binding.association == IdentityAssociationType::delegated_prefix ||
              binding.association ==
                  IdentityAssociationType::unassociated_prefix
          ? packet::dhcpv6::encode_ia_prefix(
                resource, binding.value, binding.prefix_length,
                binding.preferred_lifetime, binding.valid_lifetime,
                std::span<const std::uint8_t>{metadata}.first(
                    metadata_octets))
          : packet::dhcpv6::encode_ia_address(
                resource, binding.value, binding.preferred_lifetime,
                binding.valid_lifetime,
                std::span<const std::uint8_t>{metadata}.first(
                    metadata_octets));
  if (!resource_octets)
    return std::nullopt;

  std::array<std::uint8_t, 512U> container{};
  std::size_t container_octets{};
  Encoder encoder{output};
  if (!encoder.begin(type, transaction_id, sent_time))
    return std::nullopt;
  if (binding.association == IdentityAssociationType::unassociated_prefix) {
    std::array<std::uint8_t, 512U> prefix_options{};
    std::size_t prefix_options_octets{};
    if (!append_u32_tlv(
            prefix_options, prefix_options_octets,
            static_cast<std::uint16_t>(
                packet::dhcpv6::OptionCode::leasequery_base_time),
            binding.base_time) ||
        prefix_options.size() - prefix_options_octets < metadata_octets)
      return std::nullopt;
    std::copy_n(metadata.begin(), metadata_octets,
                prefix_options.begin() +
                    static_cast<std::ptrdiff_t>(prefix_options_octets));
    prefix_options_octets += metadata_octets;
    const auto prefix = packet::dhcpv6::encode_ia_prefix(
        container, binding.value, binding.prefix_length,
        binding.preferred_lifetime, binding.valid_lifetime,
        std::span<const std::uint8_t>{prefix_options}.first(
            prefix_options_octets));
    if (!prefix ||
        !encoder.option(
            static_cast<std::uint16_t>(
                packet::dhcpv6::OptionCode::ia_prefix),
            std::span<const std::uint8_t>{container}.first(*prefix)))
      return std::nullopt;
    return encoder.message().size();
  }

  if (!append_tlv(
          container, container_octets,
          static_cast<std::uint16_t>(
              packet::dhcpv6::OptionCode::client_identifier),
          binding.client_identifier) ||
      !append_u32_tlv(
          container, container_octets,
          static_cast<std::uint16_t>(
              packet::dhcpv6::OptionCode::leasequery_base_time),
          binding.base_time))
    return std::nullopt;

  std::array<std::uint8_t, 512U> ia_resources{};
  std::size_t ia_resources_octets{};
  const auto resource_code =
      binding.association == IdentityAssociationType::delegated_prefix
          ? packet::dhcpv6::OptionCode::ia_prefix
          : packet::dhcpv6::OptionCode::ia_address;
  if (!append_tlv(
          ia_resources, ia_resources_octets,
          static_cast<std::uint16_t>(resource_code),
          std::span<const std::uint8_t>{resource}.first(*resource_octets)))
    return std::nullopt;

  std::array<std::uint8_t, 512U> ia{};
  const auto ia_octets =
      binding.association == IdentityAssociationType::temporary
          ? packet::dhcpv6::encode_ia_ta(
                ia, binding.iaid,
                std::span<const std::uint8_t>{ia_resources}.first(
                    ia_resources_octets))
          : packet::dhcpv6::encode_ia_na_or_pd(
                ia, binding.iaid, binding.t1, binding.t2,
                std::span<const std::uint8_t>{ia_resources}.first(
                    ia_resources_octets));
  const auto ia_code =
      binding.association == IdentityAssociationType::temporary
          ? packet::dhcpv6::OptionCode::ia_ta
      : binding.association == IdentityAssociationType::delegated_prefix
          ? packet::dhcpv6::OptionCode::ia_pd
          : packet::dhcpv6::OptionCode::ia_na;
  if (!ia_octets ||
      !append_tlv(
          container, container_octets,
          static_cast<std::uint16_t>(ia_code),
          std::span<const std::uint8_t>{ia}.first(*ia_octets)) ||
      !encoder.option(
          static_cast<std::uint16_t>(
              packet::dhcpv6::OptionCode::client_data),
          std::span<const std::uint8_t>{container}.first(container_octets)))
    return std::nullopt;
  return encoder.message().size();
}

std::optional<std::size_t>
encode_binding_reply(std::uint32_t transaction_id, std::uint32_t sent_time,
                     std::span<const BindingUpdateView> bindings,
                     std::span<std::uint8_t> output) noexcept {
  if (bindings.empty() ||
      bindings.size() >
          device_catalog::dhcp_failover_updates_in_flight ||
      bindings.size() >
          device_catalog::dhcp_failover_options_per_message ||
      output.size() < header_octets)
    return std::nullopt;

  // RFC 8156 groups all resources for one client below one CLIENT_DATA option.
  // Repeating CLIENT_DATA for each resource would produce a syntactically
  // valid TLV stream with invalid protocol semantics. We retain the canonical
  // single-resource encoder, but merge only its IA children beneath one client
  // container and keep CLIENTID plus LQ_BASE_TIME exactly once.
  std::array<std::uint8_t, maximum_message_octets> encoded{};
  std::array<std::uint8_t, maximum_message_octets> client_data{};
  std::size_t client_data_octets{};
  const auto expected_client = bindings.front().client_identifier;
  const auto expected_base_time = bindings.front().base_time;
  for (std::size_t index = 0; index < bindings.size(); ++index) {
    const auto &view = bindings[index];
    if (view.association == IdentityAssociationType::unassociated_prefix ||
        view.client_identifier.size() != expected_client.size() ||
        !std::equal(view.client_identifier.begin(),
                    view.client_identifier.end(), expected_client.begin()) ||
        view.base_time != expected_base_time)
      return std::nullopt;
    const BindingUpdate binding{
        .client_identifier = view.client_identifier,
        .value = view.value,
        .association = view.association,
        .status = view.status,
        .iaid = view.iaid,
        .t1 = view.t1,
        .t2 = view.t2,
        .preferred_lifetime = view.preferred_lifetime,
        .valid_lifetime = view.valid_lifetime,
        .base_time = view.base_time,
        .start_time_of_state = view.start_time_of_state,
        .state_expiration_time = view.state_expiration_time,
        .client_last_transaction_time = view.client_last_transaction_time,
        .partner_lifetime = view.partner_lifetime,
        .partner_raw_client_last_transaction_time =
            view.partner_raw_client_last_transaction_time,
        .expiration_time = view.expiration_time,
        .prefix_length = view.prefix_length};
    const auto bytes =
        encode_binding(MessageType::binding_reply, transaction_id, sent_time,
                       binding, encoded);
    if (!bytes)
      return std::nullopt;
    const auto decoded =
        decode(std::span<const std::uint8_t>{encoded}.first(*bytes));
    const auto container = decoded.status == DecodeStatus::accepted
                               ? decoded.message.first(static_cast<std::uint16_t>(
                                     packet::dhcpv6::OptionCode::client_data))
                               : std::nullopt;
    if (!container)
      return std::nullopt;
    packet::dhcpv6::OptionCursor cursor{container->value};
    while (const auto child = cursor.next()) {
      const bool association =
          child->code == static_cast<std::uint16_t>(
                             packet::dhcpv6::OptionCode::ia_na) ||
          child->code == static_cast<std::uint16_t>(
                             packet::dhcpv6::OptionCode::ia_ta) ||
          child->code == static_cast<std::uint16_t>(
                             packet::dhcpv6::OptionCode::ia_pd);
      // Identity and base-time describe the whole CLIENT_DATA container.
      // Later resource encodings contribute only their IA subcontainer.
      if ((index == 0U || association) &&
          !append_tlv(client_data, client_data_octets, child->code,
                      child->data))
        return std::nullopt;
    }
    if (!cursor.valid())
      return std::nullopt;
  }
  Encoder reply{output};
  if (!reply.begin(MessageType::binding_reply, transaction_id, sent_time) ||
      !reply.option(
          static_cast<std::uint16_t>(
              packet::dhcpv6::OptionCode::client_data),
          std::span<const std::uint8_t>{client_data}.first(client_data_octets)))
    return std::nullopt;
  return reply.message().size();
}

bool Endpoint::configure(Configuration configuration,
                         std::uint32_t absolute_now,
                         Clock::time_point now) {
  if (configuration.relationship_name.empty() ||
      configuration.relationship_name.size() > 128U ||
      configuration.maximum_client_lead_time_seconds == 0U ||
      configuration.keepalive_seconds == 0U ||
      configuration.maximum_response_delay_seconds == 0U ||
      configuration.maximum_unacked_updates == 0U ||
      configuration.maximum_unacked_updates >
          device_catalog::dhcp_failover_updates_in_flight)
    return false;
  configuration_ = std::move(configuration);
  configured_ = true;
  communications_ok_ = false;
  partner_state_.reset();
  update_request_complete_ = false;
  transition(State::startup, absolute_now, now);
  return true;
}

void Endpoint::communication_changed(bool available,
                                     std::uint32_t absolute_now,
                                     Clock::time_point now) noexcept {
  if (!configured_ || available == communications_ok_)
    return;
  communications_ok_ = available;
  contact_deadline_ =
      // The negotiated keepalive value schedules outgoing CONTACT messages.
      // RFC 8156 section 6.6 declares the partner unreachable only after the
      // maximum response delay, so receiving-side failure detection uses that
      // independent deadline.
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
    // CONTACT is emitted by the application owner. Missing all traffic through
    // the negotiated response interval is the evidence that communication is
    // no longer OK, not a direct mutation of the peer endpoint.
    communications_ok_ = false;
    contact_deadline_ = Clock::time_point::max();
  }
  evaluate(absolute_now, now);
}

std::uint32_t Endpoint::allocate_transaction_id() noexcept {
  auto value = next_transaction_id_ & 0x00ffffffU;
  if (value == 0U)
    value = 1U;
  next_transaction_id_ = value == 0x00ffffffU ? 1U : value + 1U;
  return value;
}

Responsiveness Endpoint::responsiveness() const noexcept {
  switch (state_) {
  case State::partner_down:
  case State::communications_interrupted:
  case State::resolution_interrupted:
  case State::conflict_done:
    return Responsiveness::responsive;
  case State::recover_done:
    // RFC 8156 section 8.7 permits only renewal of a lease already present
    // in the request while the two endpoints interlock their return to
    // NORMAL. Treating this state as entirely silent would unnecessarily
    // interrupt valid clients during recovery.
    return Responsiveness::renew_responsive;
  case State::normal:
    return configuration_.role == Role::primary
               ? Responsiveness::responsive
               : Responsiveness::renew_responsive;
  case State::startup:
  case State::recover:
  case State::recover_wait:
  case State::potential_conflict:
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
      value.configuration.maximum_client_lead_time_seconds == 0U ||
      value.configuration.keepalive_seconds == 0U ||
      value.configuration.maximum_response_delay_seconds == 0U ||
      value.configuration.maximum_unacked_updates == 0U ||
      value.configuration.maximum_unacked_updates >
          device_catalog::dhcp_failover_updates_in_flight ||
      !valid_state(value.state) ||
      (value.partner_state && !valid_state(*value.partner_state)) ||
      value.next_transaction_id == 0U ||
      value.next_transaction_id > 0x00ffffffU ||
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
  const auto restore_deadline = [now](std::int64_t remaining) {
    return remaining < 0
               ? Clock::time_point::max()
               : now + std::chrono::nanoseconds{remaining};
  };
  state_deadline_ = restore_deadline(value.state_remaining_nanoseconds);
  contact_deadline_ = restore_deadline(value.contact_remaining_nanoseconds);
  return true;
}

void Endpoint::evaluate(std::uint32_t absolute_now,
                        Clock::time_point now) noexcept {
  switch (state_) {
  case State::startup:
    if (communications_ok_ && partner_state_) {
      update_request_complete_ = false;
      transition(State::recover, absolute_now, now);
    }
    break;
  case State::recover:
    // RFC 8156 section 8.5.2 leaves the endpoint in RECOVER when contact is
    // lost. A restored connection restarts synchronization instead of making
    // the incomplete database responsive.
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
    // RFC 8156 section 8.6.2 deliberately keeps the MCLT timer running when
    // communication fails. The endpoint may reach RECOVER-DONE while the
    // partner is unreachable, so communication status is not a guard here.
    if (now >= state_deadline_) {
      transition(State::recover_done, absolute_now, now);
    }
    break;
  case State::recover_done:
    // RFC 8156 section 8.7.2 says a communication failure leaves this state
    // unchanged. Only newly observed partner state can drive the interlock.
    if (communications_ok_ && partner_state_ &&
               (*partner_state_ == State::normal ||
                *partner_state_ == State::recover_done)) {
      transition(State::normal, absolute_now, now);
    } else if (communications_ok_ && partner_state_ &&
               (*partner_state_ == State::recover ||
                *partner_state_ == State::recover_wait)) {
      transition(State::communications_interrupted, absolute_now, now);
    } else if (communications_ok_ && partner_state_ &&
               *partner_state_ == State::potential_conflict) {
      update_request_complete_ = false;
      transition(State::potential_conflict, absolute_now, now);
    }
    break;
  case State::normal:
    if (!communications_ok_) {
      const auto delay = configuration_.auto_partner_down_seconds
                             ? std::optional<std::chrono::seconds>{
                                   std::chrono::seconds{
                                       *configuration_
                                            .auto_partner_down_seconds}}
                             : std::nullopt;
      transition(State::communications_interrupted, absolute_now, now, delay);
    } else if (partner_state_ && *partner_state_ != State::normal) {
      // A state other than the expected NORMAL peer state first invalidates
      // the communication contract. The COMMUNICATIONS-INTERRUPTED transition
      // table then decides whether safe automatic reintegration is possible.
      transition(State::communications_interrupted, absolute_now, now);
    }
    break;
  case State::communications_interrupted:
    if (communications_ok_) {
      if (partner_state_ &&
          (*partner_state_ == State::normal ||
           *partner_state_ == State::communications_interrupted ||
           *partner_state_ == State::recover_done))
        transition(State::normal, absolute_now, now);
      else if (partner_state_ &&
               (*partner_state_ == State::partner_down ||
                *partner_state_ == State::potential_conflict ||
                *partner_state_ == State::conflict_done ||
                *partner_state_ == State::resolution_interrupted)) {
        update_request_complete_ = false;
        transition(State::potential_conflict, absolute_now, now);
      }
      // A peer in RECOVER cannot safely accept the database owned here. RFC
      // 8156 section 8.9.2 requires remaining communications-interrupted.
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
               *partner_state_ != State::startup) {
      update_request_complete_ = false;
      transition(State::potential_conflict, absolute_now, now);
    }
    break;
  case State::potential_conflict:
    if (!communications_ok_) {
      transition(State::resolution_interrupted, absolute_now, now);
    } else if (update_request_complete_) {
      // Section 8.10.2 deliberately interlocks the peers: the primary first
      // enters CONFLICT-DONE and serves clients while the secondary can return
      // directly to NORMAL after receiving the primary database.
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
    // Communication loss has no state effect here. The primary has completed
    // its half of conflict resolution and remains responsive until the
    // secondary explicitly reports NORMAL.
    if (communications_ok_ && partner_state_ &&
        *partner_state_ == State::normal) {
      transition(State::normal, absolute_now, now);
    }
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
                        std::uint16_t connect_flags,
                        std::uint32_t absolute_now,
                        Clock::time_point now) {
  if ((connect_flags & 0xfffeU) != 0U)
    return false;
  Endpoint staged;
  if (!staged.configure(configuration, absolute_now, now))
    return false;
  configuration_ = std::move(configuration);
  endpoint_ = std::move(staged);
  connect_flags_ = connect_flags;
  pending_head_ = 0U;
  pending_count_ = 0U;
  synchronization_transaction_id_ = 0U;
  phase_ = SessionPhase::disconnected;
  configured_ = true;
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
    phase_ = SessionPhase::awaiting_connect_reply;
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
  const auto skew =
      static_cast<std::int32_t>(absolute_now - message.sent_time);
  if (skew < -5 || skew > 5) {
    // RFC 8156 section 7.5.1 uses five seconds as the connection-level skew
    // threshold. Closing here prevents inconsistent lifetime comparisons.
    fail(absolute_now, now);
    return {.kind = SessionEventKind::protocol_error};
  }

  if (phase_ == SessionPhase::awaiting_connect) {
    NegotiatedParameters negotiated;
    if (validate_negotiation(message, configuration_, false, negotiated) !=
        NegotiationStatus::accepted) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    // The primary defines the MCLT. The secondary adopts the received
    // connection parameters before it makes the endpoint communicative.
    configuration_.maximum_client_lead_time_seconds =
        negotiated.maximum_client_lead_time_seconds;
    configuration_.keepalive_seconds = negotiated.keepalive_seconds;
    configuration_.maximum_unacked_updates =
        static_cast<std::uint16_t>(negotiated.maximum_unacked_updates);
    connect_flags_ = negotiated.connect_flags;
    if (!endpoint_.configure(configuration_, absolute_now, now) ||
        !enqueue(MessageType::connect_reply, message.transaction_id) ||
        !enqueue(MessageType::state)) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    endpoint_.communication_changed(true, absolute_now, now);
    synchronization_transaction_id_ = endpoint_.allocate_transaction_id();
    if (!enqueue(MessageType::update_request_all,
                 synchronization_transaction_id_)) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    phase_ = SessionPhase::synchronizing;
    return {};
  }

  if (phase_ == SessionPhase::awaiting_connect_reply) {
    NegotiatedParameters negotiated;
    if (validate_negotiation(message, configuration_, true, negotiated) !=
            NegotiationStatus::accepted ||
        !enqueue(MessageType::state)) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    configuration_.keepalive_seconds = negotiated.keepalive_seconds;
    configuration_.maximum_unacked_updates =
        static_cast<std::uint16_t>(negotiated.maximum_unacked_updates);
    connect_flags_ = negotiated.connect_flags;
    if (!endpoint_.configure(configuration_, absolute_now, now)) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    endpoint_.communication_changed(true, absolute_now, now);
    synchronization_transaction_id_ = endpoint_.allocate_transaction_id();
    if (!enqueue(MessageType::update_request_all,
                 synchronization_transaction_id_)) {
      fail(absolute_now, now);
      return {.kind = SessionEventKind::protocol_error};
    }
    phase_ = SessionPhase::synchronizing;
    return {};
  }

  endpoint_.communication_changed(true, absolute_now, now);
  switch (message.type) {
  case MessageType::binding_update:
    return {.kind = SessionEventKind::binding_update, .message = message};
  case MessageType::binding_reply:
    return {.kind = SessionEventKind::binding_reply, .message = message};
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
    endpoint_.partner_state_changed(state->state, absolute_now, now);
    return {.kind = SessionEventKind::partner_state_changed,
            .message = message};
  }
  case MessageType::contact:
    return {};
  case MessageType::disconnect:
    transport_closed(absolute_now, now);
    return {.kind = SessionEventKind::peer_disconnected,
            .message = message};
  case MessageType::connect:
  case MessageType::connect_reply:
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
  if (!endpoint_.communications_ok()) {
    phase_ = SessionPhase::disconnected;
    pending_head_ = 0U;
    pending_count_ = 0U;
    return;
  }
  if (pending_count_ == 0U &&
      now - last_transmit_ >=
          std::chrono::seconds{configuration_.keepalive_seconds} &&
      !enqueue(MessageType::contact))
    fail(absolute_now, now);
}

bool Session::finish_synchronization(
    std::uint32_t request_transaction_id) noexcept {
  return configured_ && request_transaction_id != 0U &&
         request_transaction_id <= 0x00ffffffU &&
         enqueue(MessageType::update_done, request_transaction_id);
}

SessionCheckpoint Session::checkpoint(Clock::time_point now) const {
  SessionCheckpoint state{
      .configuration = configuration_,
      .endpoint = endpoint_.checkpoint(now),
      .pending = {},
      .transmit_remaining_nanoseconds = 0,
      .synchronization_transaction_id =
          synchronization_transaction_id_,
      .connect_flags = connect_flags_,
      .phase = phase_};
  state.pending.reserve(pending_count_);
  for (std::size_t offset = 0U; offset < pending_count_; ++offset) {
    const auto &pending =
        pending_[(pending_head_ + offset) % pending_.size()];
    state.pending.push_back(
        {.type = pending.type,
         .transaction_id = pending.transaction_id});
  }
  if (configuration_.keepalive_seconds != 0U) {
    const auto deadline =
        last_transmit_ +
        std::chrono::seconds{configuration_.keepalive_seconds};
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
      (state.connect_flags & 0xfffeU) != 0U ||
      static_cast<std::uint8_t>(state.phase) >
          static_cast<std::uint8_t>(SessionPhase::established))
    return false;

  Session staged;
  if (!staged.configure(state.configuration, state.connect_flags,
                        state.endpoint.state_started_absolute, now) ||
      !staged.endpoint_.restore(state.endpoint, now))
    return false;
  for (const auto &pending : state.pending) {
    const auto type = static_cast<std::uint8_t>(pending.type);
    if (type < static_cast<std::uint8_t>(MessageType::binding_update) ||
        type > static_cast<std::uint8_t>(MessageType::contact) ||
        !staged.enqueue(pending.type, pending.transaction_id))
      return false;
  }
  staged.synchronization_transaction_id_ =
      state.synchronization_transaction_id;
  staged.phase_ = state.phase;
  const auto interval =
      std::chrono::seconds{state.configuration.keepalive_seconds};
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
      pending.type == MessageType::connect_reply) {
    encoded = encode_negotiation(
        pending.type, pending.transaction_id, absolute_now, configuration_,
        connect_flags_, output);
  } else if (pending.type == MessageType::state) {
    const auto checkpoint = endpoint_.checkpoint(now);
    const bool startup = checkpoint.state == State::startup;
    const auto advertised =
        startup ? State::normal : checkpoint.state;
    encoded = encode_state(
        pending.transaction_id, absolute_now,
        {.state = advertised,
         .flags = static_cast<std::uint8_t>(startup ? 1U : 0U),
         .started_at = checkpoint.state_started_absolute,
         .partner_down_at =
             advertised == State::partner_down
                 ? std::optional{checkpoint.state_started_absolute}
                 : std::nullopt},
        output);
  } else {
    Encoder encoder{output};
    if (encoder.begin(pending.type, pending.transaction_id, absolute_now))
      encoded = encoder.message().size();
  }
  if (!encoded)
    return std::nullopt;
  pending_head_ = (pending_head_ + 1U) % pending_.size();
  --pending_count_;
  last_transmit_ = now;
  return encoded;
}

} // namespace router::dhcpv6::failover
