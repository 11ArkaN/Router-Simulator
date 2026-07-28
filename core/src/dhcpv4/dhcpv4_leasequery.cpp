// DHCPv4 Leasequery TCP wire framing and request validation. This file has no
// socket, clock or lease dependencies, which keeps malformed stream handling
// testable without manufacturing a network shortcut.

#include "router/dhcpv4_leasequery.hpp"

#include <algorithm>
#include <limits>

namespace router::dhcpv4::leasequery {
namespace {

std::optional<std::uint32_t>
u32_option(const packet::dhcpv4::MessageView &message,
           packet::dhcpv4::OptionCode wanted, bool &duplicate_or_invalid,
           bool &present) noexcept {
  std::array<std::uint8_t, 4U> bytes{};
  packet::dhcpv4::RawOptionCursor cursor{message};
  while (const auto option = cursor.next()) {
    if (option->code != static_cast<std::uint8_t>(wanted))
      continue;
    if (present || option->data.size() != bytes.size()) {
      duplicate_or_invalid = true;
      continue;
    }
    std::copy(option->data.begin(), option->data.end(), bytes.begin());
    present = true;
  }
  if (!cursor.valid())
    duplicate_or_invalid = true;
  if (!present)
    return std::nullopt;
  return static_cast<std::uint32_t>(bytes[0]) << 24U |
         static_cast<std::uint32_t>(bytes[1]) << 16U |
         static_cast<std::uint32_t>(bytes[2]) << 8U |
         static_cast<std::uint32_t>(bytes[3]);
}

bool zero(packet::Ipv4 value) noexcept {
  return std::ranges::all_of(value,
                             [](std::uint8_t octet) { return octet == 0U; });
}

std::optional<std::span<const std::uint8_t>>
relay_suboption(std::span<const std::uint8_t> option,
                std::uint8_t wanted, bool &invalid) noexcept {
  std::optional<std::span<const std::uint8_t>> result;
  while (!option.empty()) {
    if (option.size() < 2U) {
      invalid = true;
      return std::nullopt;
    }
    const auto code = option[0U];
    const auto length = static_cast<std::size_t>(option[1U]);
    option = option.subspan(2U);
    if (length > option.size()) {
      invalid = true;
      return std::nullopt;
    }
    if (code == wanted) {
      if (result || length == 0U) {
        invalid = true;
        return std::nullopt;
      }
      result = option.first(length);
    }
    option = option.subspan(length);
  }
  return result;
}

std::array<std::uint8_t, 4U> u32(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24U),
          static_cast<std::uint8_t>(value >> 16U),
          static_cast<std::uint8_t>(value >> 8U),
          static_cast<std::uint8_t>(value)};
}

bool requested(std::span<const std::uint8_t> options,
               packet::dhcpv4::OptionCode code) noexcept {
  return std::ranges::find(options, static_cast<std::uint8_t>(code)) !=
         options.end();
}

std::uint32_t elapsed_seconds(LeaseRepository::Clock::time_point then,
                              LeaseRepository::Clock::time_point now) noexcept {
  if (then >= now)
    return 0U;
  return static_cast<std::uint32_t>(std::min<std::int64_t>(
      std::numeric_limits<std::uint32_t>::max(),
      std::chrono::duration_cast<std::chrono::seconds>(now - then).count()));
}

WireBindingState wire_state(BindingState state) noexcept {
  switch (state) {
  case BindingState::active:
    return WireBindingState::active;
  case BindingState::expired:
    return WireBindingState::expired;
  case BindingState::released:
    return WireBindingState::released;
  case BindingState::declined:
  case BindingState::conflict:
    return WireBindingState::abandoned;
  case BindingState::reserved:
    return WireBindingState::available;
  case BindingState::pending_offer:
    // A pending OFFER is neither available nor leased. TRANSITIONING is the
    // RFC state intended for a binding temporarily between stable states.
    return WireBindingState::transitioning;
  }
  return WireBindingState::reset;
}

} // namespace

StreamResult StreamDecoder::current() const noexcept {
  if (malformed_)
    return {.status = StreamStatus::malformed_length};
  if (complete_octets_ == 0U)
    return {.status = StreamStatus::need_more};
  return {.status = StreamStatus::message_ready,
          .message = std::span<const std::uint8_t>{storage_}.subspan(
              frame_prefix_octets, complete_octets_)};
}

StreamResult
StreamDecoder::ingest(std::span<const std::uint8_t> bytes) noexcept {
  if (malformed_ || complete_octets_ != 0U)
    return current();
  std::size_t wanted = frame_prefix_octets;
  if (occupied_ >= frame_prefix_octets) {
    const auto length = static_cast<std::size_t>(storage_[0]) << 8U |
                        static_cast<std::size_t>(storage_[1]);
    wanted += length;
  }
  const auto accepted =
      std::min(bytes.size(), wanted > occupied_ ? wanted - occupied_ : 0U);
  std::copy_n(bytes.begin(), accepted, storage_.begin() + occupied_);
  occupied_ += accepted;
  if (occupied_ < frame_prefix_octets)
    return {.status = StreamStatus::need_more,
            .accepted_octets = accepted};

  const auto length = static_cast<std::size_t>(storage_[0]) << 8U |
                      static_cast<std::size_t>(storage_[1]);
  // A legal DHCPv4 message must contain the fixed BOOTP header, cookie and at
  // least the End option. Rejecting impossible lengths here prevents a peer
  // from keeping the connection open with a zero-length frame.
  if (length < packet::dhcpv4::options_offset + 1U ||
      length > packet::dhcpv4::maximum_message_octets) {
    malformed_ = true;
    return {.status = StreamStatus::malformed_length,
            .accepted_octets = accepted};
  }
  if (occupied_ < frame_prefix_octets + length) {
    // The prefix may have arrived in this call. Consume payload bytes from
    // the same TCP read before returning so ordinary coalescing does not
    // require an artificial extra socket read.
    const auto remaining_input = bytes.subspan(accepted);
    const auto payload_needed =
        frame_prefix_octets + length - occupied_;
    const auto payload_accepted =
        std::min(remaining_input.size(), payload_needed);
    std::copy_n(remaining_input.begin(), payload_accepted,
                storage_.begin() + occupied_);
    occupied_ += payload_accepted;
    if (occupied_ < frame_prefix_octets + length)
      return {.status = StreamStatus::need_more,
              .accepted_octets = accepted + payload_accepted};
    complete_octets_ = length;
    auto result = current();
    result.accepted_octets = accepted + payload_accepted;
    return result;
  }
  complete_octets_ = length;
  auto result = current();
  result.accepted_octets = accepted;
  return result;
}

void StreamDecoder::consume() noexcept {
  if (complete_octets_ == 0U)
    return;
  const auto consumed = frame_prefix_octets + complete_octets_;
  const auto remaining = occupied_ - consumed;
  std::move(storage_.begin() + static_cast<std::ptrdiff_t>(consumed),
            storage_.begin() + static_cast<std::ptrdiff_t>(occupied_),
            storage_.begin());
  occupied_ = remaining;
  complete_octets_ = 0U;
  malformed_ = false;
  // Parsing the next buffered frame requires no new TCP read. Reuse ingest
  // with an empty span so callers can drain all coalesced messages.
  static_cast<void>(ingest({}));
}

void StreamDecoder::reset() noexcept {
  occupied_ = 0U;
  complete_octets_ = 0U;
  malformed_ = false;
}

StreamDecoderCheckpoint StreamDecoder::checkpoint() const {
  StreamDecoderCheckpoint state{
      .storage = {},
      .occupied = occupied_,
      .complete_octets = complete_octets_,
      .malformed = malformed_};
  state.storage.assign(storage_.begin(),
                       storage_.begin() +
                           static_cast<std::ptrdiff_t>(occupied_));
  return state;
}

bool StreamDecoder::restore(
    const StreamDecoderCheckpoint &state) noexcept {
  if (state.occupied != state.storage.size() ||
      state.occupied > storage_.size() ||
      state.complete_octets >
          packet::dhcpv4::maximum_message_octets ||
      (state.complete_octets != 0U &&
       state.occupied <
           frame_prefix_octets + state.complete_octets))
    return false;
  if (state.occupied >= frame_prefix_octets) {
    const auto declared = static_cast<std::size_t>(state.storage[0]) << 8U |
                          static_cast<std::size_t>(state.storage[1]);
    if ((!state.malformed &&
         (declared < packet::dhcpv4::options_offset + 1U ||
          declared > packet::dhcpv4::maximum_message_octets)) ||
        (state.complete_octets != 0U &&
         declared != state.complete_octets))
      return false;
  } else if (state.complete_octets != 0U || state.malformed) {
    return false;
  }
  std::fill(storage_.begin(), storage_.end(), std::uint8_t{});
  std::copy(state.storage.begin(), state.storage.end(), storage_.begin());
  occupied_ = state.occupied;
  complete_octets_ = state.complete_octets;
  malformed_ = state.malformed;
  return true;
}

std::optional<std::size_t>
encode_frame(std::span<const std::uint8_t> message,
             std::span<std::uint8_t> output) noexcept {
  if (message.size() < packet::dhcpv4::options_offset + 1U ||
      message.size() > packet::dhcpv4::maximum_message_octets ||
      output.size() < frame_prefix_octets + message.size())
    return std::nullopt;
  output[0] = static_cast<std::uint8_t>(message.size() >> 8U);
  output[1] = static_cast<std::uint8_t>(message.size());
  std::copy(message.begin(), message.end(),
            output.begin() + frame_prefix_octets);
  return frame_prefix_octets + message.size();
}

RequestParseResult
parse_request_result(std::span<const std::uint8_t> message) noexcept {
  const auto parsed = packet::dhcpv4::parse(message);
  if (!parsed ||
      parsed->operation != packet::dhcpv4::Operation::boot_request ||
      !zero(parsed->client_address) || !zero(parsed->your_address) ||
      !zero(parsed->server_address))
    return {.status = RequestParseStatus::malformed};
  const auto message_type = packet::dhcpv4::message_type(*parsed);
  if (!message_type)
    return {.status = RequestParseStatus::malformed};

  RequestView result{.transaction_id = parsed->transaction_id};
  switch (*message_type) {
  case packet::dhcpv4::MessageType::bulk_lease_query:
    result.kind = RequestKind::bulk;
    break;
  case packet::dhcpv4::MessageType::active_lease_query:
    // RFC 7724 forbids both a hardware address and Client Identifier because
    // an Active query subscribes to all allowed binding changes.
    if (parsed->hardware_length != 0U)
      return {.status = RequestParseStatus::malformed};
    result.kind = RequestKind::active;
    break;
  case packet::dhcpv4::MessageType::tls:
    result.kind = RequestKind::tls;
    break;
  default:
    return {.status = RequestParseStatus::not_allowed};
  }

  bool invalid{};
  bool start_present{};
  bool end_present{};
  result.query_start_time =
      u32_option(*parsed, packet::dhcpv4::OptionCode::query_start_time,
                 invalid, start_present);
  result.query_end_time =
      u32_option(*parsed, packet::dhcpv4::OptionCode::query_end_time,
                 invalid, end_present);
  if (invalid || (result.kind == RequestKind::active && end_present) ||
      (start_present && end_present &&
       *result.query_start_time > *result.query_end_time))
    return {.status = RequestParseStatus::malformed};

  std::array<std::uint8_t, 255U> client_identifier{};
  const auto normalized_client = packet::dhcpv4::normalize_option(
      *parsed,
      static_cast<std::uint8_t>(
          packet::dhcpv4::OptionCode::client_identifier),
      client_identifier);
  std::array<std::uint8_t, 255U> relay_information{};
  const auto normalized_relay = packet::dhcpv4::normalize_option(
      *parsed,
      static_cast<std::uint8_t>(
          packet::dhcpv4::OptionCode::relay_agent_information),
      relay_information);
  const auto normalized_requested = packet::dhcpv4::normalize_option(
      *parsed,
      static_cast<std::uint8_t>(
          packet::dhcpv4::OptionCode::parameter_request_list),
      result.requested_options);
  if (!normalized_client || !normalized_relay || !normalized_requested ||
      normalized_client->octets > result.selector_value.size() ||
      normalized_requested->octets > result.requested_options.size())
    return {.status = RequestParseStatus::malformed};
  result.requested_option_octets =
      static_cast<std::uint16_t>(normalized_requested->octets);

  bool relay_invalid{};
  const auto relay_bytes =
      std::span<const std::uint8_t>{relay_information}.first(
          normalized_relay->octets);
  // RFC 3046 assigns Remote-ID suboption 2. RFC 6925 assigns Relay-ID
  // suboption 12. The parser validates the entire suboption stream even when
  // neither selector is requested, preventing malformed trailing bytes from
  // being treated as an all-address query.
  const auto remote_id = relay_suboption(relay_bytes, 2U, relay_invalid);
  const auto relay_id = relay_suboption(relay_bytes, 12U, relay_invalid);
  if (relay_invalid)
    return {.status = RequestParseStatus::malformed};

  const bool hardware =
      parsed->hardware_type != 0U && parsed->hardware_length != 0U;
  if (parsed->hardware_length > parsed->client_hardware_address.size() ||
      (parsed->hardware_length != 0U && parsed->hardware_type == 0U))
    return {.status = RequestParseStatus::malformed};
  const auto selector_count = static_cast<unsigned>(hardware) +
                              static_cast<unsigned>(
                                  normalized_client->occurrences != 0U) +
                              static_cast<unsigned>(remote_id.has_value()) +
                              static_cast<unsigned>(relay_id.has_value());
  if (result.kind == RequestKind::active && selector_count != 0U)
    return {.status = RequestParseStatus::malformed};
  if (result.kind == RequestKind::bulk && selector_count > 1U)
    return {.status = RequestParseStatus::not_allowed};

  auto select = [&](SelectorKind kind, std::span<const std::uint8_t> value) {
    result.selector = kind;
    result.selector_octets = static_cast<std::uint16_t>(value.size());
    std::copy(value.begin(), value.end(), result.selector_value.begin());
  };
  if (hardware) {
    result.hardware_type = parsed->hardware_type;
    select(SelectorKind::hardware_address,
           std::span{parsed->client_hardware_address}.first(
               parsed->hardware_length));
  } else if (normalized_client->occurrences != 0U) {
    if (normalized_client->octets == 0U)
      return {.status = RequestParseStatus::malformed};
    select(SelectorKind::client_identifier,
           std::span{client_identifier}.first(normalized_client->octets));
  } else if (remote_id) {
    select(SelectorKind::remote_identifier, *remote_id);
  } else if (relay_id) {
    select(SelectorKind::relay_identifier, *relay_id);
  }
  return {.status = RequestParseStatus::accepted, .request = result};
}

std::optional<RequestView>
parse_request(std::span<const std::uint8_t> message) noexcept {
  auto parsed = parse_request_result(message);
  return parsed.status == RequestParseStatus::accepted
             ? std::optional<RequestView>{std::move(parsed.request)}
             : std::nullopt;
}

bool matches(const RequestView &request, const Lease &lease,
             std::uint32_t base_time,
             LeaseRepository::Clock::time_point now) noexcept {
  const auto state_elapsed = elapsed_seconds(lease.last_state_change, now);
  const auto absolute_change =
      state_elapsed > base_time ? 0U : base_time - state_elapsed;
  if ((request.query_start_time &&
       absolute_change < *request.query_start_time) ||
      (request.query_end_time &&
       absolute_change > *request.query_end_time))
    return false;

  const auto selector =
      std::span{request.selector_value}.first(request.selector_octets);
  switch (request.selector) {
  case SelectorKind::all_configured:
    return true;
  case SelectorKind::hardware_address:
    return lease.state == BindingState::active &&
           lease.hardware.type == request.hardware_type &&
           lease.hardware.length == request.selector_octets &&
           std::ranges::equal(
               std::span{lease.hardware.address}.first(lease.hardware.length),
               selector);
  case SelectorKind::client_identifier:
    return lease.state == BindingState::active && lease.client.option_61 &&
           lease.client.octets == request.selector_octets &&
           std::ranges::equal(
               std::span{lease.client.bytes}.first(lease.client.octets),
               selector);
  case SelectorKind::remote_identifier:
  case SelectorKind::relay_identifier: {
    if (lease.state != BindingState::active)
      return false;
    bool invalid{};
    const auto relay = std::span{lease.relay_agent_information}.first(
        lease.relay_agent_information_octets);
    const auto found = relay_suboption(
        relay,
        request.selector == SelectorKind::remote_identifier ? 2U : 12U,
        invalid);
    return !invalid && found && std::ranges::equal(*found, selector);
  }
  }
  return false;
}

std::optional<std::size_t>
encode_binding_reply(const BindingReplyInput &input,
                     std::span<std::uint8_t> output) noexcept {
  if (input.address == packet::Ipv4{} ||
      input.server_identifier == packet::Ipv4{})
    return std::nullopt;
  const bool active =
      input.lease && input.lease->state == BindingState::active &&
      input.lease->active_until > input.now;
  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_reply,
      .hardware_type = static_cast<std::uint8_t>(
          input.lease ? input.lease->hardware.type : 0U),
      .hardware_length = static_cast<std::uint8_t>(
          input.lease ? input.lease->hardware.length : 0U),
      .transaction_id = input.transaction_id,
      .client_address = input.address,
      .client_hardware_address =
          input.lease ? input.lease->hardware.address
                      : std::array<std::uint8_t, 16U>{}};
  auto writer = packet::dhcpv4::begin(output, header);
  const std::array message_type{static_cast<std::uint8_t>(
      active ? packet::dhcpv4::MessageType::lease_active
             : packet::dhcpv4::MessageType::lease_unassigned)};
  if (!writer ||
      !writer->append(
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::message_type),
          message_type))
    return std::nullopt;

  if (input.include_server_identifier &&
      !writer->append(
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::server_identifier),
          input.server_identifier))
    return std::nullopt;

  const auto request = input.requested_options;
  if (input.lease && input.lease->client.option_61 &&
      requested(request, packet::dhcpv4::OptionCode::client_identifier) &&
      !writer->append(
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::client_identifier),
          std::span{input.lease->client.bytes}.first(
              input.lease->client.octets)))
    return std::nullopt;

  if (active &&
      requested(request, packet::dhcpv4::OptionCode::lease_time)) {
    const auto remaining =
        input.lease->active_until <= input.now
            ? 0U
            : static_cast<std::uint32_t>(std::min<std::int64_t>(
                  std::numeric_limits<std::uint32_t>::max(),
                  std::chrono::duration_cast<std::chrono::seconds>(
                      input.lease->active_until - input.now)
                      .count()));
    const auto value = u32(remaining);
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::lease_time),
            value))
      return std::nullopt;
  }

  if (requested(request, packet::dhcpv4::OptionCode::base_time) ||
      input.active_query) {
    const auto value = u32(input.base_time);
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::base_time),
            value))
      return std::nullopt;
  }
  if (input.lease &&
      requested(request,
                packet::dhcpv4::OptionCode::start_time_of_state)) {
    const auto value =
        u32(elapsed_seconds(input.lease->last_state_change, input.now));
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::start_time_of_state),
            value))
      return std::nullopt;
  }
  if (input.lease &&
      requested(request,
                packet::dhcpv4::OptionCode::client_last_transaction_time)) {
    const auto value =
        u32(elapsed_seconds(input.lease->last_client_transaction, input.now));
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::client_last_transaction_time),
            value))
      return std::nullopt;
  }
  if (requested(request, packet::dhcpv4::OptionCode::dhcp_state)) {
    const std::array value{static_cast<std::uint8_t>(
        input.lease ? wire_state(input.lease->state)
                    : WireBindingState::available)};
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::dhcp_state),
            value))
      return std::nullopt;
  }
  if (input.lease && input.lease->relay_agent_information_octets != 0U &&
      requested(request,
                packet::dhcpv4::OptionCode::relay_agent_information) &&
      !writer->append(
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::relay_agent_information),
          std::span{input.lease->relay_agent_information}.first(
              input.lease->relay_agent_information_octets)))
    return std::nullopt;
  if (input.pool &&
      requested(request, packet::dhcpv4::OptionCode::subnet_mask) &&
      !writer->append(
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::subnet_mask),
          input.pool->subnet_mask))
    return std::nullopt;
  if (active && input.pool && input.pool->router != packet::Ipv4{} &&
      requested(request, packet::dhcpv4::OptionCode::router) &&
      !writer->append(
          static_cast<std::uint8_t>(packet::dhcpv4::OptionCode::router),
          input.pool->router))
    return std::nullopt;

  return writer->finish()
             ? std::optional<std::size_t>{writer->view().size()}
             : std::nullopt;
}

std::optional<std::size_t>
encode_status_reply(RequestKind kind, std::uint32_t transaction_id,
                    StatusCode status, std::uint32_t base_time,
                    std::span<const std::uint8_t> text,
                    std::span<std::uint8_t> output) noexcept {
  if (text.size() > 253U)
    return std::nullopt;
  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_reply,
      .transaction_id = transaction_id};
  auto writer = packet::dhcpv4::begin(output, header);
  const auto type =
      kind == RequestKind::bulk
          ? packet::dhcpv4::MessageType::lease_query_done
          : kind == RequestKind::active
                ? packet::dhcpv4::MessageType::lease_query_status
                : packet::dhcpv4::MessageType::tls;
  const std::array message_type{static_cast<std::uint8_t>(type)};
  std::array<std::uint8_t, 255U> status_value{};
  status_value[0U] = static_cast<std::uint8_t>(
      static_cast<std::uint16_t>(status) >> 8U);
  status_value[1U] = static_cast<std::uint8_t>(status);
  std::copy(text.begin(), text.end(), status_value.begin() + 2U);
  if (!writer ||
      !writer->append(
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::message_type),
          message_type) ||
      (status != StatusCode::success &&
       !writer->append(
           static_cast<std::uint8_t>(
               packet::dhcpv4::OptionCode::status_code),
           std::span{status_value}.first(text.size() + 2U))))
    return std::nullopt;
  if (kind == RequestKind::active) {
    const auto value = u32(base_time);
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::base_time),
            value))
      return std::nullopt;
  }
  return writer->finish()
             ? std::optional<std::size_t>{writer->view().size()}
             : std::nullopt;
}

} // namespace router::dhcpv4::leasequery
