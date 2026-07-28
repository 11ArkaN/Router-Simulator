// DHCPv4 server message processing. All lease mutations are delegated to the
// single-owner repository before a response is emitted, so packet output never
// describes a binding that the runtime failed to commit.

#include "router/dhcpv4_server.hpp"
#include "router/interface_identity.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace router::dhcpv4 {
namespace {

[[nodiscard]] bool zero(packet::Ipv4 value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [](std::uint8_t octet) { return octet == 0U; });
}

[[nodiscard]] ClientHardwareIdentity
hardware_identity(const packet::dhcpv4::MessageView &message) noexcept {
  ClientHardwareIdentity result{
      .address = message.client_hardware_address,
      .type = message.hardware_type,
      .length = message.hardware_length};
  return result.length <= result.address.size() ? result
                                                : ClientHardwareIdentity{};
}

[[nodiscard]] std::optional<packet::Ipv4>
ipv4_option(const packet::dhcpv4::MessageView &message,
            packet::dhcpv4::OptionCode code) noexcept {
  std::array<std::uint8_t, 4U> data{};
  const auto normalized = packet::dhcpv4::normalize_option(
      message, static_cast<std::uint8_t>(code), data);
  if (!normalized || normalized->occurrences == 0U)
    return std::nullopt;
  if (normalized->occurrences != 1U || normalized->octets != data.size())
    return std::nullopt;
  return packet::Ipv4{data[0U], data[1U], data[2U], data[3U]};
}

[[nodiscard]] std::array<std::uint8_t, 4U>
u32(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24U),
          static_cast<std::uint8_t>(value >> 16U),
          static_cast<std::uint8_t>(value >> 8U),
          static_cast<std::uint8_t>(value)};
}

[[nodiscard]] std::span<const std::uint8_t>
bytes(const packet::Ipv4 &address) noexcept {
  return {address.data(), address.size()};
}

[[nodiscard]] std::uint32_t word(packet::Ipv4 address) noexcept {
  return static_cast<std::uint32_t>(address[0U]) << 24U |
         static_cast<std::uint32_t>(address[1U]) << 16U |
         static_cast<std::uint32_t>(address[2U]) << 8U |
         static_cast<std::uint32_t>(address[3U]);
}

[[nodiscard]] std::optional<std::uint32_t>
u32_option(const packet::dhcpv4::MessageView &message,
           packet::dhcpv4::OptionCode code) noexcept {
  const auto encoded = ipv4_option(message, code);
  return encoded ? std::optional{word(*encoded)} : std::nullopt;
}

struct LinkSelectionResult {
  std::optional<packet::Ipv4> address;
  bool valid{true};
};

struct RawOptionResult {
  std::span<const std::uint8_t> value{};
  bool present{};
  bool valid{true};
};

[[nodiscard]] RawOptionResult
single_raw_option(const packet::dhcpv4::MessageView &message,
                  packet::dhcpv4::OptionCode selected) noexcept {
  RawOptionResult result;
  packet::dhcpv4::RawOptionCursor options{message};
  while (const auto option = options.next()) {
    if (option->code != static_cast<std::uint8_t>(selected))
      continue;
    if (result.present)
      return {.valid = false};
    result.value = option->data;
    result.present = true;
  }
  result.valid = options.valid();
  return result;
}

[[nodiscard]] bool requested_option(std::span<const std::uint8_t> list,
                                    bool list_present,
                                    packet::dhcpv4::OptionCode code) noexcept {
  // RFC 4388 falls back to the ordinary DHCPREQUEST option set when no
  // Parameter Request List exists. The caller uses this helper only for that
  // ordinary non-sensitive set. A present empty list requests none.
  return !list_present ||
         std::ranges::find(list, static_cast<std::uint8_t>(code)) !=
             list.end();
}

[[nodiscard]] LinkSelectionResult
relay_link_selection(const packet::dhcpv4::MessageView &message) noexcept {
  // RFC 3527 defines Link Selection as sub-option 5 with exactly four octets.
  // More than one occurrence is ambiguous and malformed. The raw option
  // cursor is used because Option 82 sub-options have their own TLV namespace.
  std::optional<packet::Ipv4> selected;
  packet::dhcpv4::RawOptionCursor options{message};
  while (const auto option = options.next()) {
    if (option->code != static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::
                                relay_agent_information))
      continue;
    std::size_t offset = 0U;
    while (offset < option->data.size()) {
      if (option->data.size() - offset < 2U)
        return {.address = std::nullopt, .valid = false};
      const auto code = option->data[offset++];
      const auto length = option->data[offset++];
      if (option->data.size() - offset < length)
        return {.address = std::nullopt, .valid = false};
      if (code == 5U) {
        if (length != packet::Ipv4{}.size() || selected)
          return {.address = std::nullopt, .valid = false};
        selected = packet::Ipv4{
            option->data[offset], option->data[offset + 1U],
            option->data[offset + 2U], option->data[offset + 3U]};
      }
      offset += length;
    }
  }
  return {.address = selected, .valid = options.valid()};
}

} // namespace

bool Server::configure(const ServerConfiguration &configuration,
                       std::span<const Pool> pools,
                       std::span<const Reservation> reservations,
                       std::span<const ExcludedRange> exclusions) {
  if (configuration.server_instance == 0U ||
      zero(configuration.server_identifier) ||
      configuration.domain_name_servers.size() >
          (std::numeric_limits<std::uint8_t>::max() /
           packet::Ipv4{}.size()))
    return false;

  LeaseRepository replacement = leases_;
  if (!replacement.configure(pools, reservations, configuration.offer_hold,
                             configuration.decline_hold, exclusions))
    return false;
  try {
    configuration_ = configuration;
    leases_ = std::move(replacement);
  } catch (...) {
    return false;
  }
  configured_ = true;
  return true;
}

ServerProcessResult Server::response(
    const packet::dhcpv4::MessageView &request,
    packet::dhcpv4::MessageType response_type,
    packet::Ipv4 offered_address, const Pool *pool,
    const ClientKey &client, std::uint32_t lease_seconds,
    packet::Ipv4 server_identifier,
    std::span<std::uint8_t> output) const {
  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_reply,
      .hardware_type = request.hardware_type,
      .hardware_length = request.hardware_length,
      .hops = 0U,
      .transaction_id = request.transaction_id,
      .seconds = 0U,
      .flags = request.flags,
      .client_address = request.client_address,
      .your_address = offered_address,
      .server_address = {},
      .gateway_address = request.gateway_address,
      .client_hardware_address = request.client_hardware_address,
  };
  auto writer = packet::dhcpv4::begin(output, header);
  const std::array type{static_cast<std::uint8_t>(response_type)};
  if (!writer ||
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::message_type),
                      type) ||
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::server_identifier),
                      bytes(server_identifier)))
    return {.status = ServerProcessStatus::output_too_small};

  // RFC 6842 requires the server to copy Option 61 to OFFER and ACK. The raw
  // hardware fallback is not encoded as Option 61 because the client did not
  // send that option.
  if (client.option_61 &&
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::client_identifier),
                      std::span{client.bytes.data(), client.octets}))
    return {.status = ServerProcessStatus::output_too_small};

  if (pool && (response_type == packet::dhcpv4::MessageType::offer ||
               response_type ==
                   packet::dhcpv4::MessageType::acknowledgement)) {
    const auto lease = u32(lease_seconds);
    if (!writer->append(static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::lease_time),
                        lease) ||
        !writer->append(static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::subnet_mask),
                        bytes(pool->subnet_mask)) ||
        (!zero(pool->router) &&
         !writer->append(static_cast<std::uint8_t>(
                             packet::dhcpv4::OptionCode::router),
                         bytes(pool->router))))
      return {.status = ServerProcessStatus::output_too_small};

    if (pool->renewal_seconds != 0U) {
      const auto renewal = u32(pool->renewal_seconds);
      if (!writer->append(static_cast<std::uint8_t>(
                              packet::dhcpv4::OptionCode::renewal_time),
                          renewal))
        return {.status = ServerProcessStatus::output_too_small};
    }
    if (pool->rebinding_seconds != 0U) {
      const auto rebinding = u32(pool->rebinding_seconds);
      if (!writer->append(static_cast<std::uint8_t>(
                              packet::dhcpv4::OptionCode::rebinding_time),
                          rebinding))
        return {.status = ServerProcessStatus::output_too_small};
    }
  }

  if (!configuration_.domain_name_servers.empty()) {
    // Serialize explicitly instead of depending on std::array object layout.
    // The fixed scratch fits the one-octet DHCPv4 option length domain.
    std::array<std::uint8_t, 252U> dns_bytes{};
    std::size_t position = 0U;
    for (const auto &server : configuration_.domain_name_servers) {
      std::copy(server.begin(), server.end(),
                dns_bytes.begin() + static_cast<std::ptrdiff_t>(position));
      position += server.size();
    }
    if (!writer->append(static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::domain_name_server),
                        std::span{dns_bytes.data(), position}))
      return {.status = ServerProcessStatus::output_too_small};
  }
  if (!writer->finish())
    return {.status = ServerProcessStatus::output_too_small};

  const auto relayed = !zero(request.gateway_address);
  const auto broadcast_requested = (request.flags & 0x8000U) != 0U;
  return {.status = ServerProcessStatus::response,
          .message_octets = writer->view().size(),
          .limited_broadcast = !relayed && broadcast_requested,
          .direct_client_l2 =
              !relayed && !broadcast_requested && zero(request.client_address)};
}

ServerProcessResult Server::lease_query_response(
    const packet::dhcpv4::MessageView &request,
    std::span<std::uint8_t> output, Clock::time_point now) {
  // RFC 4388 section 6.3 defines three mutually exclusive query regimes and
  // requires giaddr solely as the routed return address. It must not scope
  // the lease lookup as it does for an allocation request.
  if (zero(request.gateway_address))
    return {.status = ServerProcessStatus::malformed};

  const auto identifier_option = single_raw_option(
      request, packet::dhcpv4::OptionCode::client_identifier);
  if (!identifier_option.valid ||
      (identifier_option.present && identifier_option.value.empty()))
    return {.status = ServerProcessStatus::malformed};
  const bool address_query = !zero(request.client_address);
  const bool hardware_query =
      request.hardware_type != 0U && request.hardware_length != 0U &&
      request.hardware_length <= request.client_hardware_address.size() &&
      std::ranges::any_of(
          std::span{request.client_hardware_address}.first(
              request.hardware_length),
          [](std::uint8_t octet) { return octet != 0U; });
  const auto query_forms = static_cast<unsigned>(address_query) +
                           static_cast<unsigned>(hardware_query) +
                           static_cast<unsigned>(identifier_option.present);
  if (query_forms != 1U)
    return {.status = ServerProcessStatus::malformed};

  leases_.expire(now);
  const Lease *selected{};
  ClientKey selected_key{};
  if (address_query) {
    selected = leases_.active_lease_at(request.client_address, now);
  } else {
    const auto key = client_key(request);
    if (!key)
      return {.status = ServerProcessStatus::malformed};
    selected_key = *key;
    for (const auto &lease : leases_.leases()) {
      if (lease.state != BindingState::active ||
          lease.active_until <= now ||
          !equal_client_key(lease.client, *key))
        continue;
      if (!selected ||
          lease.last_client_transaction >
              selected->last_client_transaction)
        selected = &lease;
    }
  }

  bool managed = false;
  if (address_query) {
    const auto queried = word(request.client_address);
    managed = std::ranges::any_of(leases_.pools(), [&](const Pool &pool) {
      return pool.enabled &&
             pool.scope.server_instance == configuration_.server_instance &&
             pool.scope.routing_context == configuration_.routing_context &&
             queried >= word(pool.first) && queried <= word(pool.last);
    });
  }
  const auto response_type =
      selected ? packet::dhcpv4::MessageType::lease_active
               : (address_query && managed
                      ? packet::dhcpv4::MessageType::lease_unassigned
                      : packet::dhcpv4::MessageType::lease_unknown);

  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_reply,
      .hardware_type =
          selected ? selected->hardware.type : std::uint8_t{},
      .hardware_length =
          selected ? selected->hardware.length : std::uint8_t{},
      .transaction_id = request.transaction_id,
      .client_address =
          selected ? selected->address
                   : (address_query ? request.client_address : packet::Ipv4{}),
      .gateway_address = request.gateway_address,
      .client_hardware_address =
          selected ? selected->hardware.address
                   : std::array<std::uint8_t, 16U>{},
  };
  auto writer = packet::dhcpv4::begin(output, header);
  const std::array type{static_cast<std::uint8_t>(response_type)};
  if (!writer ||
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::message_type),
                      type))
    return {.status = ServerProcessStatus::output_too_small};

  // RFC 4388 forbids every option other than Message Type in UNKNOWN and
  // completes UNASSIGNED once ciaddr is set. ACTIVE alone carries binding
  // details requested by the access concentrator.
  if (selected) {
    std::array<std::uint8_t, 255U> parameter_request_list{};
    const auto normalized = packet::dhcpv4::normalize_option(
        request,
        static_cast<std::uint8_t>(
            packet::dhcpv4::OptionCode::parameter_request_list),
        parameter_request_list);
    if (!normalized)
      return {.status = ServerProcessStatus::malformed};
    const bool list_present = normalized->occurrences != 0U;
    const auto requested = std::span{parameter_request_list}.first(
        normalized->octets);
    const auto *pool =
        leases_.pool_for(selected->scope, selected->address);

    if (selected->client.option_61 &&
        requested_option(requested, list_present,
                         packet::dhcpv4::OptionCode::client_identifier) &&
        !writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::client_identifier),
            std::span{selected->client.bytes.data(),
                      selected->client.octets}))
      return {.status = ServerProcessStatus::output_too_small};

    const auto remaining = selected->active_until - now;
    const auto remaining_seconds = static_cast<std::uint32_t>(
        std::min<std::int64_t>(
            std::numeric_limits<std::uint32_t>::max(),
            std::max<std::int64_t>(
                0, std::chrono::duration_cast<std::chrono::seconds>(
                       remaining)
                       .count())));
    if (requested_option(requested, list_present,
                         packet::dhcpv4::OptionCode::lease_time)) {
      const auto encoded = u32(remaining_seconds);
      if (!writer->append(
              static_cast<std::uint8_t>(
                  packet::dhcpv4::OptionCode::lease_time),
              encoded))
        return {.status = ServerProcessStatus::output_too_small};
    }
    if (pool) {
      const auto lease_start =
          selected->active_until -
          std::chrono::seconds{selected->lease_seconds};
      const auto append_relative_deadline =
          [&](packet::dhcpv4::OptionCode code,
              std::uint32_t offset_seconds) {
            if (!requested_option(requested, list_present, code) ||
                offset_seconds == 0U)
              return true;
            const auto deadline =
                lease_start + std::chrono::seconds{offset_seconds};
            if (deadline <= now)
              return true;
            const auto seconds = static_cast<std::uint32_t>(
                std::min<std::int64_t>(
                    std::numeric_limits<std::uint32_t>::max(),
                    std::chrono::duration_cast<std::chrono::seconds>(
                        deadline - now)
                        .count()));
            const auto encoded = u32(seconds);
            return writer->append(static_cast<std::uint8_t>(code), encoded);
          };
      if (!append_relative_deadline(
              packet::dhcpv4::OptionCode::renewal_time,
              pool->renewal_seconds) ||
          !append_relative_deadline(
              packet::dhcpv4::OptionCode::rebinding_time,
              pool->rebinding_seconds))
        return {.status = ServerProcessStatus::output_too_small};
    }

    if (pool && requested_option(requested, list_present,
                                 packet::dhcpv4::OptionCode::subnet_mask) &&
        !writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::subnet_mask),
            pool->subnet_mask))
      return {.status = ServerProcessStatus::output_too_small};
    if (pool && !zero(pool->router) &&
        requested_option(requested, list_present,
                         packet::dhcpv4::OptionCode::router) &&
        !writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::router),
            pool->router))
      return {.status = ServerProcessStatus::output_too_small};

    const auto elapsed_seconds = static_cast<std::uint32_t>(
        std::min<std::int64_t>(
            std::numeric_limits<std::uint32_t>::max(),
            std::max<std::int64_t>(
                0, std::chrono::duration_cast<std::chrono::seconds>(
                       now - selected->last_client_transaction)
                       .count())));
    const auto encoded_elapsed = u32(elapsed_seconds);
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::client_last_transaction_time),
            encoded_elapsed))
      return {.status = ServerProcessStatus::output_too_small};

    if (selected->relay_agent_information_octets != 0U &&
        requested_option(
            requested, list_present,
            packet::dhcpv4::OptionCode::relay_agent_information) &&
        !writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::relay_agent_information),
            std::span{selected->relay_agent_information}.first(
                selected->relay_agent_information_octets)))
      return {.status = ServerProcessStatus::output_too_small};

    // Associated IP is mandatory when the same client has interacted using
    // more than one address. Multiple occurrences are legal RFC 3396
    // fragments and prevent the one-octet option length from truncating a
    // binding set.
    std::array<std::uint8_t, 252U> associated{};
    std::size_t associated_octets{};
    std::size_t associated_count{};
    const auto flush_associated = [&]() {
      if (associated_octets == 0U)
        return true;
      const bool appended = writer->append(
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::associated_ip),
          std::span{associated}.first(associated_octets));
      associated_octets = 0U;
      return appended;
    };
    for (const auto &lease : leases_.leases()) {
      const auto &identity =
          address_query ? selected->client : selected_key;
      if (!equal_client_key(lease.client, identity))
        continue;
      ++associated_count;
      if (lease.address == selected->address)
        continue;
      if (associated_octets == associated.size() &&
          !flush_associated())
        return {.status = ServerProcessStatus::output_too_small};
      std::ranges::copy(
          lease.address,
          associated.begin() +
              static_cast<std::ptrdiff_t>(associated_octets));
      associated_octets += lease.address.size();
    }
    if (associated_count > 1U && !flush_associated())
      return {.status = ServerProcessStatus::output_too_small};
  }
  if (!writer->finish())
    return {.status = ServerProcessStatus::output_too_small};

  if (response_type == packet::dhcpv4::MessageType::lease_active)
    ++statistics_.tx_lease_active;
  else if (response_type ==
           packet::dhcpv4::MessageType::lease_unassigned)
    ++statistics_.tx_lease_unassigned;
  else
    ++statistics_.tx_lease_unknown;
  return {.status = ServerProcessStatus::response,
          .message_octets = writer->view().size()};
}

ServerProcessResult Server::process(
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output, std::uint64_t link_identity,
    Clock::time_point now) {
  const std::array<packet::Ipv4, 1U> identifiers{
      configuration_.server_identifier};
  return process(input, output, link_identity,
                 configuration_.server_identifier, identifiers, now);
}

ServerProcessResult Server::process(
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output, std::uint64_t link_identity,
    packet::Ipv4 response_server_identifier,
    std::span<const packet::Ipv4> accepted_identifiers,
    Clock::time_point now) {
  if (!configured_)
    return {.status = ServerProcessStatus::not_configured};
  if (zero(response_server_identifier))
    return {.status = ServerProcessStatus::not_configured};
  const auto request = packet::dhcpv4::parse(input);
  if (!request ||
      request->operation != packet::dhcpv4::Operation::boot_request)
    return {.status = ServerProcessStatus::malformed};
  const auto type = packet::dhcpv4::message_type(*request);
  if (!type)
    return {.status = ServerProcessStatus::malformed};
  if (*type == packet::dhcpv4::MessageType::lease_query) {
    ++statistics_.rx_lease_query;
    return lease_query_response(*request, output, now);
  }
  const auto client = client_key(*request);
  if (!client)
    return {.status = ServerProcessStatus::malformed};
  const auto hardware = hardware_identity(*request);
  const auto relay_information = single_raw_option(
      *request, packet::dhcpv4::OptionCode::relay_agent_information);
  if (!relay_information.valid)
    return {.status = ServerProcessStatus::malformed};

  AllocationScope scope{
      .server_instance = configuration_.server_instance,
      .routing_context = configuration_.routing_context,
      .link_identity = link_identity,
  };
  if (!zero(request->gateway_address)) {
    // A relayed packet reaches the server through the server-facing interface,
    // which is not the client allocation link. RFC 2131 uses giaddr for subnet
    // selection and RFC 3527 lets a relay provide a different Link Selection
    // address while retaining giaddr as the return address.
    const auto link_selection = relay_link_selection(*request);
    if (!link_selection.valid)
      return {.status = ServerProcessStatus::malformed};
    const auto selector =
        link_selection.address.value_or(request->gateway_address);
    const Pool *matched{};
    for (const auto &pool : leases_.pools()) {
      if (!pool.enabled ||
          pool.scope.server_instance != configuration_.server_instance ||
          pool.scope.routing_context != configuration_.routing_context ||
          (word(pool.first) & word(pool.subnet_mask)) !=
              (word(selector) & word(pool.subnet_mask)))
        continue;
      if (matched && matched->scope.link_identity != pool.scope.link_identity)
        return {.status = ServerProcessStatus::unknown_scope};
      matched = &pool;
    }
    if (!matched)
      return {.status = ServerProcessStatus::unknown_scope};
    scope.link_identity = matched->scope.link_identity;
  }
  const auto requested = ipv4_option(
      *request, packet::dhcpv4::OptionCode::requested_address);
  const auto requested_lease = u32_option(
      *request, packet::dhcpv4::OptionCode::lease_time);

  if (*type == packet::dhcpv4::MessageType::discover) {
    ++statistics_.rx_discover;
    const auto allocated = leases_.offer(scope, *client,
                                         request->transaction_id,
                                         requested, now, requested_lease,
                                         hardware,
                                         relay_information.value);
    if (allocated.status == AllocateStatus::unknown_scope ||
        allocated.status == AllocateStatus::ambiguous_scope)
      return {.status = ServerProcessStatus::unknown_scope};
    if (allocated.status == AllocateStatus::resource_exhausted)
      return {.status = ServerProcessStatus::resource_exhausted};
    if (allocated.status != AllocateStatus::offered &&
        allocated.status != AllocateStatus::reused)
      return {.status = ServerProcessStatus::discarded};
    auto result = response(*request, packet::dhcpv4::MessageType::offer,
                           allocated.address,
                           leases_.pool_for(scope, allocated.address),
                           *client, allocated.lease_seconds,
                           response_server_identifier, output);
    if (result.status == ServerProcessStatus::response)
      ++statistics_.tx_offer;
    return result;
  }

  if (*type == packet::dhcpv4::MessageType::request) {
    ++statistics_.rx_request;
    const auto selected_server = ipv4_option(
        *request, packet::dhcpv4::OptionCode::server_identifier);
    if (selected_server &&
        std::ranges::find(accepted_identifiers, *selected_server) ==
            accepted_identifiers.end())
      return {.status = ServerProcessStatus::discarded};
    const auto selected_address =
        !zero(request->client_address)
            ? std::optional{request->client_address}
            : requested;
    if (!selected_address)
      return {.status = ServerProcessStatus::malformed};
    const auto *pool = leases_.pool_for(scope, *selected_address);
    if (!pool || !leases_.commit(scope, *client, request->transaction_id,
                                 *selected_address, now, requested_lease,
                                 hardware, relay_information.value)) {
      if (!configuration_.authoritative)
        return {.status = ServerProcessStatus::discarded};
      auto result = response(
          *request, packet::dhcpv4::MessageType::negative_acknowledgement,
          {}, nullptr, *client, 0U, response_server_identifier, output);
      if (result.status == ServerProcessStatus::response)
        ++statistics_.tx_negative_acknowledgement;
      return result;
    }
    const auto *lease = leases_.lease_for(scope, *client);
    if (!lease)
      return {.status = ServerProcessStatus::resource_exhausted};
    auto result = response(
        *request, packet::dhcpv4::MessageType::acknowledgement,
        *selected_address, pool, *client, lease->lease_seconds,
        response_server_identifier, output);
    if (result.status == ServerProcessStatus::response)
      ++statistics_.tx_acknowledgement;
    return result;
  }

  if (*type == packet::dhcpv4::MessageType::release) {
    ++statistics_.rx_release;
    if (!zero(request->client_address))
      (void)leases_.release(scope, *client, request->client_address, now);
    return {.status = ServerProcessStatus::discarded};
  }

  if (*type == packet::dhcpv4::MessageType::decline) {
    ++statistics_.rx_decline;
    if (requested)
      (void)leases_.decline(scope, *client, *requested, now);
    return {.status = ServerProcessStatus::discarded};
  }

  if (*type == packet::dhcpv4::MessageType::inform) {
    ++statistics_.rx_inform;
    auto result = response(
        *request, packet::dhcpv4::MessageType::acknowledgement, {}, nullptr,
        *client, 0U, response_server_identifier, output);
    if (result.status == ServerProcessStatus::response)
      ++statistics_.tx_acknowledgement;
    return result;
  }
  return {.status = ServerProcessStatus::discarded};
}

ForceRenewResult Server::force_renew(
    packet::Ipv4 address, packet::Ipv4 server_identifier,
    std::span<std::uint8_t> output,
    Clock::time_point now) {
  if (!configured_)
    return {.status = ForceRenewStatus::not_configured};
  if (!configuration_.force_renews)
    return {.status = ForceRenewStatus::disabled};
  if (zero(server_identifier))
    return {.status = ForceRenewStatus::not_configured};
  const auto *lease = leases_.active_lease_at(address, now);
  if (!lease)
    return {.status = ForceRenewStatus::lease_not_found};
  const bool direct_client =
      lab::physical_port_from_interface_id(lease->scope.link_identity).has_value();
  if (direct_client &&
      (lease->hardware.type != 1U ||
       lease->hardware.length != packet::Mac{}.size()))
    return {.status = ForceRenewStatus::unsupported_hardware};

  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_reply,
      .hardware_type = lease->hardware.type,
      .hardware_length = lease->hardware.length,
      .transaction_id = 0U,
      .client_address = address,
      .client_hardware_address = lease->hardware.address};
  auto writer = packet::dhcpv4::begin(output, header);
  const std::array type{
      static_cast<std::uint8_t>(packet::dhcpv4::MessageType::force_renew)};
  if (!writer ||
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::message_type),
                      type) ||
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::server_identifier),
                      server_identifier) ||
      !writer->finish())
    return {.status = ForceRenewStatus::output_too_small};

  packet::Mac destination_mac{};
  std::copy_n(lease->hardware.address.begin(), destination_mac.size(),
              destination_mac.begin());
  return {.status = ForceRenewStatus::encoded,
          .destination = address,
          .destination_mac = destination_mac,
          .link_identity = lease->scope.link_identity,
          .message_octets = writer->view().size()};
}

ServerCheckpoint Server::checkpoint(Clock::time_point now) const {
  return {.configuration = configuration_,
          .leases = leases_.checkpoint(now),
          .statistics = statistics_,
          .configured = configured_};
}

bool Server::restore(const ServerCheckpoint &state,
                     Clock::time_point now) {
  if (!state.configured || state.configuration.server_instance == 0U ||
      zero(state.configuration.server_identifier) ||
      state.configuration.domain_name_servers.size() >
          packet::dhcpv4::maximum_ipv4_addresses_per_option)
    return false;
  LeaseRepository leases;
  if (!leases.restore(state.leases, now))
    return false;
  Server staged;
  try {
    staged.configuration_ = state.configuration;
    staged.leases_ = std::move(leases);
    staged.statistics_ = state.statistics;
  } catch (...) {
    return false;
  }
  staged.configured_ = true;
  *this = std::move(staged);
  return true;
}

} // namespace router::dhcpv4
