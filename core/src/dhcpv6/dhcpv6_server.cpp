// DHCPv6 server wire orchestration. Validation precedes all lease mutation so
// malformed or misaddressed messages cannot partially alter server state.
// Response options are streamed directly into caller-owned UDP storage.

#include "router/dhcpv6_server.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <utility>

namespace router::dhcpv6 {
namespace {

using packet::dhcpv6::MessageType;
using packet::dhcpv6::OptionCode;

enum class StatusCode : std::uint16_t {
  success = 0U,
  unspecified_failure = 1U,
  no_addresses_available = 2U,
  no_binding = 3U,
  not_on_link = 4U,
  no_prefixes_available = 6U,
  unknown_query_type = 7U,
  malformed_query = 8U,
  not_configured = 9U,
  not_allowed = 10U
};

struct RequestOptions {
  std::span<const std::uint8_t> client_identifier{};
  std::span<const std::uint8_t> server_identifier{};
  std::span<const std::uint8_t> option_request{};
  std::span<const std::uint8_t> leasequery_query{};
  bool rapid_commit{};
  bool has_identity_association{};
  bool leasequery_query_present{};
  bool valid{true};
};

constexpr std::uint16_t code(OptionCode value) noexcept {
  return static_cast<std::uint16_t>(value);
}

constexpr std::uint8_t type(MessageType value) noexcept {
  return static_cast<std::uint8_t>(value);
}

void write16(std::span<std::uint8_t> output, std::size_t offset,
             std::uint16_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 1U] = static_cast<std::uint8_t>(value);
}

bool same_identifier(std::span<const std::uint8_t> option,
                     const ServerConfiguration &configuration) noexcept {
  return option.size() == configuration.duid_octets &&
         std::equal(option.begin(), option.end(), configuration.duid.begin());
}

RequestOptions scan_options(std::span<const std::uint8_t> bytes) noexcept {
  RequestOptions result;
  packet::dhcpv6::OptionCursor cursor{bytes};
  while (const auto option = cursor.next()) {
    if (option->code == code(OptionCode::client_identifier)) {
      if (!result.client_identifier.empty() ||
          !packet::dhcpv6::valid_duid(option->data))
        result.valid = false;
      else
        result.client_identifier = option->data;
    } else if (option->code == code(OptionCode::server_identifier)) {
      if (!result.server_identifier.empty() ||
          !packet::dhcpv6::valid_duid(option->data))
        result.valid = false;
      else
        result.server_identifier = option->data;
    } else if (option->code == code(OptionCode::option_request)) {
      // Multiple OROs are not combined. RFC 9915 section 21.7 allows at most
      // one and every requested code is exactly two network-order octets.
      if (!result.option_request.empty() || option->data.size() % 2U != 0U)
        result.valid = false;
      else
        result.option_request = option->data;
    } else if (option->code == code(OptionCode::rapid_commit)) {
      if (result.rapid_commit || !option->data.empty())
        result.valid = false;
      result.rapid_commit = true;
    } else if (option->code == code(OptionCode::leasequery_query)) {
      // RFC 5007 requires exactly one query option. Empty is not used as the
      // duplicate sentinel because a zero-length occurrence is itself a
      // malformed query that still has to be distinguished from absence.
      if (result.leasequery_query_present)
        result.valid = false;
      else
        result.leasequery_query = option->data;
      result.leasequery_query_present = true;
    } else if (option->code == code(OptionCode::ia_na) ||
               option->code == code(OptionCode::ia_pd)) {
      result.has_identity_association = true;
    }
  }
  result.valid = result.valid && cursor.valid();
  return result;
}

bool has_requested_code(std::span<const std::uint8_t> oro,
                        OptionCode requested) noexcept {
  for (std::size_t offset = 0; offset < oro.size(); offset += 2U) {
    const auto value = static_cast<std::uint16_t>(oro[offset] << 8U) |
                       oro[offset + 1U];
    if (value == code(requested))
      return true;
  }
  return false;
}

bool append_nested_option(std::span<std::uint8_t> output,
                          std::size_t &position, OptionCode option_code,
                          std::span<const std::uint8_t> data) noexcept {
  if (data.size() > std::numeric_limits<std::uint16_t>::max() ||
      position > output.size() || output.size() - position < 4U + data.size())
    return false;
  write16(output, position, code(option_code));
  write16(output, position + 2U, static_cast<std::uint16_t>(data.size()));
  std::copy(data.begin(), data.end(), output.begin() + position + 4U);
  position += 4U + data.size();
  return true;
}

bool append_status(packet::dhcpv6::Writer &writer,
                   StatusCode status) noexcept {
  std::array<std::uint8_t, 2U> data{};
  const auto encoded = packet::dhcpv6::encode_status_code(
      data, static_cast<std::uint16_t>(status));
  return encoded && writer.append(code(OptionCode::status_code), data);
}

bool append_u32_option(packet::dhcpv6::Writer &writer,
                       OptionCode option_code,
                       std::uint32_t value) noexcept {
  const std::array<std::uint8_t, 4U> data{
      static_cast<std::uint8_t>(value >> 24U),
      static_cast<std::uint8_t>(value >> 16U),
      static_cast<std::uint8_t>(value >> 8U),
      static_cast<std::uint8_t>(value)};
  return writer.append(code(option_code), data);
}

ClientIdentity identity(std::span<const std::uint8_t> duid,
                        const crypto::Sha256Digest &link_identity,
                        std::uint32_t iaid, LeaseKind kind) noexcept {
  ClientIdentity result{.link_identity = link_identity,
                        .duid_octets = static_cast<std::uint16_t>(duid.size()),
                        .iaid = iaid,
                        .kind = kind};
  std::copy(duid.begin(), duid.end(), result.duid.begin());
  return result;
}

bool append_ia(packet::dhcpv6::Writer &writer, OptionCode ia_code,
               std::uint32_t iaid, const LeaseResult &lease) noexcept {
  // One repository binding currently maps to one lease within an IA. These
  // buffers hold only fixed RFC fields, not administrator or packet-scale
  // collections, and their sizes are derived from the largest IA suboption.
  std::array<std::uint8_t, 32U> resource_data{};
  std::array<std::uint8_t, 48U> nested{};
  std::array<std::uint8_t, 64U> association{};
  std::size_t nested_size{};

  const bool success = lease.status == LeaseStatus::assigned ||
                       lease.status == LeaseStatus::renewed;
  if (success) {
    std::optional<std::size_t> encoded;
    OptionCode resource_code;
    if (ia_code == OptionCode::ia_pd) {
      resource_code = OptionCode::ia_prefix;
      encoded = packet::dhcpv6::encode_ia_prefix(
          resource_data, lease.value, lease.prefix_length,
          lease.preferred_lifetime_seconds, lease.valid_lifetime_seconds);
    } else {
      resource_code = OptionCode::ia_address;
      encoded = packet::dhcpv6::encode_ia_address(
          resource_data, lease.value, lease.preferred_lifetime_seconds,
          lease.valid_lifetime_seconds);
    }
    if (!encoded ||
        !append_nested_option(nested, nested_size, resource_code,
                              std::span<const std::uint8_t>{resource_data}
                                  .first(*encoded)))
      return false;
  } else {
    const auto status = lease.status == LeaseStatus::no_prefixes_available
                            ? StatusCode::no_prefixes_available
                        : lease.status == LeaseStatus::no_binding
                            ? StatusCode::no_binding
                            : StatusCode::no_addresses_available;
    std::array<std::uint8_t, 2U> status_data{};
    const auto encoded = packet::dhcpv6::encode_status_code(
        status_data, static_cast<std::uint16_t>(status));
    if (!encoded ||
        !append_nested_option(nested, nested_size, OptionCode::status_code,
                              status_data))
      return false;
  }

  std::optional<std::size_t> encoded_association;
  if (ia_code == OptionCode::ia_ta)
    encoded_association = packet::dhcpv6::encode_ia_ta(
        association, iaid,
        std::span<const std::uint8_t>{nested}.first(nested_size));
  else
    encoded_association = packet::dhcpv6::encode_ia_na_or_pd(
        association, iaid, success ? lease.t1_seconds : 0U,
        success ? lease.t2_seconds : 0U,
        std::span<const std::uint8_t>{nested}.first(nested_size));
  return encoded_association &&
         writer.append(code(ia_code),
                       std::span<const std::uint8_t>{association}.first(
                           *encoded_association));
}

// Return the client-facing message nested under any legal Relay-forward or
// Relay-reply chain. The server uses this only after the ordinary bounded
// parser has accepted each layer, so statistics never introduce a second,
// looser wire decoder.
std::optional<std::uint8_t>
innermost_message_type(std::span<const std::uint8_t> bytes) noexcept {
  for (std::uint8_t depth{}; depth <= packet::dhcpv6::hop_count_limit;
       ++depth) {
    const auto message = packet::dhcpv6::parse(bytes);
    if (!message)
      return std::nullopt;
    if (!message->relay)
      return message->type;

    std::span<const std::uint8_t> inner;
    bool found{};
    packet::dhcpv6::OptionCursor cursor{message->options};
    while (const auto option = cursor.next()) {
      if (option->code != code(OptionCode::relay_message))
        continue;
      if (found)
        return std::nullopt;
      inner = option->data;
      found = true;
    }
    if (!cursor.valid() || !found)
      return std::nullopt;
    bytes = inner;
  }
  return std::nullopt;
}

void note_received(ServerStatistics &statistics,
                   std::uint8_t message_type) noexcept {
  switch (static_cast<MessageType>(message_type)) {
  case MessageType::solicit:
    ++statistics.rx_solicit;
    break;
  case MessageType::request:
    ++statistics.rx_request;
    break;
  case MessageType::confirm:
    ++statistics.rx_confirm;
    break;
  case MessageType::renew:
    ++statistics.rx_renew;
    break;
  case MessageType::rebind:
    ++statistics.rx_rebind;
    break;
  case MessageType::release:
    ++statistics.rx_release;
    break;
  case MessageType::decline:
    ++statistics.rx_decline;
    break;
  case MessageType::information_request:
    ++statistics.rx_information_request;
    break;
  case MessageType::leasequery:
    ++statistics.rx_leasequery;
    break;
  default:
    break;
  }
}

void note_transmitted(ServerStatistics &statistics,
                      std::uint8_t message_type) noexcept {
  switch (static_cast<MessageType>(message_type)) {
  case MessageType::advertise:
    ++statistics.tx_advertise;
    break;
  case MessageType::reply:
    ++statistics.tx_reply;
    break;
  case MessageType::reconfigure:
    ++statistics.tx_reconfigure;
    break;
  case MessageType::leasequery_reply:
    ++statistics.tx_leasequery_reply;
    break;
  default:
    break;
  }
}

} // namespace

Server::Server()
    : relay_scratch_a_(packet::dhcpv6::maximum_message_octets),
      relay_scratch_b_(packet::dhcpv6::maximum_message_octets),
      leasequery_scratch_(packet::dhcpv6::maximum_message_octets) {}

bool Server::configure(const ServerConfiguration &configuration,
                       std::span<const LeasePool> address_pools,
                       std::span<const LeasePool> prefix_pools,
                       std::chrono::seconds decline_hold_time) noexcept {
  if (!packet::dhcpv6::valid_duid(
          std::span<const std::uint8_t>{configuration.duid}.first(
              std::min<std::size_t>(configuration.duid_octets,
                                    configuration.duid.size()))) ||
      configuration.duid_octets > configuration.duid.size() ||
      (!address_pools.empty() &&
       configuration.address_pool_index >= address_pools.size()) ||
      (!prefix_pools.empty() &&
       configuration.prefix_pool_index >= prefix_pools.size()) ||
      configuration.information_refresh_time_seconds <
          packet::dhcpv6::information_refresh_minimum_seconds ||
      (configuration.solicit_maximum_retransmission_seconds &&
       (*configuration.solicit_maximum_retransmission_seconds <
            packet::dhcpv6::maximum_retransmission_minimum_seconds ||
        *configuration.solicit_maximum_retransmission_seconds >
            packet::dhcpv6::maximum_retransmission_limit_seconds)) ||
      (configuration.information_maximum_retransmission_seconds &&
       (*configuration.information_maximum_retransmission_seconds <
            packet::dhcpv6::maximum_retransmission_minimum_seconds ||
        *configuration.information_maximum_retransmission_seconds >
            packet::dhcpv6::maximum_retransmission_limit_seconds)))
    return false;

  // RFC 9915 requires one T1/T2 pair across every IA in a Reply. Rejecting a
  // conflicting administrator policy is safer than silently rewriting lease
  // timers or producing a non-conformant multi-IA response.
  std::optional<std::pair<std::uint32_t, std::uint32_t>> renewal;
  const auto consistent = [&](const LeasePool &pool) {
    const auto candidate = std::pair{pool.t1_seconds, pool.t2_seconds};
    if (!renewal)
      renewal = candidate;
    return *renewal == candidate;
  };
  if (!std::all_of(address_pools.begin(), address_pools.end(), consistent) ||
      !std::all_of(prefix_pools.begin(), prefix_pools.end(), consistent))
    return false;

  const auto unambiguous_links = [](std::span<const LeasePool> pools) {
    for (std::size_t left = 0; left < pools.size(); ++left) {
      if (!pools[left].link_scoped)
        continue;
      const bool nonzero = std::any_of(
          pools[left].link_identity.begin(), pools[left].link_identity.end(),
          [](std::uint8_t value) { return value != 0U; });
      if (!nonzero)
        return false;
      for (std::size_t right = left + 1U; right < pools.size(); ++right)
        if (pools[right].link_scoped &&
            pools[left].link_identity == pools[right].link_identity)
          return false;
    }
    return true;
  };
  // One address pool and one prefix pool may serve the same link, but two
  // pools of the same IA kind would make request handling order-dependent.
  if (!unambiguous_links(address_pools) ||
      !unambiguous_links(prefix_pools))
    return false;

  ServerConfiguration staged_configuration;
  std::vector<LeasePool> staged_address_pools;
  std::vector<LeasePool> staged_prefix_pools;
  // Configuration contains an administrator-sized DNS server list. Copy it
  // before changing live state and convert allocation failure into the
  // documented atomic false result instead of terminating a noexcept call.
  try {
    staged_configuration = configuration;
    staged_address_pools.assign(address_pools.begin(), address_pools.end());
    staged_prefix_pools.assign(prefix_pools.begin(), prefix_pools.end());
  } catch (...) {
    return false;
  }
  // LeaseRepository owns the complete generated lease arena. Staging it on a
  // WebAssembly pthread stack would make configuration depth determine
  // whether an otherwise valid server overflows the stack. Heap staging keeps
  // the replacement atomic and converts allocation failure into `false`.
  auto staged = std::unique_ptr<LeaseRepository>{};
  try {
    staged = std::make_unique<LeaseRepository>();
  } catch (...) {
    return false;
  }
  if (!staged->configure(address_pools, prefix_pools, decline_hold_time))
    return false;
  configuration_ = std::move(staged_configuration);
  address_pools_ = std::move(staged_address_pools);
  prefix_pools_ = std::move(staged_prefix_pools);
  decline_hold_time_ = decline_hold_time;
  leases_ = std::move(*staged);
  configured_ = true;
  return true;
}

ServerCheckpoint Server::checkpoint(Clock::time_point now) const {
  return {.configuration = configuration_,
          .address_pools = address_pools_,
          .prefix_pools = prefix_pools_,
          .leases = leases_.checkpoint(now),
          .failover_bindings = leases_.failover_checkpoint(),
          .statistics = statistics_,
          .decline_hold_seconds = decline_hold_time_.count(),
          .configured = configured_};
}

bool Server::validate_checkpoint(const ServerCheckpoint &state) noexcept {
  if (!state.configured || state.decline_hold_seconds < 0)
    return false;
  try {
    Server staged;
    return staged.configure(
               state.configuration, state.address_pools, state.prefix_pools,
               std::chrono::seconds{state.decline_hold_seconds}) &&
           staged.leases_.validate_checkpoint(state.leases) &&
           staged.leases_.validate_failover_checkpoint(
               state.failover_bindings);
  } catch (...) {
    return false;
  }
}

bool Server::restore(const ServerCheckpoint &state, Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  try {
    Server staged;
    if (!staged.configure(
            state.configuration, state.address_pools, state.prefix_pools,
            std::chrono::seconds{state.decline_hold_seconds}) ||
        !staged.leases_.restore(state.leases, now) ||
        !staged.leases_.restore_failover_checkpoint(
            state.failover_bindings))
      return false;
    staged.statistics_ = state.statistics;
    *this = std::move(staged);
    return true;
  } catch (...) {
    return false;
  }
}

ServerProcessResult Server::process(std::span<const std::uint8_t> input,
                                    std::span<std::uint8_t> output,
                                    Clock::time_point now,
                                    const crypto::Sha256Digest
                                        &direct_link_identity,
                                    packet::Ipv6 direct_client_address) noexcept {
  // Statistics are updated only at the public service boundary. Recursive
  // relay processing therefore cannot double-count the same nested message.
  const auto outer = packet::dhcpv6::parse(input);
  const auto inner_type = innermost_message_type(input);
  if (!outer || !inner_type) {
    ++statistics_.dropped_bad_packet;
    return process_impl(input, output, now, 0U, direct_link_identity,
                        direct_client_address);
  }
  if (outer->type == type(MessageType::relay_forward))
    ++statistics_.rx_relay_forward;
  note_received(statistics_, *inner_type);

  const auto result = process_impl(input, output, now, 0U,
                                   direct_link_identity,
                                   direct_client_address);
  if (result.status == ServerProcessStatus::malformed ||
      result.status == ServerProcessStatus::unsupported_relay)
    ++statistics_.dropped_bad_packet;
  else if (result.status == ServerProcessStatus::output_too_small)
    ++statistics_.dropped_resource_exhausted;

  if (result.status != ServerProcessStatus::response)
    return result;
  const auto response_bytes = output.first(result.message_octets);
  const auto response_outer = packet::dhcpv6::parse(response_bytes);
  const auto response_inner = innermost_message_type(response_bytes);
  if (response_outer &&
      response_outer->type == type(MessageType::relay_reply))
    ++statistics_.tx_relay_reply;
  if (response_inner)
    note_transmitted(statistics_, *response_inner);
  return result;
}

std::optional<std::size_t>
Server::pool_for(LeaseKind kind,
                 const crypto::Sha256Digest &link_identity) const noexcept {
  const auto &pools =
      kind == LeaseKind::prefix ? prefix_pools_ : address_pools_;
  const auto configured_index =
      kind == LeaseKind::prefix ? configuration_.prefix_pool_index
                                : configuration_.address_pool_index;

  // An explicitly scoped pool always wins. At most one matching scope is
  // admitted by configure(), so selection cannot depend on YAML or vector
  // order when a Base server owns several client-facing links.
  for (std::size_t index = 0; index < pools.size(); ++index)
    if (pools[index].link_scoped &&
        pools[index].link_identity == link_identity)
      return index;
  if (configured_index < pools.size() && !pools[configured_index].link_scoped)
    return configured_index;
  return std::nullopt;
}

ServerProcessResult Server::process_impl(
    std::span<const std::uint8_t> input, std::span<std::uint8_t> output,
    Clock::time_point now, std::uint8_t relay_depth,
    const crypto::Sha256Digest &link_identity,
    packet::Ipv6 client_address) noexcept {
  if (!configured_)
    return {.status = ServerProcessStatus::not_configured};
  // A larger caller buffer must not let DHCP bypass the ordinary IPv6 UDP
  // length field. IPv6 fragmentation is still available below this layer for
  // every message up to this real wire limit.
  output = output.first(
      std::min(output.size(), packet::dhcpv6::maximum_message_octets));
  const auto request = packet::dhcpv6::parse(input);
  if (!request)
    return {.status = ServerProcessStatus::malformed};
  if (request->relay) {
    if (request->type != type(MessageType::relay_forward) ||
        relay_depth >= packet::dhcpv6::hop_count_limit)
      return {.status = ServerProcessStatus::unsupported_relay};
    std::span<const std::uint8_t> inner;
    // The relay link-address and complete Interface-ID bytes identify the
    // allocation link. Hashing their length-delimited wire values prevents
    // ambiguous concatenation while keeping the lease key fixed-size.
    crypto::Sha256 relay_link_hash;
    relay_link_hash.update(request->link_address);
    bool have_inner{};
    packet::dhcpv6::OptionCursor relay_options{request->options};
    while (const auto option = relay_options.next()) {
      if (option->code == code(OptionCode::interface_id)) {
        const std::array<std::uint8_t, 2U> length{
            static_cast<std::uint8_t>(option->data.size() >> 8U),
            static_cast<std::uint8_t>(option->data.size())};
        relay_link_hash.update(length);
        relay_link_hash.update(option->data);
      }
      if (option->code != code(OptionCode::relay_message))
        continue;
      if (have_inner)
        return {.status = ServerProcessStatus::malformed};
      inner = option->data;
      have_inner = true;
    }
    if (!relay_options.valid() || !have_inner)
      return {.status = ServerProcessStatus::malformed};
    const auto relay_link_identity = relay_link_hash.finish();
    const auto inner_result =
        process_impl(inner, relay_scratch_a_, now,
                     static_cast<std::uint8_t>(relay_depth + 1U),
                     relay_link_identity, request->peer_address);
    if (inner_result.status != ServerProcessStatus::response)
      return inner_result;
    const auto wrapped = encapsulate_relay_reply(
        input,
        std::span<const std::uint8_t>{relay_scratch_a_}.first(
            inner_result.message_octets),
        relay_scratch_b_);
    if (wrapped.status != RelayStatus::forwarded)
      return {.status = wrapped.status == RelayStatus::output_too_small
                            ? ServerProcessStatus::output_too_small
                            : ServerProcessStatus::malformed};
    if (output.size() < wrapped.message_octets)
      return {.status = ServerProcessStatus::output_too_small};
    std::copy_n(relay_scratch_b_.begin(), wrapped.message_octets,
                output.begin());
    return {.status = ServerProcessStatus::response,
            .message_octets = wrapped.message_octets};
  }
  const auto options = scan_options(request->options);
  if (!options.valid)
    return {.status = ServerProcessStatus::malformed};

  const auto message_type = request->type;
  if (message_type == type(MessageType::leasequery)) {
    // RFC 5007 validates the outer requestor identity before interpreting the
    // nested query. Nokia's documented server surface enables only lookup by
    // DUID, but unsupported query types still receive a standards-compliant
    // reply rather than being mistaken for malformed ordinary DHCPv6.
    if (options.client_identifier.empty() ||
        !options.leasequery_query_present ||
        (!options.server_identifier.empty() &&
         !same_identifier(options.server_identifier, configuration_)))
      return {.status = ServerProcessStatus::discarded};

    auto writer = packet::dhcpv6::begin_client_server(
        output, type(MessageType::leasequery_reply),
        request->transaction_id);
    if (!writer)
      return {.status = ServerProcessStatus::output_too_small};
    const auto server_duid =
        std::span<const std::uint8_t>{configuration_.duid}.first(
            configuration_.duid_octets);
    if (!writer->append(code(OptionCode::server_identifier), server_duid) ||
        !writer->append(code(OptionCode::client_identifier),
                        options.client_identifier))
      return {.status = ServerProcessStatus::output_too_small};

    if (!configuration_.lease_query) {
      // SR OS rejects a syntactically valid query when the administrator has
      // not enabled lease-query. Count that policy decision separately from
      // malformed packets and leave the binding repository untouched.
      ++statistics_.dropped_not_allowed;
      if (!append_status(*writer, StatusCode::not_allowed))
        return {.status = ServerProcessStatus::output_too_small};
      return {.status = ServerProcessStatus::response,
              .message_octets = writer->size()};
    }

    const auto query = options.leasequery_query;
    if (query.empty() || query[0] != 2U) {
      // QUERY_BY_ADDRESS is deliberately not accepted because SR OS 26.7
      // documents Client ID as the only supported identification method.
      if (!append_status(*writer, query.size() < 17U
                                      ? StatusCode::malformed_query
                                      : StatusCode::unknown_query_type))
        return {.status = ServerProcessStatus::output_too_small};
      return {.status = ServerProcessStatus::response,
              .message_octets = writer->size()};
    }
    if (query.size() < 17U) {
      if (!append_status(*writer, StatusCode::malformed_query))
        return {.status = ServerProcessStatus::output_too_small};
      return {.status = ServerProcessStatus::response,
              .message_octets = writer->size()};
    }

    std::span<const std::uint8_t> target_duid;
    bool target_seen{};
    bool nested_valid{true};
    packet::dhcpv6::OptionCursor query_options{query.subspan(17U)};
    while (const auto option = query_options.next()) {
      if (option->code != code(OptionCode::client_identifier))
        continue;
      if (target_seen || !packet::dhcpv6::valid_duid(option->data))
        nested_valid = false;
      else
        target_duid = option->data;
      target_seen = true;
    }
    nested_valid = nested_valid && query_options.valid() && target_seen;
    if (!nested_valid) {
      if (!append_status(*writer, StatusCode::malformed_query))
        return {.status = ServerProcessStatus::output_too_small};
      return {.status = ServerProcessStatus::response,
              .message_octets = writer->size()};
    }

    // Nokia returns all active bindings for the DUID and does not implement
    // RFC 5007 Client Link or Relay Data. The raw link-address is therefore
    // intentionally not used as a filter. Each resource remains a distinct
    // wire option inside one CLIENT_DATA option.
    const auto state = leases_.checkpoint(now);
    std::size_t client_data_size{};
    if (!append_nested_option(leasequery_scratch_, client_data_size,
                              OptionCode::client_identifier, target_duid))
      return {.status = ServerProcessStatus::output_too_small};
    bool found{};
    std::uint32_t last_transaction_seconds =
        std::numeric_limits<std::uint32_t>::max();
    const auto lifetime_seconds = [](std::int64_t nanoseconds) {
      if (nanoseconds <= 0)
        return std::uint32_t{};
      const auto seconds = nanoseconds / 1'000'000'000LL;
      return seconds > std::numeric_limits<std::uint32_t>::max()
                 ? std::numeric_limits<std::uint32_t>::max()
                 : static_cast<std::uint32_t>(seconds);
    };
    for (const auto &lease : state) {
      const auto lease_duid =
          std::span<const std::uint8_t>{lease.client.duid}.first(
              lease.client.duid_octets);
      if (lease.declined || lease_duid.size() != target_duid.size() ||
          !std::equal(lease_duid.begin(), lease_duid.end(),
                      target_duid.begin()))
        continue;
      found = true;
      std::array<std::uint8_t, 32U> resource{};
      std::optional<std::size_t> encoded;
      auto resource_code = OptionCode::ia_address;
      if (lease.client.kind == LeaseKind::prefix) {
        resource_code = OptionCode::ia_prefix;
        encoded = packet::dhcpv6::encode_ia_prefix(
            resource, lease.value, lease.prefix_length,
            lifetime_seconds(lease.preferred_remaining_nanoseconds),
            lifetime_seconds(lease.valid_remaining_nanoseconds));
      } else {
        encoded = packet::dhcpv6::encode_ia_address(
            resource, lease.value,
            lifetime_seconds(lease.preferred_remaining_nanoseconds),
            lifetime_seconds(lease.valid_remaining_nanoseconds));
      }
      if (!encoded ||
          !append_nested_option(
              leasequery_scratch_, client_data_size, resource_code,
              std::span<const std::uint8_t>{resource}.first(*encoded)))
        return {.status = ServerProcessStatus::output_too_small};
      last_transaction_seconds =
          std::min(last_transaction_seconds,
                   lifetime_seconds(
                       lease.last_client_transaction_ago_nanoseconds));
    }
    if (found) {
      if (!append_nested_option(
              leasequery_scratch_, client_data_size,
              OptionCode::client_last_transaction_time,
              std::array<std::uint8_t, 4U>{
                  static_cast<std::uint8_t>(last_transaction_seconds >> 24U),
                  static_cast<std::uint8_t>(last_transaction_seconds >> 16U),
                  static_cast<std::uint8_t>(last_transaction_seconds >> 8U),
                  static_cast<std::uint8_t>(last_transaction_seconds)}) ||
          !writer->append(
              code(OptionCode::client_data),
              std::span<const std::uint8_t>{leasequery_scratch_}.first(
                  client_data_size)))
        return {.status = ServerProcessStatus::output_too_small};
    }
    return {.status = ServerProcessStatus::response,
            .message_octets = writer->size()};
  }

  const bool solicit = message_type == type(MessageType::solicit);
  const bool request_message = message_type == type(MessageType::request);
  const bool confirm = message_type == type(MessageType::confirm);
  const bool renew = message_type == type(MessageType::renew);
  const bool rebind = message_type == type(MessageType::rebind);
  const bool release = message_type == type(MessageType::release);
  const bool decline = message_type == type(MessageType::decline);
  const bool information =
      message_type == type(MessageType::information_request);
  if (!(solicit || request_message || confirm || renew || rebind || release ||
        decline || information)) {
    ++statistics_.dropped_not_allowed;
    return {.status = ServerProcessStatus::discarded};
  }

  const bool client_required = !information;
  const bool server_required = request_message || renew || release || decline;
  const bool server_forbidden = solicit || confirm || rebind;
  if ((client_required && options.client_identifier.empty()) ||
      (server_required && options.server_identifier.empty()) ||
      (server_forbidden && !options.server_identifier.empty()) ||
      (!options.server_identifier.empty() &&
       !same_identifier(options.server_identifier, configuration_)) ||
      (information && options.has_identity_association))
    return {.status = ServerProcessStatus::discarded};

  const bool rapid = solicit && options.rapid_commit &&
                     configuration_.rapid_commit;
  const auto response_type = solicit && !rapid ? MessageType::advertise
                                                : MessageType::reply;
  auto writer = packet::dhcpv6::begin_client_server(
      output, type(response_type), request->transaction_id);
  if (!writer)
    return {.status = ServerProcessStatus::output_too_small};
  const auto server_duid =
      std::span<const std::uint8_t>{configuration_.duid}.first(
          configuration_.duid_octets);
  if (!writer->append(code(OptionCode::server_identifier), server_duid) ||
      (!options.client_identifier.empty() &&
       !writer->append(code(OptionCode::client_identifier),
                       options.client_identifier)))
    return {.status = ServerProcessStatus::output_too_small};
  // RFC 9915 section 16 deliberately removes the Server Unicast mechanism.
  // Clients send multicast, while upgraded servers still accept a valid
  // unicast message from an older client. The destination therefore cannot
  // alter DHCP message semantics and is not part of this owner's API.
  if (response_type == MessageType::advertise) {
    const std::array<std::uint8_t, 1U> preference{configuration_.preference};
    if (!writer->append(code(OptionCode::preference), preference))
      return {.status = ServerProcessStatus::output_too_small};
  }
  if (rapid && !writer->append(code(OptionCode::rapid_commit), {}))
    return {.status = ServerProcessStatus::output_too_small};

  bool saw_ia{};
  bool confirm_saw_address{};
  bool confirm_on_link{true};
  packet::dhcpv6::OptionCursor cursor{request->options};
  while (const auto option = cursor.next()) {
    const bool na = option->code == code(OptionCode::ia_na);
    const bool pd = option->code == code(OptionCode::ia_pd);
    // RFC 9915 section 21.5 obsoletes IA_TA and tells servers to ignore it.
    // Keeping the numeric option in the packet codec remains useful for
    // capture inspection, but it must never reach allocation policy.
    if (!(na || pd))
      continue;
    saw_ia = true;
    const auto association = packet::dhcpv6::parse_ia_na_or_pd(option->data);
    if (!association)
      return {.status = ServerProcessStatus::malformed};
    const auto iaid = association->iaid;
    const auto kind =
        pd ? LeaseKind::prefix : LeaseKind::non_temporary;
    const auto client =
        identity(options.client_identifier, link_identity, iaid, kind);
    const auto pool_index = pool_for(kind, link_identity);
    if (confirm) {
      if (pd)
        return {.status = ServerProcessStatus::discarded};
      packet::dhcpv6::OptionCursor confirm_options{association->options};
      while (const auto supplied = confirm_options.next()) {
        if (supplied->code != code(OptionCode::ia_address))
          continue;
        const auto address = packet::dhcpv6::parse_ia_address(supplied->data);
        if (!address)
          return {.status = ServerProcessStatus::malformed};
        confirm_saw_address = true;
        confirm_on_link = confirm_on_link &&
                          leases_.appropriate_address(address->address,
                                                      link_identity);
      }
      if (!confirm_options.valid())
        return {.status = ServerProcessStatus::malformed};
      continue;
    }
    LeaseResult lease;
    bool committed{};
    if (solicit && !rapid)
      lease = pool_index ? leases_.preview(client, *pool_index, now)
                         : LeaseResult{.status =
                                           pd ? LeaseStatus::no_prefixes_available
                                              : LeaseStatus::no_addresses_available};
    else if (request_message || rapid) {
      lease = pool_index ? leases_.assign(client, *pool_index, now)
                         : LeaseResult{.status =
                                           pd ? LeaseStatus::no_prefixes_available
                                              : LeaseStatus::no_addresses_available};
      committed = lease.status == LeaseStatus::assigned ||
                  lease.status == LeaseStatus::renewed;
    } else if (renew || rebind) {
      lease = leases_.renew(client, now);
      committed = lease.status == LeaseStatus::renewed;
    } else if (release || decline) {
      const auto status = release ? leases_.release(client)
                                  : leases_.decline(client, now);
      if (status == LeaseStatus::released || status == LeaseStatus::declined) {
        continue;
      }
      lease.status = LeaseStatus::no_binding;
    } else
      return {.status = ServerProcessStatus::discarded};
    // The server learns the endpoint from the received IPv6 packet or from
    // the enclosing Relay-forward peer-address. Recording it only after a
    // successful binding mutation prevents an Advertise preview from
    // manufacturing persistent operational state.
    if (committed && !ip::is_unspecified(client_address) &&
        !leases_.note_client_address(client, client_address))
      return {.status = ServerProcessStatus::malformed};
    const auto ia_code = pd ? OptionCode::ia_pd : OptionCode::ia_na;
    if (!append_ia(*writer, ia_code, iaid, lease))
      return {.status = ServerProcessStatus::output_too_small};
  }
  if (!cursor.valid())
    return {.status = ServerProcessStatus::malformed};

  if (confirm) {
    // If no address or no explicit link policy is available, section 18.3.3
    // requires silence. A known link returns one top-level status and no IA.
    if (!confirm_saw_address || !leases_.has_address_policy())
      return {.status = ServerProcessStatus::discarded};
    if (!append_status(*writer, confirm_on_link ? StatusCode::success
                                               : StatusCode::not_on_link))
      return {.status = ServerProcessStatus::output_too_small};
  }

  if ((release || decline) &&
      !append_status(*writer, StatusCode::success))
    return {.status = ServerProcessStatus::output_too_small};
  if (has_requested_code(options.option_request,
                         OptionCode::dns_recursive_name_server) &&
      !configuration_.dns_recursive_servers.empty()) {
    const auto bytes = std::as_bytes(
        std::span<const packet::Ipv6>{configuration_.dns_recursive_servers});
    if (!writer->append(code(OptionCode::dns_recursive_name_server),
                        {reinterpret_cast<const std::uint8_t *>(bytes.data()),
                         bytes.size()}))
      return {.status = ServerProcessStatus::output_too_small};
  }
  if (information &&
      has_requested_code(options.option_request,
                         OptionCode::information_refresh_time)) {
    std::array<std::uint8_t, 4U> refresh{
        static_cast<std::uint8_t>(
            configuration_.information_refresh_time_seconds >> 24U),
        static_cast<std::uint8_t>(
            configuration_.information_refresh_time_seconds >> 16U),
        static_cast<std::uint8_t>(
            configuration_.information_refresh_time_seconds >> 8U),
        static_cast<std::uint8_t>(
            configuration_.information_refresh_time_seconds)};
    if (!writer->append(code(OptionCode::information_refresh_time), refresh))
      return {.status = ServerProcessStatus::output_too_small};
  }
  if (configuration_.solicit_maximum_retransmission_seconds &&
      has_requested_code(
          options.option_request,
          OptionCode::solicit_maximum_retransmission_time) &&
      !append_u32_option(
          *writer, OptionCode::solicit_maximum_retransmission_time,
          *configuration_.solicit_maximum_retransmission_seconds))
    return {.status = ServerProcessStatus::output_too_small};
  if (configuration_.information_maximum_retransmission_seconds &&
      has_requested_code(
          options.option_request,
          OptionCode::information_maximum_retransmission_time) &&
      !append_u32_option(
          *writer, OptionCode::information_maximum_retransmission_time,
          *configuration_.information_maximum_retransmission_seconds))
    return {.status = ServerProcessStatus::output_too_small};

  // A stateful exchange without IAs is still a valid way to request other
  // options. The server returns identifiers and configured ORO data rather
  // than fabricating a lease. Solicit without IA remains an Advertise.
  static_cast<void>(saw_ia);
  return {.status = ServerProcessStatus::response,
          .message_octets = writer->size()};
}

} // namespace router::dhcpv6
