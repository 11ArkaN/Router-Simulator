// DHCPv6 relay wire transformations. No state survives a function call, which
// preserves RFC 9915's stateless relay return-path model through Interface-Id.

#include "router/dhcpv6_relay.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

namespace router::dhcpv6 {

RelayForwardResult encapsulate_relay_forward(
    std::span<const std::uint8_t> message, packet::Ipv6 received_source,
    packet::Ipv6 configured_link_address,
    std::span<const std::uint8_t> interface_id,
    std::span<std::uint8_t> output) noexcept {
  const auto received = packet::dhcpv6::parse(message);
  if (!received)
    return {.status = RelayStatus::malformed};
  if (received->type == static_cast<std::uint8_t>(
                            packet::dhcpv6::MessageType::relay_reply))
    return {.status = RelayStatus::wrong_direction};

  std::uint8_t hop_count{};
  auto link_address = configured_link_address;
  if (received->type == static_cast<std::uint8_t>(
                            packet::dhcpv6::MessageType::relay_forward)) {
    if (received->hop_count >= packet::dhcpv6::hop_count_limit)
      return {.status = RelayStatus::hop_count_exceeded};
    hop_count = static_cast<std::uint8_t>(received->hop_count + 1U);
    // A globally scoped source already identifies the downstream relay. RFC
    // 9915 section 19.1.2 therefore requires an all-zero link-address here.
    if (!ip::is_unspecified(received_source) &&
        !ip::is_link_local(received_source) &&
        !ip::is_multicast(received_source))
      link_address = {};
  }

  auto writer = packet::dhcpv6::begin_relay(
      output,
      static_cast<std::uint8_t>(
          packet::dhcpv6::MessageType::relay_forward),
      hop_count, link_address, received_source);
  if (!writer)
    return {.status = RelayStatus::output_too_small};
  if ((!interface_id.empty() &&
       !writer->append(static_cast<std::uint16_t>(
                           packet::dhcpv6::OptionCode::interface_id),
                       interface_id)) ||
      !writer->append(static_cast<std::uint16_t>(
                          packet::dhcpv6::OptionCode::relay_message),
                      message))
    return {.status = RelayStatus::output_too_small};
  return {.status = RelayStatus::forwarded,
          .message_octets = writer->size()};
}

std::optional<RelayReplyView>
decapsulate_relay_reply(std::span<const std::uint8_t> message) noexcept {
  const auto relay = packet::dhcpv6::parse(message);
  if (!relay || relay->type != static_cast<std::uint8_t>(
                                   packet::dhcpv6::MessageType::relay_reply))
    return std::nullopt;
  RelayReplyView result{.link_address = relay->link_address,
                        .peer_address = relay->peer_address};
  bool have_interface{};
  bool have_message{};
  packet::dhcpv6::OptionCursor cursor{relay->options};
  while (const auto option = cursor.next()) {
    if (option->code == static_cast<std::uint16_t>(
                            packet::dhcpv6::OptionCode::interface_id)) {
      if (have_interface)
        return std::nullopt;
      result.interface_id = option->data;
      have_interface = true;
      result.has_interface_id = true;
    } else if (option->code == static_cast<std::uint16_t>(
                                   packet::dhcpv6::OptionCode::relay_message)) {
      if (have_message || !packet::dhcpv6::parse(option->data))
        return std::nullopt;
      result.message = option->data;
      have_message = true;
    }
  }
  return cursor.valid() && have_message ? std::optional{result}
                                        : std::nullopt;
}

RelayForwardResult encapsulate_relay_reply(
    std::span<const std::uint8_t> relay_forward,
    std::span<const std::uint8_t> response,
    std::span<std::uint8_t> output) noexcept {
  const auto relay = packet::dhcpv6::parse(relay_forward);
  if (!relay)
    return {.status = RelayStatus::malformed};
  if (relay->type != static_cast<std::uint8_t>(
                         packet::dhcpv6::MessageType::relay_forward))
    return {.status = RelayStatus::wrong_direction};
  if (!packet::dhcpv6::parse(response))
    return {.status = RelayStatus::malformed};

  std::span<const std::uint8_t> interface_id;
  bool have_interface{};
  bool have_relay_message{};
  packet::dhcpv6::OptionCursor cursor{relay->options};
  while (const auto option = cursor.next()) {
    if (option->code == static_cast<std::uint16_t>(
                            packet::dhcpv6::OptionCode::interface_id)) {
      if (have_interface)
        return {.status = RelayStatus::malformed};
      interface_id = option->data;
      have_interface = true;
    } else if (option->code == static_cast<std::uint16_t>(
                                   packet::dhcpv6::OptionCode::relay_message)) {
      if (have_relay_message)
        return {.status = RelayStatus::malformed};
      have_relay_message = true;
    }
  }
  if (!cursor.valid() || !have_relay_message)
    return {.status = RelayStatus::malformed};

  auto writer = packet::dhcpv6::begin_relay(
      output,
      static_cast<std::uint8_t>(packet::dhcpv6::MessageType::relay_reply),
      relay->hop_count, relay->link_address, relay->peer_address);
  if (!writer ||
      (have_interface &&
       !writer->append(static_cast<std::uint16_t>(
                           packet::dhcpv6::OptionCode::interface_id),
                       interface_id)) ||
      !writer->append(static_cast<std::uint16_t>(
                          packet::dhcpv6::OptionCode::relay_message),
                      response))
    return {.status = RelayStatus::output_too_small};
  return {.status = RelayStatus::forwarded,
          .message_octets = writer->size()};
}

RelayConfigStatus
RelayAgent::replace_interface(RelayInterfaceConfig config) {
  // Zero is reserved for "no interface" in routing intents and scoped
  // addresses. Rejecting it here keeps a valid downstream decision
  // distinguishable from an unresolved return path.
  if (config.interface_id == 0U ||
      config.physical_port_ordinal >=
          device_catalog::maximum_ports_per_router)
    return RelayConfigStatus::invalid_interface;
  if (ip::is_unspecified(config.link_address) ||
      ip::is_multicast(config.link_address) ||
      ip::is_loopback(config.link_address))
    return RelayConfigStatus::invalid_link_address;
  if (config.has_source_address &&
      (ip::is_unspecified(config.source_address) ||
       ip::is_multicast(config.source_address) ||
       ip::is_loopback(config.source_address)))
    return RelayConfigStatus::invalid_link_address;
  if (!config.has_source_address &&
      !ip::is_unspecified(config.source_address))
    return RelayConfigStatus::invalid_link_address;
  if (config.relay_interface_id.size() >
      std::numeric_limits<std::uint16_t>::max())
    return RelayConfigStatus::interface_id_too_long;
  if (config.server_count > config.servers.size())
    return RelayConfigStatus::too_many_servers;

  for (std::size_t index = 0; index < config.server_count; ++index) {
    const auto &server = config.servers[index];
    // An explicit upstream cannot be unspecified or loopback. Link-local
    // destinations need a zone because the FIB cannot infer which link-local
    // namespace the administrator intended.
    if (ip::is_unspecified(server.address) || ip::is_loopback(server.address) ||
        (ip::is_link_local(server.address) &&
         server.scope_interface_id == 0U))
      return RelayConfigStatus::invalid_server;
    for (std::size_t previous = 0; previous < index; ++previous)
      if (config.servers[previous] == server)
        return RelayConfigStatus::duplicate_server;
  }

  for (const auto &existing : interfaces_) {
    if (existing.interface_id == config.interface_id)
      continue;
    // Interface-Id is opaque and matched byte-for-byte. Two interfaces with
    // the same non-empty value would make a valid Relay-reply impossible to
    // route deterministically, so the configuration transaction is rejected.
    if (!config.relay_interface_id.empty() &&
        existing.relay_interface_id == config.relay_interface_id)
      return RelayConfigStatus::duplicate_return_key;
  }

  const auto existing = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.interface_id == config.interface_id;
      });
  if (existing != interfaces_.end())
    *existing = std::move(config);
  else {
    try {
      interfaces_.push_back(std::move(config));
    } catch (const std::bad_alloc &) {
      // Existing configuration is untouched because vector growth either
      // succeeds or provides the strong exception guarantee.
      return RelayConfigStatus::resource_exhausted;
    }
  }
  return RelayConfigStatus::accepted;
}

bool RelayAgent::remove_interface(std::uint64_t interface_id) noexcept {
  const auto found = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.interface_id == interface_id;
      });
  if (found == interfaces_.end())
    return false;
  interfaces_.erase(found);
  return true;
}

void RelayAgent::clear() noexcept {
  // clear() releases cold-path configuration. DHCPv6 relays retain no
  // transaction return state, so there is no packet owner to drain first.
  interfaces_.clear();
}

bool RelayAgent::restore(
    const std::vector<RelayInterfaceConfig> &interfaces) {
  try {
    RelayAgent replacement;
    replacement.interfaces_.reserve(interfaces.size());
    for (const auto &configuration : interfaces)
      if (replacement.replace_interface(configuration) !=
          RelayConfigStatus::accepted)
        return false;
    interfaces_.swap(replacement.interfaces_);
    return true;
  } catch (const std::bad_alloc &) {
    // Restore validates into a private owner. Resource exhaustion never
    // partially replaces the live return-path table.
    return false;
  }
}

const RelayInterfaceConfig *
RelayAgent::find_ingress(std::uint64_t interface_id) const noexcept {
  const auto found = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.interface_id == interface_id;
      });
  return found == interfaces_.end() ? nullptr : &*found;
}

const RelayInterfaceConfig *RelayAgent::unique_on_physical_port(
    std::uint16_t physical_port_ordinal) const noexcept {
  const RelayInterfaceConfig *match{};
  for (const auto &candidate : interfaces_) {
    if (candidate.physical_port_ordinal != physical_port_ordinal)
      continue;
    if (match)
      return nullptr;
    match = &candidate;
  }
  return match;
}

RelayDecision
RelayAgent::decide(const ReceivedRelayDatagram &received,
                   std::span<std::uint8_t> output) const noexcept {
  if (received.destination_port != packet::dhcpv6::server_port)
    return {.status = RelayDecisionStatus::wrong_ports};

  const auto parsed = packet::dhcpv6::parse(received.payload);
  if (!parsed)
    return {.status = RelayDecisionStatus::malformed};

  const auto relay_reply_type = static_cast<std::uint8_t>(
      packet::dhcpv6::MessageType::relay_reply);
  const auto relay_forward_type = static_cast<std::uint8_t>(
      packet::dhcpv6::MessageType::relay_forward);
  if (parsed->type == relay_reply_type) {
    // Servers send Relay-reply from UDP 547 to UDP 547 and unicast it to the
    // preceding relay. Accepting a multicast reply would turn one server
    // response into multiple downstream transmissions.
    if (received.source_port != packet::dhcpv6::server_port)
      return {.status = RelayDecisionStatus::wrong_ports};
    if (ip::is_multicast(received.destination))
      return {.status = RelayDecisionStatus::wrong_destination};

    const auto reply = decapsulate_relay_reply(received.payload);
    if (!reply)
      return {.status = RelayDecisionStatus::malformed};

    const RelayInterfaceConfig *egress{};
    bool ambiguous{};
    for (const auto &candidate : interfaces_) {
      const bool interface_id_matches =
          candidate.relay_interface_id.size() == reply->interface_id.size() &&
          std::equal(candidate.relay_interface_id.begin(),
                     candidate.relay_interface_id.end(),
                     reply->interface_id.begin());
      const bool matches =
          reply->has_interface_id
              ? interface_id_matches
              : !ip::is_unspecified(reply->link_address) &&
                    candidate.link_address == reply->link_address;
      if (!matches)
        continue;
      if (egress) {
        ambiguous = true;
        break;
      }
      egress = &candidate;
    }
    if (ambiguous)
      return {.status = RelayDecisionStatus::return_path_ambiguous};
    if (!egress)
      return {.status = RelayDecisionStatus::return_path_not_found};
    if (reply->message.size() > output.size())
      return {.status = RelayDecisionStatus::output_too_small};

    // RFC 9915 requires exact payload preservation while removing precisely
    // one relay layer. memmove permits a caller to provide overlapping storage
    // without reserializing or interpreting the inner message.
    std::memmove(output.data(), reply->message.data(), reply->message.size());
    const auto inner = packet::dhcpv6::parse(reply->message);
    return {.status = RelayDecisionStatus::forward_downstream,
            .payload_octets = reply->message.size(),
            .egress_interface_id = egress->interface_id,
            .destination = reply->peer_address,
            .source_port = packet::dhcpv6::server_port,
            .destination_port =
                inner && inner->type == relay_reply_type
                    ? packet::dhcpv6::server_port
                    : packet::dhcpv6::client_port};
  }

  const auto *ingress = find_ingress(received.ingress_interface_id);
  if (!ingress)
    return {.status = RelayDecisionStatus::not_configured};
  const bool from_relay = parsed->type == relay_forward_type;
  const auto required_source_port = from_relay
                                        ? packet::dhcpv6::server_port
                                        : packet::dhcpv6::client_port;
  if (received.source_port != required_source_port)
    return {.status = RelayDecisionStatus::wrong_ports};
  // A directly attached client uses ff02::1:2 when it multicasts. Unicast
  // Renew and Release remain valid because the UDP/local-address owner has
  // already established that this router was the intended destination.
  if (!from_relay && ip::is_multicast(received.destination) &&
      received.destination !=
          packet::dhcpv6::all_relay_agents_and_servers)
    return {.status = RelayDecisionStatus::wrong_destination};

  const auto encoded = encapsulate_relay_forward(
      received.payload, received.source, ingress->link_address,
      ingress->relay_interface_id, output);
  switch (encoded.status) {
  case RelayStatus::malformed:
  case RelayStatus::wrong_direction:
    return {.status = RelayDecisionStatus::malformed};
  case RelayStatus::hop_count_exceeded:
    return {.status = RelayDecisionStatus::hop_count_exceeded};
  case RelayStatus::output_too_small:
    return {.status = RelayDecisionStatus::output_too_small};
  case RelayStatus::forwarded:
    break;
  }

  static constexpr std::array<RelayDestination, 1U> protocol_default{{
      {.address = packet::dhcpv6::all_servers, .scope_interface_id = 0U}}};
  std::span<const RelayDestination> upstream;
  if (ingress->server_count != 0U) {
    upstream = std::span<const RelayDestination>{ingress->servers}.first(
        ingress->server_count);
  } else if (ingress->upstream_policy ==
             RelayUpstreamPolicy::protocol_default) {
    upstream = protocol_default;
  } else {
    return {.status = RelayDecisionStatus::no_upstream_server};
  }

  return {.status = RelayDecisionStatus::forward_upstream,
          .payload_octets = encoded.message_octets,
          .source_address = ingress->source_address,
          .has_source_address = ingress->has_source_address,
          .source_port = packet::dhcpv6::server_port,
          .destination_port = packet::dhcpv6::server_port,
          .upstream_destinations = upstream};
}

} // namespace router::dhcpv6
