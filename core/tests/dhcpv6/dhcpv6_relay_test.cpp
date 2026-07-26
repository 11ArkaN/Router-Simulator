// Relay tests verify nested hop counts, exact payload preservation,
// Interface-Id return routing and HOP_COUNT_LIMIT discard behavior.

#include "router/dhcpv6_relay.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void dhcpv6_relay_tests() {
  using namespace router;
  using namespace router::dhcpv6;
  using namespace router::packet::dhcpv6;

  const auto client = ip::parse_ipv6("fe80::100");
  const auto link = ip::parse_ipv6("2001:db8:1::1");
  const auto relay_source = ip::parse_ipv6("2001:db8:2::1");
  if (!client || !link || !relay_source)
    throw std::runtime_error("DHCPv6 relay fixture address is invalid");
  std::array<std::uint8_t, 64U> solicit_storage{};
  auto solicit = begin_client_server(
      solicit_storage, static_cast<std::uint8_t>(MessageType::solicit),
      0x123456U);
  constexpr std::array<std::uint8_t, 5U> duid{0U, 3U, 0U, 1U, 7U};
  if (!solicit ||
      !solicit->append(static_cast<std::uint16_t>(
                           OptionCode::client_identifier),
                       duid))
    throw std::runtime_error("DHCPv6 relay client fixture failed");

  std::array<std::uint8_t, 512U> first_storage{};
  constexpr std::array<std::uint8_t, 4U> interface_id{'s', 'a', 'p', '1'};
  const auto first = encapsulate_relay_forward(
      solicit->view(), *client, *link, interface_id, first_storage);
  const auto first_message =
      first.status == RelayStatus::forwarded
          ? parse(std::span<const std::uint8_t>{first_storage}.first(
                first.message_octets))
          : std::nullopt;
  if (!first_message || first_message->hop_count != 0U ||
      first_message->link_address != *link ||
      first_message->peer_address != *client)
    throw std::runtime_error("DHCPv6 first relay encapsulation was invalid");

  std::array<std::uint8_t, 1024U> second_storage{};
  const auto second = encapsulate_relay_forward(
      std::span<const std::uint8_t>{first_storage}.first(first.message_octets),
      *relay_source, *link, {}, second_storage);
  const auto second_message =
      second.status == RelayStatus::forwarded
          ? parse(std::span<const std::uint8_t>{second_storage}.first(
                second.message_octets))
          : std::nullopt;
  if (!second_message || second_message->hop_count != 1U ||
      !ip::is_unspecified(second_message->link_address) ||
      second_message->peer_address != *relay_source)
    throw std::runtime_error("DHCPv6 nested relay hop handling was invalid");

  // A server returns the inner response under the exact Interface-Id copied
  // from Relay-forward. Decapsulation must expose the original bytes without
  // changing their transaction ID or options.
  std::array<std::uint8_t, 256U> reply_storage{};
  auto reply = begin_relay(
      reply_storage, static_cast<std::uint8_t>(MessageType::relay_reply), 0U,
      *link, *client);
  if (!reply ||
      !reply->append(static_cast<std::uint16_t>(OptionCode::interface_id),
                     interface_id) ||
      !reply->append(static_cast<std::uint16_t>(OptionCode::relay_message),
                     solicit->view()))
    throw std::runtime_error("DHCPv6 Relay-reply fixture failed");
  const auto unwrapped = decapsulate_relay_reply(reply->view());
  if (!unwrapped || unwrapped->peer_address != *client ||
      !std::equal(unwrapped->interface_id.begin(),
                  unwrapped->interface_id.end(), interface_id.begin()) ||
      !std::equal(unwrapped->message.begin(), unwrapped->message.end(),
                  solicit->view().begin()))
    throw std::runtime_error("DHCPv6 Relay-reply changed its inner message");

  std::array<std::uint8_t, 256U> generated_reply_storage{};
  const auto generated_reply = encapsulate_relay_reply(
      std::span<const std::uint8_t>{first_storage}.first(first.message_octets),
      solicit->view(), generated_reply_storage);
  const auto generated_unwrapped =
      generated_reply.status == RelayStatus::forwarded
          ? decapsulate_relay_reply(
                std::span<const std::uint8_t>{generated_reply_storage}.first(
                    generated_reply.message_octets))
          : std::nullopt;
  if (!generated_unwrapped ||
      generated_unwrapped->link_address != *link ||
      generated_unwrapped->peer_address != *client ||
      !std::equal(generated_unwrapped->interface_id.begin(),
                  generated_unwrapped->interface_id.end(),
                  interface_id.begin()) ||
      !std::equal(generated_unwrapped->message.begin(),
                  generated_unwrapped->message.end(), solicit->view().begin()))
    throw std::runtime_error(
        "DHCPv6 server Relay-reply did not reverse Relay-forward");

  std::array<std::uint8_t, 128U> limited_storage{};
  auto limited = begin_relay(
      limited_storage, static_cast<std::uint8_t>(MessageType::relay_forward),
      hop_count_limit, *link, *client);
  if (!limited ||
      encapsulate_relay_forward(limited->view(), *relay_source, *link, {},
                                second_storage)
              .status != RelayStatus::hop_count_exceeded ||
      decapsulate_relay_reply(limited->view()))
    throw std::runtime_error("DHCPv6 relay admitted hop overflow or direction");

  // The decision owner converts wire input into transport intent but never
  // sends it. With generic RFC policy, an empty destination list resolves to
  // ff05::1:3 and only that multicast transmission receives Hop Limit 8.
  RelayAgent agent;
  RelayInterfaceConfig generic{
      .interface_id = 41U,
      .link_address = *link,
      .relay_interface_id = {'s', 'a', 'p', '1'},
      .server_count = 0U,
      .upstream_policy = RelayUpstreamPolicy::protocol_default};
  if (agent.replace_interface(generic) != RelayConfigStatus::accepted)
    throw std::runtime_error("DHCPv6 generic relay configuration failed");
  std::array<std::uint8_t, 1024U> decision_storage{};
  const auto generic_decision = agent.decide(
      {.ingress_interface_id = 41U,
       .source = *client,
       .destination = all_relay_agents_and_servers,
       .source_port = client_port,
       .destination_port = server_port,
       .payload = solicit->view()},
      decision_storage);
  if (generic_decision.status != RelayDecisionStatus::forward_upstream ||
      generic_decision.source_port != server_port ||
      generic_decision.destination_port != server_port ||
      generic_decision.upstream_destinations.size() != 1U ||
      generic_decision.upstream_destinations.front().address != all_servers ||
      relay_hop_limit_override(
          generic_decision.upstream_destinations.front().address) !=
          relay_multicast_hop_limit)
    throw std::runtime_error(
        "DHCPv6 relay did not apply the RFC upstream multicast default");

  // SR OS requires an explicit service-interface server list. The absence of
  // a server is an operationally inactive relay, not permission to leak the
  // generic RFC multicast default into the vendor profile.
  RelayInterfaceConfig sros = generic;
  sros.interface_id = 42U;
  sros.relay_interface_id = {'s', 'a', 'p', '2'};
  sros.upstream_policy = RelayUpstreamPolicy::explicit_servers_required;
  if (agent.replace_interface(sros) != RelayConfigStatus::accepted ||
      agent
              .decide({.ingress_interface_id = 42U,
                       .source = *client,
                       .destination = all_relay_agents_and_servers,
                       .source_port = client_port,
                       .destination_port = server_port,
                       .payload = solicit->view()},
                      decision_storage)
              .status != RelayDecisionStatus::no_upstream_server)
    throw std::runtime_error(
        "DHCPv6 SR OS relay forwarded without a configured server");

  const auto unicast_server = ip::parse_ipv6("2001:db8:ffff::53");
  if (!unicast_server)
    throw std::runtime_error("DHCPv6 upstream fixture address is invalid");
  sros.servers[0] = {.address = *unicast_server};
  sros.server_count = 1U;
  if (agent.replace_interface(sros) != RelayConfigStatus::accepted)
    throw std::runtime_error("DHCPv6 explicit relay server was rejected");
  const auto explicit_decision = agent.decide(
      {.ingress_interface_id = 42U,
       .source = *client,
       .destination = all_relay_agents_and_servers,
       .source_port = client_port,
       .destination_port = server_port,
       .payload = solicit->view()},
      decision_storage);
  if (explicit_decision.status != RelayDecisionStatus::forward_upstream ||
      explicit_decision.upstream_destinations.size() != 1U ||
      explicit_decision.upstream_destinations.front().address !=
          *unicast_server ||
      relay_hop_limit_override(*unicast_server))
    throw std::runtime_error(
        "DHCPv6 explicit unicast server acquired multicast behavior");

  // Interface-Id is the primary stateless return key. The decision removes
  // exactly one relay layer, targets peer-address and chooses client UDP 546
  // for a non-relay inner message.
  const auto downstream = agent.decide(
      {.ingress_interface_id = 99U,
       .source = *unicast_server,
       .destination = *relay_source,
       .source_port = server_port,
       .destination_port = server_port,
       .payload = reply->view()},
      decision_storage);
  if (downstream.status != RelayDecisionStatus::forward_downstream ||
      downstream.egress_interface_id != 41U ||
      downstream.destination != *client ||
      downstream.source_port != server_port ||
      downstream.destination_port != client_port ||
      downstream.payload_octets != solicit->view().size() ||
      !std::equal(decision_storage.begin(),
                  decision_storage.begin() +
                      static_cast<std::ptrdiff_t>(downstream.payload_octets),
                  solicit->view().begin()))
    throw std::runtime_error(
        "DHCPv6 relay did not preserve the Interface-Id return path");

  constexpr std::array<std::uint8_t, 4U> unknown_interface_id{
      'n', 'o', 'p', 'e'};
  std::array<std::uint8_t, 256U> unknown_reply_storage{};
  auto unknown_reply = begin_relay(
      unknown_reply_storage,
      static_cast<std::uint8_t>(MessageType::relay_reply), 0U, *link,
      *client);
  if (!unknown_reply ||
      !unknown_reply->append(static_cast<std::uint16_t>(
                                 OptionCode::interface_id),
                             unknown_interface_id) ||
      !unknown_reply->append(
          static_cast<std::uint16_t>(OptionCode::relay_message),
          solicit->view()) ||
      agent
              .decide({.source = *unicast_server,
                       .destination = *relay_source,
                       .source_port = server_port,
                       .destination_port = server_port,
                       .payload = unknown_reply->view()},
                      decision_storage)
              .status != RelayDecisionStatus::return_path_not_found)
    throw std::runtime_error(
        "DHCPv6 relay guessed an unknown Interface-Id return path");

  RelayInterfaceConfig invalid = generic;
  invalid.interface_id = 43U;
  invalid.server_count = invalid.servers.size() + 1U;
  if (agent.replace_interface(invalid) !=
      RelayConfigStatus::too_many_servers)
    throw std::runtime_error(
        "DHCPv6 relay ignored the sourced SR OS server-list limit");
  invalid = generic;
  invalid.interface_id = 43U;
  invalid.relay_interface_id = {'s', 'a', 'p', '1'};
  if (agent.replace_interface(invalid) !=
      RelayConfigStatus::duplicate_return_key)
    throw std::runtime_error(
        "DHCPv6 relay accepted an ambiguous Interface-Id mapping");
}
