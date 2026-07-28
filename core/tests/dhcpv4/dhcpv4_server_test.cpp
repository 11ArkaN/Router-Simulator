// RFC 2131 server tests exercise DORA through complete wire payloads. They
// verify that OFFER reserves an address, REQUEST commits only that binding and
// a second client cannot receive the pending address.

#include "router/dhcpv4_server.hpp"
#include "router/interface_identity.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

using namespace router;
using namespace router::dhcpv4;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

std::size_t request(std::span<std::uint8_t> output,
                    packet::dhcpv4::MessageType type,
                    std::uint32_t transaction_id,
                    std::uint8_t mac_suffix,
                    std::optional<packet::Ipv4> requested = std::nullopt,
                    std::optional<packet::Ipv4> server = std::nullopt,
                    packet::Ipv4 gateway = {},
                    std::optional<packet::Ipv4> link_selection = std::nullopt) {
  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_request,
      .hardware_type = 1U,
      .hardware_length = 6U,
      .transaction_id = transaction_id,
      .gateway_address = gateway,
  };
  header.client_hardware_address[0U] = 0x02U;
  header.client_hardware_address[5U] = mac_suffix;
  auto writer = packet::dhcpv4::begin(output, header);
  const std::array type_data{static_cast<std::uint8_t>(type)};
  require(writer && writer->append(
                        static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::message_type),
                        type_data),
          "DHCPv4 test request could not encode message type");
  if (requested)
    require(writer->append(
                static_cast<std::uint8_t>(
                    packet::dhcpv4::OptionCode::requested_address),
                *requested),
            "DHCPv4 test request could not encode requested address");
  if (server)
    require(writer->append(
                static_cast<std::uint8_t>(
                    packet::dhcpv4::OptionCode::server_identifier),
                *server),
            "DHCPv4 test request could not encode server identifier");
  if (link_selection) {
    const std::array<std::uint8_t, 6U> relay_information{
        5U, 4U, (*link_selection)[0U], (*link_selection)[1U],
        (*link_selection)[2U], (*link_selection)[3U]};
    require(writer->append(
                static_cast<std::uint8_t>(
                    packet::dhcpv4::OptionCode::relay_agent_information),
                relay_information),
            "DHCPv4 test request could not encode Link Selection");
  }
  require(writer->finish(), "DHCPv4 test request could not encode End");
  return writer->view().size();
}

std::size_t lease_query(
    std::span<std::uint8_t> output, std::uint32_t transaction_id,
    packet::Ipv4 client_address, packet::Ipv4 gateway,
    std::optional<std::uint8_t> mac_suffix = std::nullopt,
    std::span<const std::uint8_t> client_identifier = {}) {
  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_request,
      .hardware_type = mac_suffix ? std::uint8_t{1U} : std::uint8_t{},
      .hardware_length = mac_suffix ? std::uint8_t{6U} : std::uint8_t{},
      .transaction_id = transaction_id,
      .client_address = client_address,
      .gateway_address = gateway,
  };
  if (mac_suffix) {
    header.client_hardware_address[0U] = 0x02U;
    header.client_hardware_address[5U] = *mac_suffix;
  }
  auto writer = packet::dhcpv4::begin(output, header);
  const std::array type{static_cast<std::uint8_t>(
      packet::dhcpv4::MessageType::lease_query)};
  const std::array<std::uint8_t, 3U> requested_options{
      static_cast<std::uint8_t>(packet::dhcpv4::OptionCode::lease_time),
      static_cast<std::uint8_t>(
          packet::dhcpv4::OptionCode::relay_agent_information),
      static_cast<std::uint8_t>(
          packet::dhcpv4::OptionCode::client_identifier)};
  require(writer &&
              writer->append(
                  static_cast<std::uint8_t>(
                      packet::dhcpv4::OptionCode::message_type),
                  type) &&
              writer->append(
                  static_cast<std::uint8_t>(
                      packet::dhcpv4::OptionCode::parameter_request_list),
                  requested_options),
          "DHCPv4 test could not encode Leasequery");
  if (!client_identifier.empty())
    require(writer->append(
                static_cast<std::uint8_t>(
                    packet::dhcpv4::OptionCode::client_identifier),
                client_identifier),
            "DHCPv4 test could not encode Leasequery Client Identifier");
  require(writer->finish(), "DHCPv4 test could not terminate Leasequery");
  return writer->view().size();
}

packet::Ipv4 offered_address(
    std::span<const std::uint8_t> response) {
  const auto message = packet::dhcpv4::parse(response);
  require(message.has_value(), "DHCPv4 server response did not parse");
  return message->your_address;
}

Server configured_server() {
  Server server;
  const ServerConfiguration configuration{
      .server_instance = 1U,
      .routing_context = 1U,
      .server_identifier = {192U, 0U, 2U, 1U},
      .domain_name_servers = {{192U, 0U, 2U, 53U}},
  };
  const Pool pool{
      .id = 1U,
      .scope = {.server_instance = 1U,
                .routing_context = 1U,
                .link_identity = 10U},
      .first = {192U, 0U, 2U, 10U},
      .last = {192U, 0U, 2U, 11U},
      .subnet_mask = {255U, 255U, 255U, 0U},
      .router = {192U, 0U, 2U, 1U},
      .lease_seconds = 3600U,
      .renewal_seconds = 1800U,
      .rebinding_seconds = 3150U,
      .enabled = true,
  };
  require(server.configure(configuration, std::span{&pool, 1U}, {}),
          "DHCPv4 server rejected valid configuration");
  return server;
}

Server configured_force_renew_server() {
  Server server;
  const ServerConfiguration configuration{
      .server_instance = 1U,
      .routing_context = 1U,
      .server_identifier = {192U, 0U, 2U, 1U},
      .domain_name_servers = {},
      .offer_hold = std::chrono::seconds{60},
      .decline_hold = std::chrono::seconds{3600},
      .authoritative = true,
      .force_renews = true,
  };
  const Pool pool{
      .id = 1U,
      .scope = {.server_instance = 1U,
                .routing_context = 1U,
                .link_identity = lab::physical_interface_id(1U)},
      .first = {192U, 0U, 2U, 10U},
      .last = {192U, 0U, 2U, 10U},
      .subnet_mask = {255U, 255U, 255U, 0U},
      .router = {192U, 0U, 2U, 1U},
      .lease_seconds = 3600U,
      .renewal_seconds = 1800U,
      .rebinding_seconds = 3150U,
      .enabled = true,
  };
  require(server.configure(configuration, std::span{&pool, 1U}, {}),
          "DHCPv4 server rejected FORCERENEW configuration");
  return server;
}

void dora_commits_reserved_offer() {
  auto server = configured_server();
  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> output{};
  const auto now = Server::Clock::time_point{std::chrono::seconds{1000}};

  const auto discover_octets = request(
      input, packet::dhcpv4::MessageType::discover, 0x12345678U, 1U);
  const auto offer =
      server.process(std::span{input.data(), discover_octets}, output, 10U, now);
  require(offer.status == ServerProcessStatus::response,
          "DHCPv4 DISCOVER did not produce OFFER");
  const auto address =
      offered_address(std::span{output.data(), offer.message_octets});

  const auto request_octets = request(
      input, packet::dhcpv4::MessageType::request, 0x12345678U, 1U,
      address, packet::Ipv4{192U, 0U, 2U, 1U});
  const auto acknowledgement =
      server.process(std::span{input.data(), request_octets}, output, 10U, now);
  require(acknowledgement.status == ServerProcessStatus::response,
          "DHCPv4 REQUEST did not produce ACK");
  const auto parsed =
      packet::dhcpv4::parse(std::span{output.data(),
                                     acknowledgement.message_octets});
  require(parsed && packet::dhcpv4::message_type(*parsed) ==
                        packet::dhcpv4::MessageType::acknowledgement,
          "DHCPv4 server returned the wrong response type");
  require(server.leases().leases().front().state == BindingState::active,
          "DHCPv4 ACK was emitted without an active binding");
}

void pending_offer_is_not_reused() {
  auto server = configured_server();
  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> output{};
  const auto now = Server::Clock::time_point{std::chrono::seconds{1000}};
  const auto first_octets = request(
      input, packet::dhcpv4::MessageType::discover, 1U, 1U);
  const auto first =
      server.process(std::span{input.data(), first_octets}, output, 10U, now);
  const auto first_address =
      offered_address(std::span{output.data(), first.message_octets});

  const auto second_octets = request(
      input, packet::dhcpv4::MessageType::discover, 2U, 2U);
  const auto second =
      server.process(std::span{input.data(), second_octets}, output, 10U, now);
  const auto second_address =
      offered_address(std::span{output.data(), second.message_octets});
  require(first_address != second_address,
          "DHCPv4 server reused a pending offer");
}

void relayed_request_selects_the_client_link() {
  Server server;
  ServerConfiguration configuration{};
  configuration.server_instance = 1U;
  configuration.routing_context = 1U;
  configuration.server_identifier = {198U, 51U, 100U, 2U};
  const std::array pools{
      Pool{.id = 1U,
           .scope = {.server_instance = 1U,
                     .routing_context = 1U,
                     .link_identity = 10U},
           .first = {192U, 0U, 2U, 10U},
           .last = {192U, 0U, 2U, 20U},
           .subnet_mask = {255U, 255U, 255U, 0U},
           .router = {192U, 0U, 2U, 1U},
           .lease_seconds = 3600U,
           .renewal_seconds = 1800U,
           .rebinding_seconds = 3150U,
           .enabled = true},
      Pool{.id = 2U,
           .scope = {.server_instance = 1U,
                     .routing_context = 1U,
                     .link_identity = 20U},
           .first = {203U, 0U, 113U, 10U},
           .last = {203U, 0U, 113U, 20U},
           .subnet_mask = {255U, 255U, 255U, 0U},
           .router = {203U, 0U, 113U, 1U},
           .lease_seconds = 3600U,
           .renewal_seconds = 1800U,
           .rebinding_seconds = 3150U,
           .enabled = true}};
  require(server.configure(configuration, pools, {}),
          "DHCPv4 server rejected relayed-link pools");

  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> output{};
  const auto octets = request(
      input, packet::dhcpv4::MessageType::discover, 9U, 9U, std::nullopt,
      std::nullopt, packet::Ipv4{198U, 51U, 100U, 1U},
      packet::Ipv4{203U, 0U, 113U, 1U});
  const auto result = server.process(
      std::span{input.data(), octets}, output,
      999U, Server::Clock::time_point{std::chrono::seconds{1000}});
  require(result.status == ServerProcessStatus::response &&
              offered_address(
                  std::span{output.data(), result.message_octets}) ==
                  packet::Ipv4{203U, 0U, 113U, 10U},
          "DHCPv4 server selected its ingress interface instead of the "
          "RFC 3527 client link");
}

void force_renew_targets_the_committed_client_without_counting_encoding() {
  auto server = configured_force_renew_server();
  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> output{};
  const auto now = Server::Clock::time_point{std::chrono::seconds{1000}};
  const auto discover_octets = request(
      input, packet::dhcpv4::MessageType::discover, 11U, 0x44U);
  const auto offer = server.process(
      std::span{input.data(), discover_octets}, output,
      lab::physical_interface_id(1U), now);
  require(offer.status == ServerProcessStatus::response,
          "DHCPv4 FORCERENEW test did not produce OFFER");
  const auto address =
      offered_address(std::span{output.data(), offer.message_octets});
  const auto request_octets = request(
      input, packet::dhcpv4::MessageType::request, 11U, 0x44U, address,
      packet::Ipv4{192U, 0U, 2U, 1U});
  require(server.process(std::span{input.data(), request_octets}, output,
                         lab::physical_interface_id(1U), now)
              .status == ServerProcessStatus::response,
          "DHCPv4 FORCERENEW test did not commit the binding");

  const auto result = server.force_renew(
      address, packet::Ipv4{192U, 0U, 2U, 1U}, output, now);
  require(result.status == ForceRenewStatus::encoded &&
              result.destination == address &&
              result.destination_mac ==
                  packet::Mac{{0x02U, 0U, 0U, 0U, 0U, 0x44U}} &&
              result.link_identity == lab::physical_interface_id(1U),
          "DHCPFORCERENEW did not retain the committed client's L2 identity");
  const auto parsed =
      packet::dhcpv4::parse(std::span{output.data(), result.message_octets});
  require(parsed && parsed->operation == packet::dhcpv4::Operation::boot_reply &&
              packet::dhcpv4::message_type(*parsed) ==
                  packet::dhcpv4::MessageType::force_renew &&
              parsed->transaction_id == 0U,
          "DHCPFORCERENEW wire payload does not follow RFC 3203");
  require(server.statistics().tx_force_renew == 0U,
          "encoding DHCPFORCERENEW was incorrectly counted as transmission");
  server.note_force_renew_sent();
  require(server.statistics().tx_force_renew == 1U,
          "successful DHCPFORCERENEW transmission was not counted");
}

void lease_query_supports_ip_mac_and_client_identifier_regimes() {
  auto server = configured_server();
  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> output{};
  const auto now = Server::Clock::time_point{std::chrono::seconds{1000}};
  const auto discover_octets = request(
      input, packet::dhcpv4::MessageType::discover, 21U, 0x55U);
  const auto offer =
      server.process(std::span{input.data(), discover_octets}, output, 10U,
                     now);
  const auto address =
      offered_address(std::span{output.data(), offer.message_octets});
  const auto request_octets = request(
      input, packet::dhcpv4::MessageType::request, 21U, 0x55U, address,
      packet::Ipv4{192U, 0U, 2U, 1U}, packet::Ipv4{},
      packet::Ipv4{192U, 0U, 2U, 1U});
  require(server.process(std::span{input.data(), request_octets}, output, 10U,
                         now)
              .status == ServerProcessStatus::response,
          "DHCPv4 Leasequery test could not commit its binding");

  auto query_octets = lease_query(
      input, 31U, address, packet::Ipv4{198U, 51U, 100U, 1U});
  auto result = server.process(std::span{input.data(), query_octets}, output,
                               999U, now + std::chrono::seconds{10});
  auto response = packet::dhcpv4::parse(
      std::span{output.data(), result.message_octets});
  require(result.status == ServerProcessStatus::response && response &&
              packet::dhcpv4::message_type(*response) ==
                  packet::dhcpv4::MessageType::lease_active &&
              response->client_address == address &&
              response->gateway_address ==
                  packet::Ipv4{198U, 51U, 100U, 1U},
          "DHCPv4 query by address did not return DHCPLEASEACTIVE");
  std::array<std::uint8_t, 255U> option{};
  const auto relay_information = packet::dhcpv4::normalize_option(
      *response,
      static_cast<std::uint8_t>(
          packet::dhcpv4::OptionCode::relay_agent_information),
      option);
  require(relay_information && relay_information->octets == 6U &&
              option[0U] == 5U,
          "DHCPLEASEACTIVE did not retain the latest Relay Agent Information");

  query_octets = lease_query(
      input, 32U, {}, packet::Ipv4{198U, 51U, 100U, 1U}, 0x55U);
  result = server.process(std::span{input.data(), query_octets}, output, 999U,
                          now + std::chrono::seconds{10});
  response = packet::dhcpv4::parse(
      std::span{output.data(), result.message_octets});
  require(response && packet::dhcpv4::message_type(*response) ==
                          packet::dhcpv4::MessageType::lease_active &&
              response->client_address == address,
          "DHCPv4 query by MAC did not select the active binding");

  query_octets = lease_query(
      input, 33U, packet::Ipv4{192U, 0U, 2U, 11U},
      packet::Ipv4{198U, 51U, 100U, 1U});
  result = server.process(std::span{input.data(), query_octets}, output, 999U,
                          now);
  response = packet::dhcpv4::parse(
      std::span{output.data(), result.message_octets});
  require(response && packet::dhcpv4::message_type(*response) ==
                          packet::dhcpv4::MessageType::lease_unassigned,
          "managed free address did not return DHCPLEASEUNASSIGNED");

  query_octets = lease_query(
      input, 34U, packet::Ipv4{203U, 0U, 113U, 99U},
      packet::Ipv4{198U, 51U, 100U, 1U});
  result = server.process(std::span{input.data(), query_octets}, output, 999U,
                          now);
  response = packet::dhcpv4::parse(
      std::span{output.data(), result.message_octets});
  require(response && packet::dhcpv4::message_type(*response) ==
                          packet::dhcpv4::MessageType::lease_unknown,
          "unmanaged address did not return DHCPLEASEUNKNOWN");
}

} // namespace

void dhcpv4_server_tests() {
  dora_commits_reserved_offer();
  pending_offer_is_not_reused();
  relayed_request_selects_the_client_link();
  force_renew_targets_the_committed_client_without_counting_encoding();
  lease_query_supports_ip_mac_and_client_identifier_regimes();
}
