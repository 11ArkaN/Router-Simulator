// DHCPv4 relay tests validate giaddr, hop count, Option 82 trust and stripping
// through complete encoded messages. The tests never call a server or client
// object directly across the relay boundary.

#include "router/dhcpv4_relay.hpp"

#include <array>
#include <stdexcept>

namespace {

using namespace router;
using namespace router::dhcpv4;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

std::size_t discover(std::span<std::uint8_t> output,
                     bool option_82 = false) {
  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_request,
      .hardware_type = 1U,
      .hardware_length = 6U,
      .transaction_id = 1U,
      .client_hardware_address = {0x02U, 0U, 0U, 0U, 0U, 1U},
  };
  auto writer = packet::dhcpv4::begin(output, header);
  const std::array type{
      static_cast<std::uint8_t>(packet::dhcpv4::MessageType::discover)};
  require(writer && writer->append(
                        static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::message_type),
                        type),
          "DHCPv4 relay test could not encode DISCOVER");
  const std::array<std::uint8_t, 3U> information{1U, 1U, 7U};
  if (option_82)
    require(writer->append(
                static_cast<std::uint8_t>(
                    packet::dhcpv4::OptionCode::relay_agent_information),
                information),
            "DHCPv4 relay test could not encode Option 82");
  require(writer->finish(), "DHCPv4 relay test could not encode End");
  return writer->view().size();
}

RelayAgent relay(bool trusted = false) {
  RelayAgent value;
  RelayConfiguration configuration{};
  configuration.admin_enabled = true;
  configuration.gateway_address = {192U, 0U, 2U, 1U};
  configuration.servers = {{{198U, 51U, 100U, 5U}}};
  configuration.circuit_id = {1U, 2U, 3U};
  configuration.remote_id = {4U, 5U, 6U};
  configuration.existing_information =
      ExistingRelayInformationAction::replace;
  configuration.maximum_hops = 4U;
  configuration.trusted_ingress = trusted;
  require(value.configure(configuration),
          "DHCPv4 relay rejected valid configuration");
  return value;
}

void adds_gateway_hop_and_option_82() {
  auto agent = relay();
  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> output{};
  const auto octets = discover(input);
  const auto result =
      agent.forward_client(std::span{input.data(), octets}, output, 0U);
  require(result.status == RelayStatus::forwarded &&
              result.destination == packet::Ipv4{198U, 51U, 100U, 5U},
          "DHCPv4 relay did not select configured server");
  const auto parsed =
      packet::dhcpv4::parse(std::span{output.data(), result.message_octets});
  require(parsed && parsed->gateway_address ==
                        packet::Ipv4{192U, 0U, 2U, 1U} &&
              parsed->hops == 1U,
          "DHCPv4 relay did not set giaddr and hops");
  packet::dhcpv4::RawOptionCursor cursor{*parsed};
  bool information = false;
  while (const auto option = cursor.next())
    information |=
        option->code ==
        static_cast<std::uint8_t>(
            packet::dhcpv4::OptionCode::relay_agent_information);
  require(cursor.valid() && information,
          "DHCPv4 relay did not add Option 82");
}

void rejects_untrusted_existing_option_82() {
  auto agent = relay(false);
  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> output{};
  const auto octets = discover(input, true);
  const auto result =
      agent.forward_client(std::span{input.data(), octets}, output, 0U);
  require(result.status == RelayStatus::untrusted_relay_information,
          "DHCPv4 relay accepted untrusted Option 82 with zero giaddr");
}

void strips_option_82_toward_client() {
  auto agent = relay(true);
  std::array<std::uint8_t, 1024U> input{};
  std::array<std::uint8_t, 1024U> relayed{};
  const auto octets = discover(input);
  const auto upstream =
      agent.forward_client(std::span{input.data(), octets}, relayed, 0U);
  auto parsed =
      packet::dhcpv4::parse(std::span{relayed.data(), upstream.message_octets});
  require(parsed.has_value(), "DHCPv4 relayed request did not parse");

  auto reply_header = *parsed;
  reply_header.operation = packet::dhcpv4::Operation::boot_reply;
  reply_header.your_address = {192U, 0U, 2U, 10U};
  auto writer = packet::dhcpv4::begin(input, reply_header);
  packet::dhcpv4::RawOptionCursor options{*parsed};
  while (const auto option = options.next())
    require(writer && writer->append(option->code, option->data),
            "DHCPv4 relay test could not copy server response option");
  require(writer && writer->finish(),
          "DHCPv4 relay test could not finish server response");
  const auto downstream =
      agent.forward_server(writer->view(), relayed);
  require(downstream.status == RelayStatus::forwarded,
          "DHCPv4 relay did not forward server response");
  require(downstream.client_mac ==
              packet::Mac{0x02U, 0U, 0U, 0U, 0U, 1U},
          "DHCPv4 relay did not preserve the client hardware address");
  const auto delivered = packet::dhcpv4::parse(
      std::span{relayed.data(), downstream.message_octets});
  require(delivered.has_value(),
          "DHCPv4 downstream relay response did not parse");
  packet::dhcpv4::RawOptionCursor delivered_options{*delivered};
  while (const auto option = delivered_options.next())
    require(option->code != static_cast<std::uint8_t>(
                                packet::dhcpv4::OptionCode::
                                    relay_agent_information),
            "DHCPv4 relay leaked Option 82 to client");
}

} // namespace

void dhcpv4_relay_tests() {
  adds_gateway_hop_and_option_82();
  rejects_untrusted_existing_option_82();
  strips_option_82_toward_client();
}
