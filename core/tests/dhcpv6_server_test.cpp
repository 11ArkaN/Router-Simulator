// DHCPv6 server tests drive real RFC 9915 byte messages through Solicit,
// Advertise, Request, Reply, retransmit, Release, Rapid Commit and stateless
// information paths. Repository assertions detect premature or lost commits.

#include "router/dhcpv6_server.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

constexpr std::uint16_t code(router::packet::dhcpv6::OptionCode value) {
  return static_cast<std::uint16_t>(value);
}

constexpr std::uint8_t type(router::packet::dhcpv6::MessageType value) {
  return static_cast<std::uint8_t>(value);
}

std::array<std::uint8_t, 12U> ia_na_data(std::uint32_t iaid) {
  std::array<std::uint8_t, 12U> output{};
  const auto size = router::packet::dhcpv6::encode_ia_na_or_pd(
      output, iaid, 0U, 0U, {});
  if (!size || *size != output.size())
    throw std::runtime_error("DHCPv6 test IA_NA encoding failed");
  return output;
}

std::vector<std::uint8_t> message(
    router::packet::dhcpv6::MessageType message_type,
    std::uint32_t transaction_id, std::span<const std::uint8_t> client_duid,
    std::span<const std::uint8_t> server_duid, bool rapid,
    bool include_ia = true) {
  std::vector<std::uint8_t> bytes(512U);
  auto writer = router::packet::dhcpv6::begin_client_server(
      bytes, type(message_type), transaction_id);
  if (!writer)
    throw std::runtime_error("DHCPv6 test message header failed");
  const auto association = ia_na_data(0x10203040U);
  if ((!client_duid.empty() &&
       !writer->append(
           code(router::packet::dhcpv6::OptionCode::client_identifier),
           client_duid)) ||
      (!server_duid.empty() &&
       !writer->append(
           code(router::packet::dhcpv6::OptionCode::server_identifier),
           server_duid)) ||
      (include_ia &&
       !writer->append(code(router::packet::dhcpv6::OptionCode::ia_na),
                       association)) ||
      (rapid &&
       !writer->append(code(router::packet::dhcpv6::OptionCode::rapid_commit),
                       {})))
    throw std::runtime_error("DHCPv6 test message options failed");
  bytes.resize(writer->size());
  return bytes;
}

std::vector<std::uint8_t> confirm_message(
    std::span<const std::uint8_t> client_duid,
    router::packet::Ipv6 address) {
  using namespace router::packet::dhcpv6;
  std::array<std::uint8_t, 24U> address_data{};
  const auto address_size =
      encode_ia_address(address_data, address, 0U, 0U);
  std::array<std::uint8_t, 28U> nested{};
  nested[0U] = 0U;
  nested[1U] = static_cast<std::uint8_t>(OptionCode::ia_address);
  nested[2U] = 0U;
  nested[3U] = static_cast<std::uint8_t>(*address_size);
  std::copy_n(address_data.begin(), *address_size, nested.begin() + 4U);
  std::array<std::uint8_t, 40U> association{};
  const auto association_size = encode_ia_na_or_pd(
      association, 0x10203040U, 0U, 0U, nested);
  std::vector<std::uint8_t> bytes(128U);
  auto writer = begin_client_server(
      bytes, type(MessageType::confirm), 0x314159U);
  if (!writer || !address_size || !association_size ||
      !writer->append(code(OptionCode::client_identifier), client_duid) ||
      !writer->append(code(OptionCode::ia_na),
                      std::span<const std::uint8_t>{association}.first(
                          *association_size)))
    throw std::runtime_error("DHCPv6 Confirm fixture failed");
  bytes.resize(writer->size());
  return bytes;
}

std::optional<router::packet::dhcpv6::OptionView>
find_option(std::span<const std::uint8_t> bytes,
            router::packet::dhcpv6::OptionCode wanted) {
  const auto parsed = router::packet::dhcpv6::parse(bytes);
  if (!parsed)
    return std::nullopt;
  router::packet::dhcpv6::OptionCursor cursor{parsed->options};
  while (const auto option = cursor.next())
    if (option->code == code(wanted))
      return option;
  return std::nullopt;
}

router::dhcpv6::LeasePool address_pool() {
  const auto prefix = router::ip::parse_ipv6_prefix("2001:db8:40::/64");
  if (!prefix)
    throw std::runtime_error("DHCPv6 server pool fixture invalid");
  router::dhcpv6::LeasePool pool{
      .prefix = *prefix,
      .preferred_lifetime_seconds = 3600U,
      .valid_lifetime_seconds = 7200U,
      .t1_seconds = 1800U,
      .t2_seconds = 2880U};
  for (std::size_t index = 0; index < pool.allocation_secret.size(); ++index)
    pool.allocation_secret[index] = static_cast<std::uint8_t>(0xa0U + index);
  return pool;
}

} // namespace

void dhcpv6_server_tests() {
  using namespace router;
  using namespace router::dhcpv6;
  using namespace router::packet::dhcpv6;
  using namespace std::chrono_literals;

  constexpr std::array<std::uint8_t, 6U> server_duid{0U, 3U, 0U, 1U, 0xaaU,
                                                     1U};
  constexpr std::array<std::uint8_t, 6U> client_duid{0U, 3U, 0U, 1U, 0xbbU,
                                                     2U};
  ServerConfiguration configuration{
      .duid_octets = static_cast<std::uint16_t>(server_duid.size()),
      .preference = 91U,
      .rapid_commit = true,
      .dns_recursive_servers = {*ip::parse_ipv6("2001:db8:53::53")},
      .solicit_maximum_retransmission_seconds = std::nullopt,
      .information_maximum_retransmission_seconds = std::nullopt};
  std::copy(server_duid.begin(), server_duid.end(),
            configuration.duid.begin());
  const auto pool = address_pool();
  Server server;
  require(server.configure(std::move(configuration),
                           std::span<const LeasePool>{&pool, 1U}, {}, 30min),
          "DHCPv6 server rejected valid configuration");

  std::array<std::uint8_t, 65535U> response{};
  const auto now = Server::Clock::now();
  const auto solicit = message(MessageType::solicit, 0x123456U, client_duid,
                               {}, false);
  auto result = server.process(solicit, response, now);
  require(result.status == ServerProcessStatus::response &&
              packet::dhcpv6::parse(
                  std::span<const std::uint8_t>{response}.first(
                      result.message_octets))
                      ->type == type(MessageType::advertise) &&
              server.leases().active_leases() == 0U,
          "DHCPv6 Solicit did not produce a non-committing Advertise");
  const auto advertise_ia = find_option(
      std::span<const std::uint8_t>{response}.first(result.message_octets),
      OptionCode::ia_na);
  require(advertise_ia && parse_ia_na_or_pd(advertise_ia->data),
          "DHCPv6 Advertise omitted the offered IA_NA");

  const auto request = message(MessageType::request, 0x223344U, client_duid,
                               server_duid, false);
  result = server.process(request, response, now + 1s);
  require(result.status == ServerProcessStatus::response &&
              packet::dhcpv6::parse(
                  std::span<const std::uint8_t>{response}.first(
                      result.message_octets))
                      ->type == type(MessageType::reply) &&
              server.leases().active_leases() == 1U,
          "DHCPv6 Request did not commit exactly one binding");
  const auto first_checkpoint = server.leases().checkpoint(now + 1s);
  result = server.process(request, response, now + 2s);
  const auto retransmit_checkpoint = server.leases().checkpoint(now + 2s);
  require(result.status == ServerProcessStatus::response &&
              server.leases().active_leases() == 1U &&
              first_checkpoint.front().value ==
                  retransmit_checkpoint.front().value,
          "DHCPv6 Request retransmit changed or duplicated its binding");

  const auto confirm = confirm_message(client_duid,
                                       first_checkpoint.front().value);
  result = server.process(confirm, response, now + 2s);
  auto confirm_status = find_option(
      std::span<const std::uint8_t>{response}.first(result.message_octets),
      OptionCode::status_code);
  require(result.status == ServerProcessStatus::response && confirm_status &&
              parse_status_code(confirm_status->data)->code == 0U,
          "DHCPv6 Confirm rejected an address appropriate to the link");
  const auto foreign = ip::parse_ipv6("2001:db8:999::1");
  require(foreign.has_value(), "DHCPv6 foreign Confirm fixture failed");
  const auto foreign_confirm = confirm_message(client_duid, *foreign);
  result = server.process(foreign_confirm, response, now + 2s);
  confirm_status = find_option(
      std::span<const std::uint8_t>{response}.first(result.message_octets),
      OptionCode::status_code);
  require(result.status == ServerProcessStatus::response && confirm_status &&
              parse_status_code(confirm_status->data)->code == 4U,
          "DHCPv6 Confirm did not return NotOnLink for a foreign prefix");

  const auto invalid = message(MessageType::request, 0x334455U, client_duid,
                               {}, false);
  require(server.process(invalid, response, now + 3s)
                  .status == ServerProcessStatus::discarded &&
              server.leases().active_leases() == 1U,
          "DHCPv6 server accepted Request without Server Identifier");

  const auto release = message(MessageType::release, 0x445566U, client_duid,
                               server_duid, false);
  result = server.process(release, response, now + 4s);
  require(result.status == ServerProcessStatus::response &&
              server.leases().active_leases() == 0U &&
              find_option(std::span<const std::uint8_t>{response}.first(
                              result.message_octets),
                          OptionCode::status_code),
          "DHCPv6 Release did not return Success and free its binding");

  const auto rapid = message(MessageType::solicit, 0x556677U, client_duid, {},
                             true);
  result = server.process(rapid, response, now + 5s);
  require(result.status == ServerProcessStatus::response &&
              packet::dhcpv6::parse(
                  std::span<const std::uint8_t>{response}.first(
                      result.message_octets))
                      ->type == type(MessageType::reply) &&
              find_option(std::span<const std::uint8_t>{response}.first(
                              result.message_octets),
                          OptionCode::rapid_commit) &&
              server.leases().active_leases() == 1U,
          "DHCPv6 Rapid Commit failed to commit before Reply");

  auto information = message(MessageType::information_request, 0x667788U, {},
                             {}, false, false);
  information.resize(64U);
  auto information_writer = begin_client_server(
      information, type(MessageType::information_request), 0x667788U);
  constexpr std::array<std::uint8_t, 4U> oro{
      0U, static_cast<std::uint8_t>(OptionCode::dns_recursive_name_server),
      0U, static_cast<std::uint8_t>(OptionCode::information_refresh_time)};
  require(information_writer &&
              information_writer->append(code(OptionCode::option_request),
                                         oro),
          "DHCPv6 Information-request fixture failed");
  information.resize(information_writer->size());
  result = server.process(information, response, now + 6s);
  require(result.status == ServerProcessStatus::response &&
              find_option(std::span<const std::uint8_t>{response}.first(
                              result.message_octets),
                          OptionCode::dns_recursive_name_server) &&
              find_option(std::span<const std::uint8_t>{response}.first(
                              result.message_octets),
                          OptionCode::information_refresh_time),
          "DHCPv6 stateless Reply omitted requested configuration");

  const auto relay_client = ip::parse_ipv6("fe80::1234");
  const auto relay_link = ip::parse_ipv6("2001:db8:40::1");
  require(relay_client && relay_link,
          "DHCPv6 server relay fixture address failed");
  std::array<std::uint8_t, 1024U> relay_forward{};
  constexpr std::array<std::uint8_t, 3U> interface_id{'i', 'f', '7'};
  const auto relayed = encapsulate_relay_forward(
      solicit, *relay_client, *relay_link, interface_id, relay_forward);
  require(relayed.status == RelayStatus::forwarded,
          "DHCPv6 server relay fixture encapsulation failed");
  result = server.process(
      std::span<const std::uint8_t>{relay_forward}.first(
          relayed.message_octets),
      response, now + 7s);
  const auto relay_reply =
      result.status == ServerProcessStatus::response
          ? decapsulate_relay_reply(
                std::span<const std::uint8_t>{response}.first(
                    result.message_octets))
          : std::nullopt;
  require(relay_reply &&
              std::equal(relay_reply->interface_id.begin(),
                         relay_reply->interface_id.end(),
                         interface_id.begin()) &&
              packet::dhcpv6::parse(relay_reply->message)->type ==
                  type(MessageType::advertise),
          "DHCPv6 server did not reconstruct the relayed return path");
}
