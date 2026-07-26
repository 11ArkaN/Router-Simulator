// Client and server integration tests exchange only encoded DHCPv6 payloads.
// They verify randomized Solicit delay, preference-255 selection, a distinct
// Request transaction, committed Reply state and the T1-triggered Renew path.

#include "router/dhcpv6_client.hpp"
#include "router/dhcpv6_server.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::dhcpv6::LeasePool pool() {
  const auto prefix = router::ip::parse_ipv6_prefix("2001:db8:60::/64");
  if (!prefix)
    throw std::runtime_error("DHCPv6 client pool fixture invalid");
  router::dhcpv6::LeasePool result{
      .prefix = *prefix,
      .preferred_lifetime_seconds = 3600U,
      .valid_lifetime_seconds = 7200U,
      .t1_seconds = 1800U,
      .t2_seconds = 2880U};
  for (std::size_t index = 0; index < result.allocation_secret.size(); ++index)
    result.allocation_secret[index] = static_cast<std::uint8_t>(index + 9U);
  return result;
}

} // namespace

void dhcpv6_client_tests() {
  using namespace router;
  using namespace router::dhcpv6;
  using namespace router::packet::dhcpv6;
  using namespace std::chrono_literals;

  constexpr std::array<std::uint8_t, 7U> server_duid{0U, 3U, 0U, 1U, 1U,
                                                     2U, 3U};
  constexpr std::array<std::uint8_t, 7U> client_duid{0U, 3U, 0U, 1U, 4U,
                                                     5U, 6U};
  ServerConfiguration server_configuration{
      .duid_octets = static_cast<std::uint16_t>(server_duid.size()),
      .preference = 255U,
      .dns_recursive_servers = {*ip::parse_ipv6("2001:db8:53::53")},
      .solicit_maximum_retransmission_seconds = 120U,
      .information_maximum_retransmission_seconds = 180U};
  std::copy(server_duid.begin(), server_duid.end(),
            server_configuration.duid.begin());
  const auto address_pool = pool();
  Server server;
  require(server.configure(server_configuration,
                           std::span<const LeasePool>{&address_pool, 1U}, {},
                           1h),
          "DHCPv6 client test server configuration failed");

  ClientConfiguration client_configuration{
      .duid_octets = static_cast<std::uint16_t>(client_duid.size()),
      .identity_associations = {
          {.iaid = 0x11223344U, .kind = LeaseKind::non_temporary}},
      .requested_options = {
          static_cast<std::uint16_t>(OptionCode::dns_recursive_name_server)},
      .rapid_commit = false};
  std::copy(client_duid.begin(), client_duid.end(),
            client_configuration.duid.begin());
  for (std::size_t index = 0;
       index < client_configuration.transaction_secret.size(); ++index)
    client_configuration.transaction_secret[index] =
        static_cast<std::uint8_t>(0x80U + index);
  auto obsolete_configuration = client_configuration;
  obsolete_configuration.identity_associations.front().kind =
      LeaseKind::temporary;
  Client obsolete_client;
  require(!obsolete_client.configure(obsolete_configuration),
          "DHCPv6 client accepted obsolete RFC 9915 IA_TA intent");
  Client client;
  require(client.configure(client_configuration),
          "DHCPv6 client rejected valid configuration");
  const auto now = Client::Clock::now();
  require(client.start(0x010203U, 0x13579bdfU, now),
          "DHCPv6 client failed to start Solicit exchange");

  std::array<std::uint8_t, maximum_message_octets> client_wire{};
  std::array<std::uint8_t, maximum_message_octets> server_wire{};

  // Discovery can hear several servers before selecting one. RFC 9915 section
  // 18.2.9 recommends an override only when every Advertise carrying that
  // option agrees, so packet arrival order must not select the last value.
  auto first_consensus_configuration = server_configuration;
  first_consensus_configuration.preference = 10U;
  first_consensus_configuration.solicit_maximum_retransmission_seconds = 300U;
  first_consensus_configuration.information_maximum_retransmission_seconds =
      360U;
  Server first_consensus_server;
  require(first_consensus_server.configure(
              first_consensus_configuration,
              std::span<const LeasePool>{&address_pool, 1U}, {}, 1h),
          "first DHCPv6 consensus server configuration failed");
  auto second_consensus_configuration = first_consensus_configuration;
  second_consensus_configuration.duid[4U] ^= 0x40U;
  second_consensus_configuration.solicit_maximum_retransmission_seconds =
      600U;
  second_consensus_configuration.information_maximum_retransmission_seconds =
      660U;
  Server second_consensus_server;
  require(second_consensus_server.configure(
              second_consensus_configuration,
              std::span<const LeasePool>{&address_pool, 1U}, {}, 1h),
          "second DHCPv6 consensus server configuration failed");
  Client consensus_client;
  require(consensus_client.configure(client_configuration) &&
              consensus_client.start(0x0a0b0cU, 0x12345671U, now),
          "DHCPv6 consensus client could not start discovery");
  const auto consensus_solicit =
      consensus_client.poll(client_wire, now + 2s);
  const auto first_advertise_result = first_consensus_server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          consensus_solicit.message_octets),
      server_wire, now + 2s);
  const auto first_advertise_ingest = consensus_client.ingest(
      std::span<const std::uint8_t>{server_wire}.first(
          first_advertise_result.message_octets),
      now + 2s);
  const auto second_advertise_result = second_consensus_server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          consensus_solicit.message_octets),
      server_wire, now + 2s);
  const auto second_advertise_ingest = consensus_client.ingest(
      std::span<const std::uint8_t>{server_wire}.first(
          second_advertise_result.message_octets),
      now + 2s);
  require(consensus_solicit.status == ClientPollStatus::transmit &&
              first_advertise_result.status ==
                  ServerProcessStatus::response &&
              second_advertise_result.status ==
                  ServerProcessStatus::response &&
              first_advertise_ingest == ClientIngestStatus::accepted &&
              second_advertise_ingest == ClientIngestStatus::accepted,
          "DHCPv6 client did not collect both valid Advertise messages");
  const auto consensus_checkpoint = consensus_client.checkpoint(now + 2s);
  require(consensus_checkpoint.solicit_maximum_retransmission_seconds ==
                  maximum_retransmission_default_seconds &&
              consensus_checkpoint.information_maximum_retransmission_seconds ==
                  maximum_retransmission_default_seconds &&
              consensus_checkpoint.advertise_solicit_maximum_conflict &&
              !consensus_checkpoint.advertise_information_maximum_seen,
          "conflicting DHCPv6 Advertise overrides did not restore defaults");
  Client restored_consensus;
  require(restored_consensus.restore(consensus_checkpoint, now + 20s) &&
              restored_consensus.checkpoint(now + 20s)
                  .advertise_solicit_maximum_conflict,
          "DHCPv6 Advertise consensus was lost across checkpoint restore");

  require(client.poll(client_wire, now).status == ClientPollStatus::idle,
          "DHCPv6 client ignored randomized SOL_MAX_DELAY");
  auto client_output = client.poll(client_wire, now + 2s);
  auto parsed =
      client_output.status == ClientPollStatus::transmit
          ? packet::dhcpv6::parse(
                std::span<const std::uint8_t>{client_wire}.first(
                    client_output.message_octets))
          : std::nullopt;
  require(parsed && parsed->type == static_cast<std::uint8_t>(
                                        MessageType::solicit),
          "DHCPv6 client did not emit Solicit after its initial delay");
  const auto solicit_transaction = parsed->transaction_id;

  auto server_output = server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          client_output.message_octets),
      server_wire, now + 2s);
  require(server_output.status == ServerProcessStatus::response &&
              client.ingest(
                  std::span<const std::uint8_t>{server_wire}.first(
                      server_output.message_octets),
                  now + 2s) == ClientIngestStatus::accepted,
          "DHCPv6 client rejected valid preference-255 Advertise");

  client_output = client.poll(client_wire, now + 2s);
  parsed = client_output.status == ClientPollStatus::transmit
               ? packet::dhcpv6::parse(
                     std::span<const std::uint8_t>{client_wire}.first(
                         client_output.message_octets))
               : std::nullopt;
  require(parsed && parsed->type == static_cast<std::uint8_t>(
                                        MessageType::request) &&
              parsed->transaction_id != solicit_transaction,
          "DHCPv6 client did not start a distinct Request exchange");
  server_output = server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          client_output.message_octets),
      server_wire, now + 2s);
  require(server_output.status == ServerProcessStatus::response &&
              client.ingest(
                  std::span<const std::uint8_t>{server_wire}.first(
                      server_output.message_octets),
                  now + 2s) == ClientIngestStatus::accepted &&
              client.state() == ClientState::bound &&
              client.leases().size() == 1U &&
              client.dns_servers().size() == 1U &&
              ip::contains(address_pool.prefix, client.leases().front().value),
          "DHCPv6 Request/Reply did not bind the offered address");

  const auto bound_checkpoint = client.checkpoint(now + 2s);
  require(bound_checkpoint.solicit_maximum_retransmission_seconds == 120U,
          "DHCPv6 client did not retain valid SOL_MAX_RT");
  Client restored;
  require(Client::validate_checkpoint(bound_checkpoint) &&
              restored.restore(bound_checkpoint, now + 100s) &&
              restored.state() == ClientState::bound &&
              restored.leases().size() == 1U &&
              restored.leases().front().value == client.leases().front().value &&
              restored.poll(client_wire, now + 1899s).status ==
                  ClientPollStatus::idle &&
              restored.poll(client_wire, now + 1901s).status ==
                  ClientPollStatus::transmit,
          "DHCPv6 checkpoint did not preserve the relative T1 deadline");

  client_output = client.poll(client_wire, now + 1803s);
  parsed = client_output.status == ClientPollStatus::transmit
               ? packet::dhcpv6::parse(
                     std::span<const std::uint8_t>{client_wire}.first(
                         client_output.message_octets))
               : std::nullopt;
  require(parsed && parsed->type ==
                        static_cast<std::uint8_t>(MessageType::renew),
          "DHCPv6 client did not enter Renew at earliest T1");
  server_output = server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          client_output.message_octets),
      server_wire, now + 1803s);
  require(server_output.status == ServerProcessStatus::response &&
              client.ingest(
                  std::span<const std::uint8_t>{server_wire}.first(
                      server_output.message_octets),
                  now + 1803s) == ClientIngestStatus::accepted &&
              client.state() == ClientState::bound,
          "DHCPv6 Renew/Reply did not refresh the binding");

  Client stateless;
  require(stateless.configure(client_configuration) &&
              stateless.start_information_request(0xabcdefU, 0x2468ace1U,
                                                   now),
          "DHCPv6 stateless client failed to start");
  auto stateless_output = stateless.poll(client_wire, now + 2s);
  parsed = stateless_output.status == ClientPollStatus::transmit
               ? packet::dhcpv6::parse(
                     std::span<const std::uint8_t>{client_wire}.first(
                         stateless_output.message_octets))
               : std::nullopt;
  require(parsed && parsed->type == static_cast<std::uint8_t>(
                                        MessageType::information_request),
          "DHCPv6 stateless client did not emit Information-request");
  server_output = server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          stateless_output.message_octets),
      server_wire, now + 2s);
  require(server_output.status == ServerProcessStatus::response &&
              stateless.ingest(
                  std::span<const std::uint8_t>{server_wire}.first(
                      server_output.message_octets),
                  now + 2s) == ClientIngestStatus::accepted &&
              stateless.state() == ClientState::information_bound &&
              stateless.dns_servers().size() == 1U &&
              stateless.poll(client_wire, now + 3600s).status ==
                  ClientPollStatus::idle &&
              stateless.poll(client_wire, now + 86403s).status ==
                  ClientPollStatus::idle &&
              stateless.poll(client_wire, now + 86405s).status ==
                  ClientPollStatus::transmit,
          "DHCPv6 Information Reply lost DNS or refresh state");
  const auto information_checkpoint = stateless.checkpoint(now + 86405s);
  require(information_checkpoint.information_maximum_retransmission_seconds ==
              180U,
          "DHCPv6 client did not retain valid INF_MAX_RT");
  Client restored_information;
  require(Client::validate_checkpoint(information_checkpoint) &&
              restored_information.restore(information_checkpoint,
                                           now + 90000s) &&
              restored_information.state() ==
                  ClientState::information_requesting,
          "DHCPv6 active Information-request did not survive checkpoint");

  // Confirm is a real multicast exchange and never carries a Server
  // Identifier. The server returns only link policy, so the client must keep
  // the original lease instead of expecting IA resources in the Reply.
  require(client.start_confirm(now + 2000s),
          "DHCPv6 client rejected Confirm for an address-only binding");
  client_output = client.poll(client_wire, now + 2002s);
  parsed = client_output.status == ClientPollStatus::transmit
               ? packet::dhcpv6::parse(
                     std::span<const std::uint8_t>{client_wire}.first(
                         client_output.message_octets))
               : std::nullopt;
  require(parsed && parsed->type ==
                        static_cast<std::uint8_t>(MessageType::confirm),
          "DHCPv6 Confirm did not honor its randomized initial delay");
  bool confirm_has_server_identifier{};
  OptionCursor confirm_options{parsed->options};
  while (const auto option = confirm_options.next())
    confirm_has_server_identifier =
        confirm_has_server_identifier ||
        option->code ==
            static_cast<std::uint16_t>(OptionCode::server_identifier);
  require(confirm_options.valid() && !confirm_has_server_identifier,
          "DHCPv6 Confirm illegally included Server Identifier");
  server_output = server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          client_output.message_octets),
      server_wire, now + 2002s);
  require(server_output.status == ServerProcessStatus::response &&
              client.ingest(
                  std::span<const std::uint8_t>{server_wire}.first(
                      server_output.message_octets),
                  now + 2002s) == ClientIngestStatus::accepted &&
              client.state() == ClientState::bound &&
              client.leases().size() == 1U,
          "DHCPv6 Confirm success did not retain the address");

  // Release removes the address before building its first packet. A valid
  // Reply completes the operation even if a retransmitted request would have
  // caused the server to report NoBinding.
  const auto released_value = client.leases().front().value;
  require(client.start_release(
              std::span<const packet::Ipv6>{&released_value, 1U},
              now + 2003s) &&
              client.leases().empty(),
          "DHCPv6 Release did not remove its address before transmission");
  client_output = client.poll(client_wire, now + 2003s);
  parsed = client_output.status == ClientPollStatus::transmit
               ? packet::dhcpv6::parse(
                     std::span<const std::uint8_t>{client_wire}.first(
                         client_output.message_octets))
               : std::nullopt;
  require(parsed && parsed->type ==
                        static_cast<std::uint8_t>(MessageType::release),
          "DHCPv6 Release did not emit its first wire message");
  server_output = server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          client_output.message_octets),
      server_wire, now + 2003s);
  require(server_output.status == ServerProcessStatus::response &&
              client.ingest(
                  std::span<const std::uint8_t>{server_wire}.first(
                      server_output.message_octets),
                  now + 2003s) == ClientIngestStatus::accepted &&
              client.state() == ClientState::stopped,
          "DHCPv6 Release Reply did not complete the operation");

  // Restore the earlier binding to exercise Decline independently. The
  // server can legitimately answer NoBinding because Release already won;
  // RFC 9915 still requires the client to complete Decline and rediscover.
  Client declining;
  require(declining.restore(bound_checkpoint, now + 3000s),
          "DHCPv6 Decline fixture restore failed");
  const auto declined_value = declining.leases().front().value;
  require(declining.start_decline(
              std::span<const packet::Ipv6>{&declined_value, 1U},
              now + 3001s) &&
              declining.leases().empty(),
          "DHCPv6 Decline did not quarantine the address locally");
  client_output = declining.poll(client_wire, now + 3001s);
  parsed = client_output.status == ClientPollStatus::transmit
               ? packet::dhcpv6::parse(
                     std::span<const std::uint8_t>{client_wire}.first(
                         client_output.message_octets))
               : std::nullopt;
  require(parsed && parsed->type ==
                        static_cast<std::uint8_t>(MessageType::decline),
          "DHCPv6 Decline did not emit its wire message");
  server_output = server.process(
      std::span<const std::uint8_t>{client_wire}.first(
          client_output.message_octets),
      server_wire, now + 3001s);
  require(server_output.status == ServerProcessStatus::response &&
              declining.ingest(
                  std::span<const std::uint8_t>{server_wire}.first(
                      server_output.message_octets),
                  now + 3001s) == ClientIngestStatus::accepted &&
              declining.state() == ClientState::soliciting,
          "DHCPv6 Decline Reply did not restart server discovery");

  // RFC 9915 rate limiting spans exchange restarts on one interface. Stopping
  // a logical exchange must not refill the bucket, otherwise a local failure
  // loop can evade the required long-term limit by repeatedly restarting.
  Client rate_limited;
  require(rate_limited.configure(client_configuration),
          "DHCPv6 rate-limit client configuration failed");
  for (std::uint32_t attempt = 0;
       attempt < device_catalog::dhcpv6_client_rate_limit_packets;
       ++attempt) {
    require(rate_limited.start(0x100U + attempt, 0x80000001U + attempt, now) &&
                rate_limited.poll(client_wire, now + 2s).status ==
                    ClientPollStatus::transmit,
            "DHCPv6 token bucket blocked a packet within its burst");
    rate_limited.stop();
  }
  require(rate_limited.start(0x200U, 0x90000001U, now) &&
              rate_limited.poll(client_wire, now + 2s).status ==
                  ClientPollStatus::idle &&
              rate_limited.poll(client_wire, now + 3s).status ==
                  ClientPollStatus::transmit,
          "DHCPv6 token bucket did not enforce and refill the profile rate");
}
