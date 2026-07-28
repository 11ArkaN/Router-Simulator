// DHCPv4 client tests connect the real client and server state owners through
// encoded payloads. No offer or acknowledgement object is transferred between
// them, preserving the same boundary used by the network runtime.

#include "router/dhcpv4_client.hpp"
#include "router/dhcpv4_server.hpp"

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

Server server() {
  Server value;
  const ServerConfiguration configuration{
      .server_instance = 1U,
      .routing_context = 1U,
      .server_identifier = {198U, 51U, 100U, 1U},
      .domain_name_servers = {},
  };
  const Pool pool{
      .id = 1U,
      .scope = {.server_instance = 1U,
                .routing_context = 1U,
                .link_identity = 5U},
      .first = {198U, 51U, 100U, 10U},
      .last = {198U, 51U, 100U, 20U},
      .subnet_mask = {255U, 255U, 255U, 0U},
      .router = {198U, 51U, 100U, 1U},
      .lease_seconds = 3600U,
      .renewal_seconds = 1800U,
      .rebinding_seconds = 3150U,
      .enabled = true,
  };
  require(value.configure(configuration, std::span{&pool, 1U}, {}),
          "DHCPv4 client test server configuration failed");
  return value;
}

Client client() {
  Client value;
  ClientConfiguration configuration{
      .hardware_address = {0x02U, 0U, 0U, 0U, 0U, 1U},
      .client_identifier = {1U, 0x02U, 0U, 0U, 0U, 0U, 1U},
      .parameter_request_list = {
          static_cast<std::uint8_t>(
              packet::dhcpv4::OptionCode::subnet_mask),
          static_cast<std::uint8_t>(packet::dhcpv4::OptionCode::router),
      },
      .user_class = {},
  };
  configuration.transaction_secret.fill(0x5aU);
  require(value.configure(configuration),
          "DHCPv4 client rejected valid persistent identity");
  return value;
}

void complete_dora_and_enter_bound() {
  auto service = server();
  auto endpoint = client();
  const auto now = Client::Clock::time_point{std::chrono::seconds{1000}};
  require(endpoint.start(now), "DHCPv4 client did not enter SELECTING");

  std::array<std::uint8_t, 1024U> client_bytes{};
  std::array<std::uint8_t, 1024U> server_bytes{};
  const auto discover = endpoint.poll(client_bytes, now);
  require(discover.status ==
              ClientPollStatus::transmit_limited_broadcast,
          "DHCPv4 client did not emit DISCOVER as limited broadcast");
  const auto offer = service.process(
      std::span{client_bytes.data(), discover.message_octets}, server_bytes,
      5U, now);
  require(offer.status == ServerProcessStatus::response,
          "DHCPv4 server did not answer DISCOVER");
  require(endpoint.ingest(
              std::span{server_bytes.data(), offer.message_octets}, now) ==
              ClientIngestStatus::accepted,
          "DHCPv4 client did not accept OFFER");
  require(endpoint.state() == ClientState::requesting,
          "DHCPv4 client did not enter REQUESTING");

  const auto request = endpoint.poll(client_bytes, now);
  require(request.status ==
              ClientPollStatus::transmit_limited_broadcast,
          "DHCPv4 client did not broadcast selecting REQUEST");
  const auto acknowledgement = service.process(
      std::span{client_bytes.data(), request.message_octets}, server_bytes,
      5U, now);
  require(acknowledgement.status == ServerProcessStatus::response,
          "DHCPv4 server did not answer REQUEST");
  require(endpoint.ingest(
              std::span{server_bytes.data(),
                        acknowledgement.message_octets},
              now) == ClientIngestStatus::accepted,
          "DHCPv4 client did not accept ACK");
  require(endpoint.state() == ClientState::checking &&
              endpoint.pending_lease(),
          "DHCPv4 client exposed an ACKed address before conflict detection");
  require(endpoint.address_probe_succeeded(now + std::chrono::seconds{4}),
          "DHCPv4 client rejected a successful address conflict check");
  require(endpoint.state() == ClientState::bound && endpoint.lease(),
          "DHCPv4 client did not enter BOUND");
  require(endpoint.lease()->router ==
              packet::Ipv4{198U, 51U, 100U, 1U},
          "DHCPv4 client lost router option");
}

void renewal_uses_unicast_then_rebinding_uses_broadcast() {
  auto service = server();
  auto endpoint = client();
  const auto start = Client::Clock::time_point{std::chrono::seconds{1000}};
  require(endpoint.start(start), "DHCPv4 renewal test did not start");
  std::array<std::uint8_t, 1024U> client_bytes{};
  std::array<std::uint8_t, 1024U> server_bytes{};
  auto transmit = endpoint.poll(client_bytes, start);
  auto answer = service.process(
      std::span{client_bytes.data(), transmit.message_octets}, server_bytes,
      5U, start);
  require(endpoint.ingest(
              std::span{server_bytes.data(), answer.message_octets}, start) ==
              ClientIngestStatus::accepted,
          "DHCPv4 renewal test OFFER failed");
  transmit = endpoint.poll(client_bytes, start);
  answer = service.process(
      std::span{client_bytes.data(), transmit.message_octets}, server_bytes,
      5U, start);
  require(endpoint.ingest(
              std::span{server_bytes.data(), answer.message_octets}, start) ==
              ClientIngestStatus::accepted,
          "DHCPv4 renewal test ACK failed");
  require(endpoint.address_probe_succeeded(start + std::chrono::seconds{4}),
          "DHCPv4 renewal test did not complete initial address probing");

  const auto renewal = endpoint.poll(
      client_bytes, start + std::chrono::seconds{1804});
  require(renewal.status == ClientPollStatus::transmit_unicast &&
              renewal.destination == packet::Ipv4{198U, 51U, 100U, 1U},
          "DHCPv4 RENEWING did not unicast to the selected server");
  const auto rebinding = endpoint.poll(
      client_bytes, start + std::chrono::seconds{3154});
  require(rebinding.status ==
              ClientPollStatus::transmit_limited_broadcast,
          "DHCPv4 REBINDING did not use limited broadcast");
}

} // namespace

void dhcpv4_client_tests() {
  complete_dora_and_enter_bound();
  renewal_uses_unicast_then_rebinding_uses_broadcast();
}
