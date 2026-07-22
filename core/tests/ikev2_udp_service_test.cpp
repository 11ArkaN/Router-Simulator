// IKE UDP tests cross real UdpEndpoint codec, demultiplexing and receive queues.
// They cover both address families, RFC 3948 discrimination, transactional
// listener setup and handle reconstruction after the UDP owner is restored.

#include "router/ikev2_packet.hpp"
#include "router/ikev2_udp_service.hpp"
#include "router/ipsec_nat_t.hpp"

#include <array>
#include <stdexcept>
#include <vector>

namespace {

struct Observation {
  router::ikev2::UdpInboundKind kind{router::ikev2::UdpInboundKind::ike};
  std::vector<std::uint8_t> bytes;
  std::uint16_t destination_port{};
};

bool observe(void *context,
             const router::ikev2::UdpInboundDatagram &datagram) {
  auto &result = *static_cast<Observation *>(context);
  result.kind = datagram.kind;
  result.bytes.assign(datagram.bytes.begin(), datagram.bytes.end());
  result.destination_port = datagram.metadata.destination_port;
  return true;
}

} // namespace

void ikev2_udp_service_tests() {
  using namespace router;
  transport::UdpEndpoint server;
  ikev2::UdpService service;
  if (!service.configure(server))
    throw std::runtime_error("IKE UDP listeners did not bind");

  transport::UdpEndpoint client;
  const packet::Ipv4 client_address{192U, 0U, 2U, 1U};
  const packet::Ipv4 server_address{192U, 0U, 2U, 2U};
  const auto client_socket = client.bind({.family = transport::IpFamily::ipv4,
                                          .ipv4 = client_address,
                                          .ipv6 = {},
                                          .interface_id = 0U,
                                          .port = 0U});
  std::array<std::uint8_t, 128U> ike_message{};
  const ikev2::Header header{.initiator_spi = 1U,
                             .responder_spi = 0U,
                             .first_payload = 0U,
                             .major_version = 2U,
                             .minor_version = 0U,
                             .exchange_type = static_cast<std::uint8_t>(
                                 ikev2::ExchangeType::ike_sa_init),
                             .initiator = true,
                             .higher_version_supported = false,
                             .response = false,
                             .message_id = 0U,
                             .length = ikev2::header_octets};
  if (!client_socket || !ikev2::encode_header(header, ike_message))
    throw std::runtime_error("IKE UDP fixture could not encode IKE_SA_INIT");
  std::array<std::uint8_t, 256U> udp{};
  const auto direct = client.encode_ipv4(
      *client_socket, client_address, server_address, 0U,
      ipsec::nat_t::ike_port,
      std::span<const std::uint8_t>{ike_message}.first(ikev2::header_octets),
      udp);
  if (direct.status != transport::UdpSendStatus::encoded ||
      server.ingest_ipv4(
          std::span<const std::uint8_t>{udp}.first(direct.datagram_octets),
          client_address, server_address, 0U) !=
          transport::UdpIngressStatus::delivered)
    throw std::runtime_error("IKE UDP/500 did not cross UDP demultiplexing");
  Observation observation;
  if (service.service_one(server, &observation, observe) !=
          ikev2::UdpServiceResult::delivered ||
      observation.kind != ikev2::UdpInboundKind::ike ||
      observation.destination_port != ipsec::nat_t::ike_port ||
      observation.bytes.size() != ikev2::header_octets)
    throw std::runtime_error("IKE UDP/500 dispatch failed");

  std::array<std::uint8_t, 160U> encapsulated{};
  const auto encapsulated_octets = ipsec::nat_t::encode_ike(
      std::span<const std::uint8_t>{ike_message}.first(ikev2::header_octets),
      encapsulated);
  const auto natt = client.encode_ipv4(
      *client_socket, client_address, server_address, 0U,
      ipsec::nat_t::encapsulated_port,
      std::span<const std::uint8_t>{encapsulated}.first(encapsulated_octets),
      udp);
  if (natt.status != transport::UdpSendStatus::encoded ||
      server.ingest_ipv4(
          std::span<const std::uint8_t>{udp}.first(natt.datagram_octets),
          client_address, server_address, 0U) !=
          transport::UdpIngressStatus::delivered ||
      service.service_one(server, &observation, observe) !=
          ikev2::UdpServiceResult::delivered ||
      observation.kind != ikev2::UdpInboundKind::ike ||
      observation.bytes.size() != ikev2::header_octets)
    throw std::runtime_error("IKE Non-ESP Marker dispatch failed");

  const packet::Ipv6 client_v6{0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
                               0U,    0U,    0U,    0U,    0U, 0U, 0U, 1U};
  const packet::Ipv6 server_v6{0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
                               0U,    0U,    0U,    0U,    0U, 0U, 0U, 2U};
  const auto client_v6_socket =
      client.bind({.family = transport::IpFamily::ipv6,
                   .ipv4 = {},
                   .ipv6 = client_v6,
                   .interface_id = 0U,
                   .port = 0U});
  const auto direct_v6 = client_v6_socket
                             ? client.encode_ipv6(
                                   *client_v6_socket, client_v6, server_v6, 0U,
                                   ipsec::nat_t::ike_port,
                                   std::span<const std::uint8_t>{ike_message}
                                       .first(ikev2::header_octets),
                                   udp)
                             : transport::UdpSendResult{};
  if (!client_v6_socket ||
      direct_v6.status != transport::UdpSendStatus::encoded ||
      server.ingest_ipv6(
          std::span<const std::uint8_t>{udp}.first(direct_v6.datagram_octets),
          client_v6, server_v6, 0U) !=
          transport::UdpIngressStatus::delivered ||
      service.service_one(server, &observation, observe) !=
          ikev2::UdpServiceResult::delivered ||
      observation.kind != ikev2::UdpInboundKind::ike)
    throw std::runtime_error("IKE UDP/IPv6 dispatch failed");

  const std::array<std::uint8_t, 8U> esp{0x12U, 0x34U, 0x56U, 0x78U,
                                        0U,    0U,    0U,    1U};
  const auto esp_udp = client.encode_ipv4(
      *client_socket, client_address, server_address, 0U,
      ipsec::nat_t::encapsulated_port, esp, udp);
  if (esp_udp.status != transport::UdpSendStatus::encoded ||
      server.ingest_ipv4(
          std::span<const std::uint8_t>{udp}.first(esp_udp.datagram_octets),
          client_address, server_address, 0U) !=
          transport::UdpIngressStatus::delivered ||
      service.service_one(server, &observation, observe) !=
          ikev2::UdpServiceResult::delivered ||
      observation.kind != ikev2::UdpInboundKind::esp ||
      observation.bytes != std::vector<std::uint8_t>(esp.begin(), esp.end()))
    throw std::runtime_error("UDP-encapsulated ESP dispatch failed");

  const std::array<std::uint8_t, 1U> keepalive{0xffU};
  const auto keepalive_udp = client.encode_ipv4(
      *client_socket, client_address, server_address, 0U,
      ipsec::nat_t::encapsulated_port, keepalive, udp);
  if (keepalive_udp.status != transport::UdpSendStatus::encoded ||
      server.ingest_ipv4(std::span<const std::uint8_t>{udp}.first(
                             keepalive_udp.datagram_octets),
                         client_address, server_address, 0U) !=
          transport::UdpIngressStatus::delivered ||
      service.service_one(server, &observation, observe) !=
          ikev2::UdpServiceResult::delivered ||
      observation.kind != ikev2::UdpInboundKind::nat_keepalive ||
      !observation.bytes.empty())
    throw std::runtime_error("NAT keepalive dispatch failed");

  const std::array<std::uint8_t, 3U> malformed_marker{};
  const auto malformed_udp = client.encode_ipv4(
      *client_socket, client_address, server_address, 0U,
      ipsec::nat_t::encapsulated_port, malformed_marker, udp);
  if (malformed_udp.status != transport::UdpSendStatus::encoded ||
      server.ingest_ipv4(
          std::span<const std::uint8_t>{udp}.first(malformed_udp.datagram_octets),
          client_address, server_address, 0U) !=
          transport::UdpIngressStatus::delivered ||
      service.service_one(server, &observation, observe) !=
          ikev2::UdpServiceResult::malformed)
    throw std::runtime_error("undersized Non-ESP Marker reached an IKE owner");

  const auto endpoint_checkpoint = server.checkpoint();
  const auto service_checkpoint = service.checkpoint();
  transport::UdpEndpoint restored_endpoint;
  ikev2::UdpService restored_service;
  if (!restored_endpoint.restore(endpoint_checkpoint) ||
      !restored_service.restore(service_checkpoint, restored_endpoint) ||
      !restored_service.socket(transport::IpFamily::ipv6, true))
    throw std::runtime_error("IKE UDP socket ownership did not restore");

  transport::UdpEndpoint conflicting_endpoint;
  const auto conflict = conflicting_endpoint.bind(
      {.family = transport::IpFamily::ipv6,
       .ipv4 = {},
       .ipv6 = {},
       .interface_id = 0U,
       .port = ipsec::nat_t::ike_port});
  ikev2::UdpService rejected_service;
  if (!conflict || rejected_service.configure(conflicting_endpoint) ||
      !conflicting_endpoint.bind({.family = transport::IpFamily::ipv4,
                                  .ipv4 = {},
                                  .ipv6 = {},
                                  .interface_id = 0U,
                                  .port = ipsec::nat_t::ike_port}))
    throw std::runtime_error("failed IKE listener setup leaked partial sockets");
}
