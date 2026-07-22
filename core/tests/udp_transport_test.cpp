// Dual-stack UDP queue tests validate bind conflicts, exact checksum-gated
// demultiplexing, multi-block payload retention, overload and stale handles.

#include "router/udp_transport.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::packet::Ipv6 ipv6(const char *text) {
  const auto value = router::ip::parse_ipv6(text);
  if (!value)
    throw std::runtime_error("UDP transport fixture IPv6 address is invalid");
  return *value;
}

} // namespace

void udp_transport_tests() {
  using namespace router;
  using namespace router::transport;

  UdpEndpoint endpoint;
  const auto local = ipv6("2001:db8::53");
  const auto remote = ipv6("2001:db8::100");
  constexpr packet::Mac remote_mac{0x02U, 0U, 0U, 0U, 0x01U, 0x00U};
  const auto socket = endpoint.bind(
      {.family = IpFamily::ipv6, .interface_id = 7U, .port = 547U});
  require(socket &&
              !endpoint.bind({.family = IpFamily::ipv6,
                              .ipv6 = local,
                              .interface_id = 7U,
                              .port = 547U}) &&
              !endpoint.bind({.family = IpFamily::ipv6,
                              .ipv6 = ipv6("fe80::1"),
                              .port = 546U}),
          "UDP bind admitted an overlapping tuple or unzoned link-local");

  // Socket transmit validation is independent from link MTU. The maximum
  // legal payload must produce one complete UDP datagram for the IP owner,
  // which may later split it into Ethernet-sized IPv6 fragments.
  std::vector<std::uint8_t> send_payload(packet::udp::maximum_payload_octets,
                                         0x5aU);
  std::vector<std::uint8_t> send_wire(packet::udp::maximum_datagram_octets);
  const auto sent = endpoint.encode_ipv6(
      *socket, local, remote, 7U, 546U, send_payload, send_wire);
  require(sent.status == UdpSendStatus::encoded &&
              sent.datagram_octets == packet::udp::maximum_datagram_octets &&
              packet::udp::parse_ipv6(send_wire, local, remote).has_value(),
          "UDP send imposed a frame MTU or produced an invalid checksum");
  require(endpoint.encode_ipv6(*socket, ipv6("2001:db8::54"), remote, 7U,
                               546U, {}, send_wire)
                  .status == UdpSendStatus::encoded,
          "wildcard UDP bind rejected an IP-owner-selected source");
  require(endpoint.encode_ipv6(*socket, local, {}, 7U, 546U, {}, send_wire)
                  .status == UdpSendStatus::invalid_destination &&
              endpoint.encode_ipv6(*socket, local, remote, 8U, 546U, {},
                                   send_wire)
                      .status == UdpSendStatus::interface_mismatch,
          "UDP send accepted an unspecified peer or the wrong interface");

  // ICMPv6 is advisory, so the socket accepts it only for the most recently
  // encoded tuple. The fixed error slot is consumed exactly once and survives
  // checkpointing without introducing an attacker-sized error queue.
  require(endpoint.encode_ipv6(*socket, local, remote, 7U, 546U, {},
                               send_wire)
                  .status == UdpSendStatus::encoded &&
              !endpoint.report_ipv6_error(
                  local, ipv6("2001:db8::101"), 7U, 547U, 546U,
                  Ipv6NetworkErrorKind::destination_unreachable,
                  packet::icmpv6_destination_unreachable_type, 0U, 0U) &&
              endpoint.report_ipv6_error(
                  local, remote, 7U, 547U, 546U,
                  Ipv6NetworkErrorKind::packet_too_big,
                  packet::icmpv6_packet_too_big_type, 0U, 1280U),
          "UDP accepted an uncorrelated error or rejected its exact tuple");
  const auto error_checkpoint = endpoint.checkpoint();
  UdpEndpoint error_restored;
  require(error_restored.restore(error_checkpoint),
          "UDP error checkpoint did not restore");
  const auto network_error = error_restored.take_network_error(*socket);
  require(network_error &&
              network_error->kind == Ipv6NetworkErrorKind::packet_too_big &&
              network_error->parameter == 1280U &&
              network_error->remote == remote &&
              !error_restored.take_network_error(*socket),
          "UDP SO_ERROR slot changed or was not consumed exactly once");
  require(error_restored.report_ipv6_error(
              local, remote, 7U, 547U, 546U,
              Ipv6NetworkErrorKind::unknown, 100U, 7U, 0x11223344U),
          "UDP discarded a correlated future ICMPv6 error type");
  const auto future_error = error_restored.take_network_error(*socket);
  require(future_error && future_error->type == 100U &&
              future_error->code == 7U &&
              future_error->parameter == 0x11223344U,
          "UDP discarded a correlated future ICMPv6 error type");
  static_cast<void>(endpoint.take_network_error(*socket));

  std::vector<std::uint8_t> payload(5000U);
  for (std::size_t index = 0; index < payload.size(); ++index)
    payload[index] = static_cast<std::uint8_t>(index);
  std::vector<std::uint8_t> wire(packet::udp::header_octets + payload.size());
  require(packet::udp::encode_ipv6(wire, remote, local, 546U, 547U, payload) &&
              endpoint.ingest_ipv6(wire, remote, local, 7U, remote_mac) ==
                  UdpIngressStatus::delivered &&
              endpoint.queued(*socket) == 1U,
          "UDP IPv6 datagram did not reach its bound receive queue");
  std::array<std::uint8_t, 32> too_small{};
  const auto retained = endpoint.receive(*socket, too_small);
  require(retained.status == UdpReceiveStatus::buffer_too_small &&
              retained.metadata.payload_octets == payload.size() &&
              endpoint.queued(*socket) == 1U,
          "UDP short receive buffer consumed or truncated the datagram");
  const auto checkpoint = endpoint.checkpoint();
  UdpEndpoint restored;
  require(UdpEndpoint::validate_checkpoint(checkpoint) &&
              restored.restore(checkpoint) && restored.queued(*socket) == 1U,
          "UDP checkpoint did not preserve socket handle and queue order");
  std::vector<std::uint8_t> received(payload.size());
  const auto delivered = endpoint.receive(*socket, received);
  require(delivered.status == UdpReceiveStatus::delivered &&
              delivered.metadata.family == IpFamily::ipv6 &&
              delivered.metadata.source_ipv6 == remote &&
              delivered.metadata.destination_ipv6 == local &&
              delivered.metadata.source_mac == remote_mac &&
              delivered.metadata.source_port == 546U &&
              delivered.metadata.destination_port == 547U &&
              received == payload && endpoint.queued(*socket) == 0U,
          "UDP receive lost metadata or chained payload bytes");
  std::vector<std::uint8_t> restored_payload(payload.size());
  const auto restored_datagram = restored.receive(*socket, restored_payload);
  require(restored_datagram.status == UdpReceiveStatus::delivered &&
              restored_datagram.metadata.source_mac == remote_mac &&
              restored_payload == payload,
          "UDP restored payload or Ethernet source metadata changed");
  auto invalid_checkpoint = checkpoint;
  invalid_checkpoint.sockets[socket->index]
      .datagrams.front()
      .metadata.destination_port = 999U;
  require(!UdpEndpoint::validate_checkpoint(invalid_checkpoint) &&
              !restored.restore(invalid_checkpoint),
          "UDP checkpoint admitted a datagram under the wrong socket tuple");

  wire.back() ^= 1U;
  require(endpoint.ingest_ipv6(wire, remote, local, 7U) ==
              UdpIngressStatus::malformed &&
              endpoint.queued(*socket) == 0U,
          "UDP receive queue admitted a bad IPv6 checksum");

  // The maximum ordinary UDP payload spans many pool blocks but remains one
  // queued datagram. Its allocation is returned exactly after receive.
  std::vector<std::uint8_t> maximum_payload(packet::udp::maximum_payload_octets,
                                            0xa5U);
  std::vector<std::uint8_t> maximum_wire(packet::udp::maximum_datagram_octets);
  const auto free_before = endpoint.free_payload_octets();
  require(packet::udp::encode_ipv6(maximum_wire, remote, local, 546U, 547U,
                                   maximum_payload) &&
              endpoint.ingest_ipv6(maximum_wire, remote, local, 7U) ==
                  UdpIngressStatus::delivered &&
              endpoint.free_payload_octets() < free_before,
          "UDP pool imposed a frame-sized payload ceiling");
  std::vector<std::uint8_t> maximum_received(maximum_payload.size());
  require(endpoint.receive(*socket, maximum_received).status ==
              UdpReceiveStatus::delivered &&
              maximum_received == maximum_payload &&
              endpoint.free_payload_octets() == free_before,
          "UDP maximum payload blocks were corrupted or leaked");

  // A zero-length application payload consumes one descriptor but no payload
  // block. Per-socket admission remains independent from the byte pool.
  std::array<std::uint8_t, packet::udp::header_octets> empty_wire{};
  require(packet::udp::encode_ipv6(empty_wire, remote, local, 546U, 547U, {})
              .has_value(),
          "UDP empty datagram fixture failed");
  for (std::size_t count = 0;
       count < device_catalog::udp_datagrams_per_socket; ++count)
    require(endpoint.ingest_ipv6(empty_wire, remote, local, 7U) ==
                UdpIngressStatus::delivered,
            "UDP socket queue filled before its generated limit");
  require(endpoint.ingest_ipv6(empty_wire, remote, local, 7U) ==
              UdpIngressStatus::queue_full,
          "UDP socket queue exceeded its generated datagram limit");

  const auto stale = *socket;
  require(endpoint.close(stale) && endpoint.queued(stale) == 0U &&
              endpoint.receive(stale, received).status ==
                  UdpReceiveStatus::invalid_socket &&
              !endpoint.close(stale),
          "UDP close retained queued state or accepted a stale handle");

  const auto first_ephemeral = endpoint.bind({.family = IpFamily::ipv4});
  const auto second_ephemeral = endpoint.bind({.family = IpFamily::ipv4});
  require(first_ephemeral && second_ephemeral &&
              endpoint.local_port(*first_ephemeral) !=
                  endpoint.local_port(*second_ephemeral),
          "UDP ephemeral allocator reused a live local tuple");

  // IPv4 broadcast transmission is an explicit socket authority analogous to
  // SO_BROADCAST. A wildcard bind alone must not accidentally grant it, and
  // the permission must survive the same socket checkpoint as the port.
  constexpr packet::Ipv4 limited_broadcast{255U, 255U, 255U, 255U};
  std::array<std::uint8_t, packet::udp::header_octets> broadcast_wire{};
  require(endpoint.encode_ipv4(*first_ephemeral, {192U, 0U, 2U, 1U},
                               limited_broadcast, 2U, 9U, {}, broadcast_wire)
                  .status == UdpSendStatus::invalid_destination,
          "UDP wildcard socket transmitted broadcast without permission");
  const auto broadcast_socket = endpoint.bind(
      {.family = IpFamily::ipv4,
       .interface_id = 2U,
       .port = 7777U,
       .ipv4_broadcast = true});
  require(broadcast_socket &&
              endpoint.encode_ipv4(*broadcast_socket, {192U, 0U, 2U, 1U},
                                   limited_broadcast, 2U, 9U, {},
                                   broadcast_wire)
                      .status == UdpSendStatus::encoded,
          "UDP broadcast-enabled socket rejected limited broadcast");
  const auto broadcast_checkpoint = endpoint.checkpoint();
  UdpEndpoint broadcast_restored;
  require(broadcast_restored.restore(broadcast_checkpoint) &&
              broadcast_restored.local_binding(*broadcast_socket)
                  ->ipv4_broadcast,
          "UDP checkpoint dropped broadcast socket authority");

  constexpr packet::Ipv4 ipv4_source{192U, 0U, 2U, 1U};
  constexpr packet::Ipv4 ipv4_destination{192U, 0U, 2U, 2U};
  const auto ipv4_port = endpoint.local_port(*first_ephemeral);
  std::vector<std::uint8_t> maximum_ipv4_payload(
      packet::udp::maximum_ipv4_payload_octets, 0x6cU);
  std::vector<std::uint8_t> maximum_ipv4_wire(
      packet::udp::header_octets + maximum_ipv4_payload.size());
  const auto maximum_ipv4_sent = endpoint.encode_ipv4(
      *first_ephemeral, ipv4_source, ipv4_destination, 2U, 53U,
      maximum_ipv4_payload, maximum_ipv4_wire);
  require(maximum_ipv4_sent.status == UdpSendStatus::encoded &&
              maximum_ipv4_sent.datagram_octets == maximum_ipv4_wire.size() &&
              packet::udp::parse_ipv4(maximum_ipv4_wire, ipv4_source,
                                      ipv4_destination)
                  .has_value(),
          "UDP endpoint imposed a link MTU on IPv4 transmit");
  std::vector<std::uint8_t> oversized_ipv4(
      packet::udp::maximum_ipv4_payload_octets + 1U);
  require(endpoint.encode_ipv4(*first_ephemeral, ipv4_source,
                               ipv4_destination, 2U, 53U,
                               oversized_ipv4, maximum_ipv4_wire)
                  .status == UdpSendStatus::message_too_large &&
              endpoint.encode_ipv4(*first_ephemeral, ipv4_source,
                                   ipv4_destination, 2U, 53U, {},
                                   maximum_ipv4_wire, false)
                  .status == UdpSendStatus::encoded &&
              maximum_ipv4_wire[6U] == 0U &&
              maximum_ipv4_wire[7U] == 0U,
          "UDP endpoint confused IPv4 protocol size or checksum policy with output capacity");
  std::array<std::uint8_t, packet::udp::header_octets + 3U> ipv4_wire{};
  constexpr std::array<std::uint8_t, 3> ipv4_payload{1U, 2U, 3U};
  require(ipv4_port &&
              packet::udp::encode_ipv4(ipv4_wire, ipv4_source,
                                       ipv4_destination, 1000U, *ipv4_port,
                                       ipv4_payload, false) &&
              endpoint.ingest_ipv4(ipv4_wire, ipv4_source, ipv4_destination,
                                   2U) == UdpIngressStatus::delivered,
          "UDP IPv4 zero-checksum datagram did not demultiplex");
  std::array<std::uint8_t, 3> ipv4_received{};
  require(endpoint.receive(*first_ephemeral, ipv4_received).status ==
              UdpReceiveStatus::delivered &&
              ipv4_received == ipv4_payload,
          "UDP IPv4 payload did not survive its receive queue");

  // Bind well beyond the removed 64-slot table. This is a regression scale,
  // not a new limit: the production repository grows until allocator or port
  // namespace exhaustion and retains every slot generation in checkpoints.
  std::vector<UdpSocketHandle> dynamic_sockets;
  dynamic_sockets.reserve(256U);
  for (std::uint16_t index = 0U; index < 256U; ++index) {
    const auto dynamic = endpoint.bind(
        {.family = IpFamily::ipv6,
         .interface_id = 7U,
         .port = static_cast<std::uint16_t>(20000U + index)});
    require(dynamic.has_value(),
            "UDP dynamic socket repository retained a fixed slot ceiling");
    dynamic_sockets.push_back(*dynamic);
  }
  const auto dynamic_checkpoint = endpoint.checkpoint();
  UdpEndpoint dynamic_restored;
  require(dynamic_checkpoint.sockets.size() > 64U &&
              dynamic_restored.restore(dynamic_checkpoint) &&
              dynamic_restored.local_port(dynamic_sockets.back()) == 20255U,
          "UDP dynamic socket handles did not survive checkpoint restore");
}
