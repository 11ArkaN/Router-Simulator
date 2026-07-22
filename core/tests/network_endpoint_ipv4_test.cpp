// Endpoint IPv4 UDP integration tests cross ARP, host routing, whole-batch
// admission, source fragmentation, out-of-order reassembly and socket queues.

#include "../src/network_endpoint.hpp"

#include "router/udp_packet.hpp"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

router::crypto::Sha256Digest transport_secret(std::uint8_t seed) {
  router::crypto::Sha256Digest result{};
  for (std::size_t index = 0U; index < result.size(); ++index)
    result[index] = static_cast<std::uint8_t>(seed + index);
  return result;
}

struct Egress {
  std::vector<router::packet::Frame> frames;
  std::size_t available{};
};

bool collect(void *context, const router::packet::Frame &frame) noexcept {
  static_cast<Egress *>(context)->frames.push_back(frame);
  return true;
}

bool admit(void *context, std::size_t count) noexcept {
  return count <= static_cast<Egress *>(context)->available;
}

} // namespace

void network_endpoint_ipv4_tests() {
  using namespace router;
  using namespace router::network_detail;
  const NetworkEndpointConfiguration source_configuration{
      .endpoint_mac = {0x02U, 0U, 0U, 0U, 0U, 1U},
      .endpoint_address = {192U, 0U, 2U, 1U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {},
      .endpoint_mtu = 576U,
      .endpoint_interface_id = 101U,
      .endpoint_transport_secret = transport_secret(1U)};
  const NetworkEndpointConfiguration destination_configuration{
      .endpoint_mac = {0x02U, 0U, 0U, 0U, 0U, 2U},
      .endpoint_address = {192U, 0U, 2U, 2U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {},
      .endpoint_mtu = 576U,
      .endpoint_interface_id = 102U,
      .endpoint_transport_secret = transport_secret(2U)};
  auto source = std::make_unique<EndpointStack>();
  auto destination = std::make_unique<EndpointStack>();
  if (!source->configure(source_configuration) ||
      !destination->configure(destination_configuration))
    throw std::runtime_error("IPv4 UDP endpoint configuration failed");
  const auto now = EndpointStack::Clock::now();
  source->set_link_state(true, now);
  destination->set_link_state(true, now);

  // The Nokia ping range and RFC 791 minimum reassembly assumptions permit a
  // 1472-octet Echo payload on a host interface whose IPv4 MTU is 68. That
  // request needs 31 fragments. Exercise unresolved ARP, checkpoint transfer,
  // out-of-order request reassembly and equally fragmented reply delivery so
  // no default-payload-sized queue can masquerade as protocol support.
  auto minimum_mtu_source_configuration = source_configuration;
  minimum_mtu_source_configuration.endpoint_address = {198U, 51U, 100U, 1U};
  minimum_mtu_source_configuration.endpoint_mtu =
      device_catalog::minimum_host_ipv4_mtu;
  minimum_mtu_source_configuration.endpoint_interface_id = 201U;
  minimum_mtu_source_configuration.endpoint_transport_secret =
      transport_secret(11U);
  auto minimum_mtu_destination_configuration = destination_configuration;
  minimum_mtu_destination_configuration.endpoint_address = {198U, 51U, 100U,
                                                              2U};
  minimum_mtu_destination_configuration.endpoint_mtu =
      device_catalog::minimum_host_ipv4_mtu;
  minimum_mtu_destination_configuration.endpoint_interface_id = 202U;
  minimum_mtu_destination_configuration.endpoint_transport_secret =
      transport_secret(12U);
  auto minimum_mtu_source = std::make_unique<EndpointStack>();
  auto minimum_mtu_destination = std::make_unique<EndpointStack>();
  if (!minimum_mtu_source->configure(minimum_mtu_source_configuration) ||
      !minimum_mtu_destination->configure(
          minimum_mtu_destination_configuration))
    throw std::runtime_error("minimum-MTU IPv4 endpoints were rejected");
  minimum_mtu_source->set_link_state(true, now);
  minimum_mtu_destination->set_link_state(true, now);
  const auto initial_probe = minimum_mtu_source->begin_echo(
      minimum_mtu_destination_configuration.endpoint_address, 701U,
      device_catalog::maximum_ping_payload_octets, false);
  if (initial_probe.count != 1U ||
      !packet::parse_arp(initial_probe.frames.front()))
    throw std::runtime_error("maximum ping did not begin with real ARP");

  NetworkCheckpointState pending_probe_checkpoint;
  minimum_mtu_source->checkpoint(pending_probe_checkpoint, now);
  const auto pending_probe_frames = pending_probe_checkpoint.frames.size();
  constexpr std::size_t expected_minimum_mtu_fragments =
      maximum_endpoint_pending_ipv4_fragments;
  if (pending_probe_frames != expected_minimum_mtu_fragments)
    throw std::runtime_error(
        "checkpoint truncated maximum-ping pending fragments");
  auto restored_minimum_mtu_source = std::make_unique<EndpointStack>();
  if (!restored_minimum_mtu_source->configure(
          minimum_mtu_source_configuration) ||
      !restored_minimum_mtu_source->restore(pending_probe_checkpoint, now))
    throw std::runtime_error(
        "minimum-MTU pending ping did not survive checkpoint restore");

  const auto minimum_mtu_arp_reply = minimum_mtu_destination->receive(
      initial_probe.frames.front(), 701U, false, now);
  const auto released_probe =
      minimum_mtu_arp_reply.count == 1U
          ? restored_minimum_mtu_source->receive(
                minimum_mtu_arp_reply.frames.front(), 701U, true, now)
          : EndpointFrames{};
  if (released_probe.count != expected_minimum_mtu_fragments ||
      !released_probe.start_echo_clock || released_probe.mtu_exceeded)
    throw std::runtime_error(
        "ARP release retained a default-ping fragment ceiling");

  EndpointFrames fragmented_reply;
  for (std::size_t index = released_probe.count; index-- > 0U;) {
    const auto response = minimum_mtu_destination->receive(
        released_probe.frames[index], 701U, false, now);
    if (response.count)
      fragmented_reply = response;
  }
  if (fragmented_reply.count != expected_minimum_mtu_fragments ||
      fragmented_reply.mtu_exceeded)
    throw std::runtime_error(
        "minimum-MTU destination emitted an oversized Echo Reply");
  bool echo_completed{};
  for (std::size_t index = fragmented_reply.count; index-- > 0U;) {
    const auto received = restored_minimum_mtu_source->receive(
        fragmented_reply.frames[index], 701U, true, now);
    echo_completed = echo_completed || received.echo_reply;
  }
  if (!echo_completed)
    throw std::runtime_error(
        "minimum-MTU fragmented Echo Reply was not reassembled");

  // PMTU changes only after an exact quotation of the locally emitted DF
  // packet. A different packet with the same apparent sender must not poison
  // the cache, while a valid modern report survives checkpoint restore and
  // prevents a known-oversized retry from reaching Ethernet.
  auto pmtu_configuration = source_configuration;
  pmtu_configuration.endpoint_address = {203U, 0U, 113U, 10U};
  pmtu_configuration.endpoint_mtu = 1'500U;
  pmtu_configuration.endpoint_interface_id = 301U;
  pmtu_configuration.endpoint_transport_secret = transport_secret(21U);
  auto pmtu_source = std::make_unique<EndpointStack>();
  if (!pmtu_source->configure(pmtu_configuration))
    throw std::runtime_error("IPv4 PMTU endpoint configuration failed");
  pmtu_source->set_link_state(true, now);
  const packet::Ipv4 pmtu_destination{203U, 0U, 113U, 20U};
  const packet::Mac gateway_mac{0x02U, 0U, 0U, 0U, 0x30U, 1U};
  pmtu_source->restore_router_neighbor(pmtu_destination, gateway_mac);
  const auto df_probe = pmtu_source->begin_echo(
      pmtu_destination, 901U, 1'200U, true, now);
  if (df_probe.count != 1U || !df_probe.start_echo_clock)
    throw std::runtime_error("IPv4 DF probe did not enter the wire path");
  const auto unrelated = packet::icmp_echo(
      gateway_mac, pmtu_configuration.endpoint_mac, pmtu_destination,
      pmtu_configuration.endpoint_address, false, 902U, 64U, 1'200U, true);
  const auto forged_error = packet::icmp_fragmentation_needed(
      unrelated, gateway_mac, pmtu_configuration.endpoint_mac,
      pmtu_destination, pmtu_configuration.endpoint_address, 900U);
  if (!forged_error)
    throw std::runtime_error("IPv4 forged PMTU fixture could not be encoded");
  const auto forged_result = pmtu_source->receive(*forged_error, 901U, true,
                                                   now + std::chrono::seconds{1});
  if (forged_result.mtu_exceeded)
    throw std::runtime_error("unrelated IPv4 quotation poisoned PMTU");
  const auto valid_error = packet::icmp_fragmentation_needed(
      df_probe.frames.front(), gateway_mac,
      pmtu_configuration.endpoint_mac, pmtu_destination,
      pmtu_configuration.endpoint_address, 900U);
  if (!valid_error ||
      !pmtu_source
           ->receive(*valid_error, 901U, true,
                     now + std::chrono::seconds{2})
           .mtu_exceeded)
    throw std::runtime_error("valid IPv4 quotation did not lower PMTU");
  NetworkCheckpointState pmtu_checkpoint;
  pmtu_source->checkpoint(pmtu_checkpoint, now + std::chrono::seconds{2});
  auto restored_pmtu_source = std::make_unique<EndpointStack>();
  if (!restored_pmtu_source->configure(pmtu_configuration) ||
      !restored_pmtu_source->restore(pmtu_checkpoint,
                                     now + std::chrono::seconds{10}) ||
      !restored_pmtu_source
           ->begin_echo(pmtu_destination, 903U, 1'200U, true,
                        now + std::chrono::seconds{10})
           .mtu_exceeded)
    throw std::runtime_error(
        "IPv4 PMTU did not survive restore or constrain DF output");

  const auto source_socket = source->bind_udp(
      {.family = transport::IpFamily::ipv4,
       .interface_id = source_configuration.endpoint_interface_id,
       .port = 10000U});
  const auto destination_socket = destination->bind_udp(
      {.family = transport::IpFamily::ipv4,
       .interface_id = destination_configuration.endpoint_interface_id,
       .port = 20000U});
  if (!source_socket || !destination_socket)
    throw std::runtime_error("IPv4 UDP endpoint bind failed");

  const auto broadcast_source_socket = source->bind_udp(
      {.family = transport::IpFamily::ipv4,
       .interface_id = source_configuration.endpoint_interface_id,
       .port = 10001U,
       .ipv4_broadcast = true});
  const auto broadcast_destination_socket = destination->bind_udp(
      {.family = transport::IpFamily::ipv4,
       .interface_id = destination_configuration.endpoint_interface_id,
       .port = 20002U});
  if (!broadcast_source_socket || !broadcast_destination_socket)
    throw std::runtime_error("IPv4 UDP broadcast socket bind failed");

  // The first application send emits only an encoded ARP request. Delivering
  // the request and reply through receive() is the sole way the source learns
  // the destination MAC before its retry.
  Egress egress{.frames = {}, .available = 256U};
  const std::array<std::uint8_t, 1U> probe_payload{0x11U};

  // Limited broadcast maps directly to Ethernet broadcast and therefore does
  // not perform ARP. The receiving wildcard socket retains the IP broadcast
  // destination in metadata, and a missing listener produces no ICMP error.
  auto broadcast_sent = source->send_udp_ipv4(
      *broadcast_source_socket, {255U, 255U, 255U, 255U}, 20002U,
      probe_payload, &egress, collect, admit);
  const auto broadcast_ethernet = egress.frames.empty()
                                      ? std::nullopt
                                      : packet::parse_ethernet(egress.frames.front());
  if (broadcast_sent.status != EndpointUdpSendStatus::sent ||
      egress.frames.size() != 1U || !broadcast_ethernet ||
      broadcast_ethernet->destination !=
          packet::Mac{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU})
    throw std::runtime_error("IPv4 UDP limited broadcast used ARP or unicast L2");
  const auto broadcast_response = destination->receive(
      egress.frames.front(), 0U, false, now);
  std::array<std::uint8_t, 1U> broadcast_payload{};
  const auto broadcast_received = destination->receive_udp(
      *broadcast_destination_socket, broadcast_payload);
  if (broadcast_response.count != 0U ||
      broadcast_received.status != transport::UdpReceiveStatus::delivered ||
      broadcast_received.metadata.destination_ipv4 !=
          packet::Ipv4{255U, 255U, 255U, 255U} ||
      broadcast_payload != probe_payload)
    throw std::runtime_error("IPv4 UDP broadcast delivery or ICMP suppression failed");
  egress.frames.clear();

  broadcast_sent = source->send_udp_ipv4(
      *broadcast_source_socket, {192U, 0U, 2U, 255U}, 20002U,
      probe_payload, &egress, collect, admit);
  if (broadcast_sent.status != EndpointUdpSendStatus::sent ||
      egress.frames.size() != 1U)
    throw std::runtime_error("IPv4 UDP directed broadcast did not use one frame");
  const auto directed_response =
      destination->receive(egress.frames.front(), 0U, false, now);
  const auto directed_received = destination->receive_udp(
      *broadcast_destination_socket, broadcast_payload);
  if (directed_response.count != 0U ||
      directed_received.status != transport::UdpReceiveStatus::delivered ||
      directed_received.metadata.destination_ipv4 !=
          packet::Ipv4{192U, 0U, 2U, 255U})
    throw std::runtime_error("IPv4 UDP directed broadcast did not stay on-link");
  egress.frames.clear();

  auto sent = source->send_udp_ipv4(
      *source_socket, destination_configuration.endpoint_address, 20000U,
      probe_payload, &egress, collect, admit);
  if (sent.status != EndpointUdpSendStatus::neighbor_resolution_started ||
      egress.frames.size() != 1U ||
      !packet::parse_arp(egress.frames.front()))
    throw std::runtime_error("IPv4 UDP bypassed ARP resolution");
  const auto arp_reply = destination->receive(egress.frames.front(), 0U, false,
                                              now);
  if (arp_reply.count != 1U ||
      !packet::parse_arp(arp_reply.frames.front()))
    throw std::runtime_error("IPv4 UDP ARP peer did not answer");
  static_cast<void>(source->receive(arp_reply.frames.front(), 0U, false, now));

  // RFC 768 over IPv4 permits 65,507 application octets. A one-frame egress
  // budget rejects the complete send before any prefix becomes observable.
  std::vector<std::uint8_t> payload(packet::udp::maximum_ipv4_payload_octets);
  for (std::size_t index = 0U; index < payload.size(); ++index)
    payload[index] = static_cast<std::uint8_t>(index * 17U + 3U);
  egress.frames.clear();
  egress.available = 1U;
  sent = source->send_udp_ipv4(
      *source_socket, destination_configuration.endpoint_address, 20000U,
      payload, &egress, collect, admit);
  if (sent.status != EndpointUdpSendStatus::output_backpressure ||
      !egress.frames.empty())
    throw std::runtime_error(
        "IPv4 UDP emitted a partial fragmented batch under backpressure");

  egress.available = 256U;
  sent = source->send_udp_ipv4(
      *source_socket, destination_configuration.endpoint_address, 20000U,
      payload, &egress, collect, admit);
  if (sent.status != EndpointUdpSendStatus::sent ||
      sent.emitted_frames != egress.frames.size() ||
      egress.frames.size() < 2U)
    throw std::runtime_error("IPv4 UDP retained a Frame-sized payload limit");

  // Reverse delivery proves that completion depends on Fragment Offset and the
  // receipt bitmap, not FIFO behavior of the current point-to-point fabric.
  for (std::size_t index = egress.frames.size(); index-- > 0U;)
    static_cast<void>(destination->receive(egress.frames[index], 0U, false,
                                           now));
  std::vector<std::uint8_t> received(payload.size());
  const auto datagram = destination->receive_udp(*destination_socket, received);
  if (datagram.status != transport::UdpReceiveStatus::delivered ||
      datagram.metadata.family != transport::IpFamily::ipv4 ||
      datagram.metadata.source_ipv4 != source_configuration.endpoint_address ||
      datagram.metadata.destination_ipv4 !=
          destination_configuration.endpoint_address ||
      datagram.metadata.source_port != 10000U ||
      datagram.metadata.destination_port != 20000U || received != payload)
    throw std::runtime_error(
        "IPv4 UDP reassembly or socket delivery changed the datagram");

  // RFC 1122 requires code 1 only when the fixed timer expires after fragment
  // zero was received. The error is produced by scheduled endpoint maintenance
  // and quotes that real first fragment rather than a synthetic operation.
  std::vector<std::uint8_t> timeout_payload(2000U, 0x7cU);
  egress.frames.clear();
  sent = source->send_udp_ipv4(
      *source_socket, destination_configuration.endpoint_address, 20000U,
      timeout_payload, &egress, collect, admit);
  if (sent.status != EndpointUdpSendStatus::sent || egress.frames.size() < 2U)
    throw std::runtime_error("IPv4 timeout fixture was not fragmented");
  static_cast<void>(destination->receive(egress.frames.front(), 0U, false,
                                         now));
  const auto timeout = destination->service_maintenance(
      now + device_catalog::ipv4_reassembly_timeout);
  const auto timeout_icmp = timeout.count
                                ? packet::parse_icmp(timeout.frames.front())
                                : std::nullopt;
  if (timeout.count != 1U || !timeout_icmp || timeout_icmp->type != 11U ||
      timeout_icmp->code != 1U)
    throw std::runtime_error(
        "IPv4 endpoint omitted the required reassembly timeout error");

  // A checksum-valid datagram to an unbound unicast tuple returns RFC 792 type
  // 3 code 3. Corrupting the same payload must be dropped silently instead of
  // reflecting an error in response to malformed transport input.
  egress.frames.clear();
  sent = source->send_udp_ipv4(
      *source_socket, destination_configuration.endpoint_address, 20001U,
      probe_payload, &egress, collect, admit);
  if (sent.status != EndpointUdpSendStatus::sent || egress.frames.size() != 1U)
    throw std::runtime_error("IPv4 closed-port fixture did not send");
  const auto closed = destination->receive(egress.frames.front(), 0U, false,
                                           now);
  const auto closed_icmp =
      closed.count ? packet::parse_icmp(closed.frames.front()) : std::nullopt;
  if (closed.count != 1U || !closed_icmp || closed_icmp->type != 3U ||
      closed_icmp->code != 3U)
    throw std::runtime_error("IPv4 closed UDP port omitted ICMP code 3");

  egress.frames.clear();
  sent = source->send_udp_ipv4(
      *source_socket, destination_configuration.endpoint_address, 20001U,
      probe_payload, &egress, collect, admit);
  if (sent.status != EndpointUdpSendStatus::sent || egress.frames.size() != 1U)
    throw std::runtime_error("IPv4 checksum fixture did not send");
  egress.frames.front().bytes[42U] ^= 0xffU;
  const auto malformed = destination->receive(egress.frames.front(), 0U, false,
                                              now);
  if (malformed.count != 0U)
    throw std::runtime_error("IPv4 bad UDP checksum generated an ICMP reply");

  // The endpoint checkpoint carries the source ID and the new repository, not
  // the removed single-Frame accumulator. Binary checkpoint tests exercise the
  // same value through LabCheckpoint serialization.
  if (!source->configure_ike_udp() ||
      !source->ike_udp_socket(transport::IpFamily::ipv4, false) ||
      !source->ike_udp_socket(transport::IpFamily::ipv6, true))
    throw std::runtime_error("endpoint-owned IKE UDP listeners did not bind");
  NetworkCheckpointState checkpoint;
  source->checkpoint(checkpoint, now);
  if (checkpoint.endpoint.next_ipv4_identification <= 1U ||
      !checkpoint.ipv4_reassembly.empty() || !checkpoint.ike_udp.configured)
    throw std::runtime_error("IPv4 UDP source identity was not checkpointed");
  auto restored_source = std::make_unique<EndpointStack>();
  if (!restored_source->configure(source_configuration) ||
      !restored_source->restore(checkpoint, now) ||
      !restored_source->ike_udp_socket(transport::IpFamily::ipv4, true) ||
      !restored_source->ike_udp_socket(transport::IpFamily::ipv6, false))
    throw std::runtime_error("endpoint-owned IKE UDP listeners did not restore");
  NetworkCheckpointState restored_checkpoint;
  restored_source->checkpoint(restored_checkpoint, now);
  if (restored_checkpoint.endpoint.next_ipv4_identification !=
      checkpoint.endpoint.next_ipv4_identification)
    throw std::runtime_error("IPv4 source identity changed across restore");

  // A complete active/passive TCP open now crosses the same endpoint, ARP and
  // encoded frame path as UDP. No test-side TcpEndpoint peer call is used:
  // each state transition is driven solely by the frame returned from the
  // preceding endpoint owner.
  const auto listener = destination->listen_tcp(
      {.family = transport::IpFamily::ipv4,
       .ipv4 = destination_configuration.endpoint_address,
       .interface_id = destination_configuration.endpoint_interface_id,
       .port = 179U});
  if (!listener)
    throw std::runtime_error("IPv4 TCP listener was rejected");

  auto opened = source->connect_tcp(
      {.family = transport::IpFamily::ipv4,
       .interface_id = source_configuration.endpoint_interface_id},
      {.ipv4 = destination_configuration.endpoint_address, .port = 179U}, {},
      now);
  if (opened.status != EndpointTcpSendStatus::sent || !opened.socket ||
      !opened.emitted)
    throw std::runtime_error("IPv4 TCP active open did not emit SYN");
  const auto syn_ip = packet::parse_ipv4(opened.frame);
  const auto syn = syn_ip
                       ? packet::tcp::parse_ipv4(
                             opened.frame.view().subspan(
                                 packet::ethernet_header_octets +
                                 syn_ip->header_length,
                                 syn_ip->total_length - syn_ip->header_length),
                             syn_ip->source, syn_ip->destination)
                       : std::nullopt;
  if (!syn || (syn->flags & packet::tcp::syn) == 0U)
    throw std::runtime_error("IPv4 TCP active open emitted malformed SYN");

  const auto syn_ack = destination->receive(opened.frame, 0U,
                                             false, now);
  if (syn_ack.count != 1U)
    throw std::runtime_error("IPv4 TCP listener did not emit SYN-ACK");
  const auto final_ack = source->receive(syn_ack.frames.front(), 0U, false,
                                         now);
  if (final_ack.count != 1U ||
      source->tcp_state(*opened.socket) != transport::tcp::State::established)
    throw std::runtime_error("IPv4 TCP client did not establish");
  static_cast<void>(destination->receive(final_ack.frames.front(), 0U, false,
                                         now));
  const auto accepted = destination->accept_tcp(*listener);
  if (!accepted || destination->tcp_state(*accepted) !=
                       transport::tcp::State::established)
    throw std::runtime_error("IPv4 TCP passive child did not establish");

  std::array<std::uint8_t, 200U> tcp_payload{};
  for (std::size_t index = 0U; index < tcp_payload.size(); ++index)
    tcp_payload[index] = static_cast<std::uint8_t>(index * 29U + 7U);
  if (source->write_tcp(*opened.socket, tcp_payload, now) !=
      tcp_payload.size())
    throw std::runtime_error("IPv4 TCP stream write was truncated");
  const auto data = source->send_tcp(*opened.socket, true, now);
  if (data.status != EndpointTcpSendStatus::sent || !data.emitted)
    throw std::runtime_error("IPv4 TCP data did not enter packet path");

  // A checksum-valid code 4 must quote an admitted DF segment from this exact
  // TCB before it can change the path cache or SMSS. An MTU of 100 leaves 80
  // octets for the TCP header and application data.
  const auto tcp_pmtu = packet::icmp_fragmentation_needed(
      data.frame, destination_configuration.endpoint_mac,
      source_configuration.endpoint_mac,
      destination_configuration.endpoint_address,
      source_configuration.endpoint_address, 100U);
  if (!tcp_pmtu)
    throw std::runtime_error("IPv4 TCP PMTU fixture could not encode code 4");
  static_cast<void>(source->receive(*tcp_pmtu, 0U, false,
                                    now + std::chrono::milliseconds{1}));
  static_cast<void>(destination->receive(data.frame, 0U, false,
                                         now));
  std::array<std::uint8_t, tcp_payload.size()> read{};
  if (destination->read_tcp(*accepted, read, now) != read.size() ||
      read != tcp_payload)
    throw std::runtime_error("IPv4 TCP payload did not reach receive stream");

  const auto delayed_ack = destination->service_maintenance(
      now + std::chrono::milliseconds{200});
  if (delayed_ack.count != 1U)
    throw std::runtime_error("IPv4 TCP delayed ACK timer emitted no frame");
  static_cast<void>(source->receive(delayed_ack.frames.front(), 0U, false,
                                    now + std::chrono::milliseconds{200}));

  // Timestamps make this connection's TCP header 32 octets, so the validated
  // path limit yields a 48-octet SMSS. Inspecting emitted wire bytes verifies
  // the result at the actual packet path rather than through private state.
  if (source->write_tcp(*opened.socket, tcp_payload,
                        now + std::chrono::milliseconds{201}) !=
      tcp_payload.size())
    throw std::runtime_error("IPv4 TCP rejected data after PMTU reduction");
  const auto reduced_data = source->send_tcp(
      *opened.socket, true, now + std::chrono::milliseconds{201});
  const auto reduced_ip = reduced_data.emitted
                              ? packet::parse_ipv4(reduced_data.frame)
                              : std::nullopt;
  const auto reduced_tcp =
      reduced_ip
          ? packet::tcp::parse_ipv4(
                reduced_data.frame.view().subspan(
                    packet::ethernet_header_octets + reduced_ip->header_length,
                    reduced_ip->total_length - reduced_ip->header_length),
                reduced_ip->source, reduced_ip->destination)
          : std::nullopt;
  if (reduced_data.status != EndpointTcpSendStatus::sent || !reduced_tcp ||
      reduced_tcp->payload.empty() || reduced_tcp->payload.size() > 48U)
    throw std::runtime_error("IPv4 TCP ignored the validated path MTU");
  static_cast<void>(destination->receive(
      reduced_data.frame, 0U, false, now + std::chrono::milliseconds{201}));
  std::array<std::uint8_t, tcp_payload.size()> reduced_read{};
  const auto reduced_octets = destination->read_tcp(
      *accepted, reduced_read, now + std::chrono::milliseconds{202});
  if (reduced_octets != reduced_tcp->payload.size() ||
      !std::equal(reduced_read.begin(), reduced_read.begin() + reduced_octets,
                  tcp_payload.begin()))
    throw std::runtime_error("IPv4 TCP PMTU resegmentation changed stream bytes");
  const auto reduced_ack = destination->service_maintenance(
      now + std::chrono::milliseconds{401});
  if (reduced_ack.count != 1U)
    throw std::runtime_error("IPv4 TCP PMTU segment lost its delayed ACK");
  static_cast<void>(source->receive(reduced_ack.frames.front(), 0U, false,
                                    now + std::chrono::milliseconds{401}));

  // Normal close follows the wire state machine rather than deleting either
  // socket locally. FIN, ACK, the passive FIN and the final ACK each traverse
  // receive(), preserving FIN-WAIT and TIME-WAIT semantics in the endpoint.
  const auto client_fin = source->close_tcp(
      *opened.socket, now + std::chrono::milliseconds{501});
  if (client_fin.status != EndpointTcpSendStatus::sent ||
      !client_fin.emitted)
    throw std::runtime_error("IPv4 TCP active close emitted no FIN");
  const auto server_fin_ack = destination->receive(
      client_fin.frame, 0U, false,
      now + std::chrono::milliseconds{501});
  if (server_fin_ack.count != 1U)
    throw std::runtime_error("IPv4 TCP passive endpoint did not ACK FIN");
  static_cast<void>(source->receive(server_fin_ack.frames.front(), 0U, false,
                                    now + std::chrono::milliseconds{501}));
  const auto server_fin = destination->close_tcp(
      *accepted, now + std::chrono::milliseconds{502});
  if (server_fin.status != EndpointTcpSendStatus::sent ||
      !server_fin.emitted)
    throw std::runtime_error("IPv4 TCP passive close emitted no FIN");
  const auto client_last_ack = source->receive(
      server_fin.frame, 0U, false,
      now + std::chrono::milliseconds{502});
  if (client_last_ack.count != 1U ||
      source->tcp_state(*opened.socket) != transport::tcp::State::time_wait)
    throw std::runtime_error("IPv4 TCP active endpoint did not enter TIME-WAIT");
  static_cast<void>(destination->receive(
      client_last_ack.frames.front(), 0U, false,
      now + std::chrono::milliseconds{502}));
}
