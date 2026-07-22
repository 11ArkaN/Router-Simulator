// Endpoint IPv6 integration tests drive the private host stack through encoded
// Ethernet frames. The assertions prove that RA, Redirect, Neighbor Cache and
// Destination Cache ownership meet at the wire boundary without reading the
// attached router's state or installing a link-layer address directly.

#include "../src/network_endpoint.hpp"

#include "router/dhcpv6_client.hpp"
#include "router/dhcpv6_packet.hpp"
#include "router/dhcpv6_server.hpp"
#include "router/ip_address.hpp"

#include <algorithm>
#include <chrono>
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
} // namespace

void network_endpoint_ipv6_tests() {
  using namespace router;
  using namespace router::network_detail;
  using namespace std::chrono_literals;

  const auto parse = [](const char *text) {
    const auto value = ip::parse_ipv6(text);
    if (!value)
      throw std::runtime_error("endpoint IPv6 test address is invalid");
    return *value;
  };
  {
  const packet::Mac host_mac{0x02U, 0U, 0U, 0U, 0U, 0x10U};
  const packet::Mac router_mac{0x02U, 0U, 0U, 0U, 0U, 0x01U};
  const packet::Mac target_mac{0x02U, 0U, 0U, 0U, 0U, 0x02U};
  const auto router = parse("fe80::1");
  const auto target = parse("fe80::2");
  const auto remote = parse("2001:db8:ffff::20");
  const auto host_link_local = ip::link_local_from_mac(host_mac);

  NetworkEndpointConfiguration configuration{
      .endpoint_mac = host_mac,
      .endpoint_address = {192U, 0U, 2U, 2U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {192U, 0U, 2U, 1U},
      .endpoint_mtu = 1500U,
      .endpoint_interface_id = 41U,
      .endpoint_ipv6_autoconfiguration = true,
      .endpoint_transport_secret = transport_secret(41U)};
  EndpointStack endpoint;
  if (!endpoint.configure(configuration))
    throw std::runtime_error("endpoint IPv6 configuration was rejected");

  const auto start = EndpointStack::Clock::now();
  endpoint.set_link_state(true, start);
  // The first due turn transmits DAD NS. Only a later turn after RetransTimer
  // may promote the address, preserving the quiet interval required by RFC
  // 4862 instead of forcing preferred state from the test.
  static_cast<void>(endpoint.service_maintenance(start + 2s));
  static_cast<void>(endpoint.service_maintenance(start + 4s));

  packet::nd::RouterAdvertisementConfig ra_config;
  ra_config.router_lifetime_seconds = 1800U;
  const auto ra = packet::nd::router_advertisement(
      router_mac, router, packet::nd::all_nodes_multicast, ra_config);
  if (!ra)
    throw std::runtime_error("endpoint test RA encoding failed");
  static_cast<void>(endpoint.receive(*ra, 0U, false, start + 5s));

  // Redirect quotes the packet that caused it and arrives as a normal unicast
  // Ethernet frame. The endpoint may accept it only because the RA-installed
  // Default Router is the current first hop for this off-link destination.
  const auto invoking = packet::icmpv6_echo(host_mac, router_mac,
                                             host_link_local, remote, false,
                                             9U);
  const auto redirect = packet::nd::redirect(
      router_mac, host_mac, router, host_link_local, target, remote,
      target_mac, invoking);
  if (!redirect)
    throw std::runtime_error("endpoint test Redirect encoding failed");
  static_cast<void>(endpoint.receive(*redirect, 0U, false, start + 6s));

  // Bind a real host UDP socket, then checkpoint after receiving only the
  // final IPv6 fragment. Restore must retain both the socket handle generation
  // and the out-of-order reassembly gap before the first fragment arrives.
  const auto udp_socket = endpoint.bind_udp(
      {.family = transport::IpFamily::ipv6,
       .interface_id = configuration.endpoint_interface_id,
       .port = packet::dhcpv6::client_port});
  if (!udp_socket)
    throw std::runtime_error("endpoint UDP/546 binding was rejected");

  // A socket-originated maximum UDP datagram is fragmented by the host IP
  // owner, not rejected at the Ethernet Frame bound. DHCP uses much smaller
  // messages, but exercising the full path prevents its transport primitive
  // from acquiring a hidden protocol-specific size ceiling.
  const auto dhcp_servers = parse("ff02::1:2");
  std::vector<std::uint8_t> maximum_send_payload(
      packet::udp::maximum_payload_octets, 0x4eU);
  struct LocalEgressProbe {
    std::vector<packet::Frame> frames;
    std::size_t available{};
  } egress_probe;
  const auto collect_frame = [](void *context,
                                const packet::Frame &frame) noexcept {
    static_cast<LocalEgressProbe *>(context)->frames.push_back(frame);
    return true;
  };
  const auto admit_frames = [](void *context, std::size_t frames) noexcept {
    return frames <= static_cast<LocalEgressProbe *>(context)->available;
  };
  // A real unicast UDP packet crosses the endpoint source path before the
  // router returns an encoded PTB quoting it. The receiving stack must match
  // that quote to the socket and publish one consumable advisory error.
  egress_probe.available = 4U;
  constexpr std::array<std::uint8_t, 4U> unicast_payload{1U, 2U, 3U, 4U};
  const auto unicast_send = endpoint.send_udp_ipv6(
      *udp_socket, router, packet::dhcpv6::server_port, unicast_payload,
      &egress_probe, collect_frame, start + 6s, admit_frames);
  if (unicast_send.status != EndpointUdpSendStatus::sent ||
      egress_probe.frames.size() != 1U)
    throw std::runtime_error("endpoint ICMPv6 fixture UDP send failed");
  const auto ptb = packet::icmpv6_packet_too_big(
      egress_probe.frames.front(), router_mac, host_mac, router,
      host_link_local, packet::ipv6_minimum_link_mtu);
  if (!ptb)
    throw std::runtime_error("endpoint ICMPv6 PTB encoding failed");
  static_cast<void>(endpoint.receive(*ptb, 0U, false, start + 6100ms));
  const auto udp_error = endpoint.take_udp_network_error(*udp_socket);
  if (!udp_error ||
      udp_error->kind !=
          transport::Ipv6NetworkErrorKind::packet_too_big ||
      udp_error->parameter != packet::ipv6_minimum_link_mtu ||
      udp_error->remote != router ||
      endpoint.take_udp_network_error(*udp_socket))
    throw std::runtime_error(
        "endpoint did not correlate and consume the received UDP PTB");
  egress_probe.frames.clear();
  // A local queue that cannot hold the whole fragmented IP datagram must
  // reject it before the first frame. Retrying after a partial prefix would
  // duplicate fragments already visible on the Ethernet medium.
  egress_probe.available = 1U;
  const auto blocked_send = endpoint.send_udp_ipv6(
      *udp_socket, dhcp_servers, packet::dhcpv6::server_port,
      maximum_send_payload, &egress_probe, collect_frame, start + 6s,
      admit_frames);
  if (blocked_send.status != EndpointUdpSendStatus::output_backpressure ||
      !egress_probe.frames.empty())
    throw std::runtime_error(
        "endpoint published a partial UDP fragment batch under backpressure");
  egress_probe.available = packet::udp::maximum_datagram_octets;
  const auto send = endpoint.send_udp_ipv6(
      *udp_socket, dhcp_servers, packet::dhcpv6::server_port,
      maximum_send_payload, &egress_probe, collect_frame, start + 6s,
      admit_frames);
  if (send.status != EndpointUdpSendStatus::sent ||
      send.emitted_frames != egress_probe.frames.size() ||
      egress_probe.frames.size() < 2U)
    throw std::runtime_error(
        "endpoint UDP send retained a frame-sized datagram ceiling");
  packet::Ipv6ReassemblyTable send_reassembly;
  packet::Ipv6ReassemblyResult completed_send;
  for (std::size_t index = 0; index < egress_probe.frames.size(); ++index)
    completed_send = send_reassembly.accept(
        egress_probe.frames[index], start + 6s +
                                        std::chrono::milliseconds{index});
  const auto completed_ip = packet::parse_ipv6(completed_send.packet);
  const auto completed_udp =
      completed_ip
          ? packet::udp::parse_ipv6(
                completed_send.packet.subspan(
                    completed_ip->upper_layer_offset,
                    packet::udp::maximum_datagram_octets),
                completed_ip->source, completed_ip->destination)
          : std::nullopt;
  if (completed_send.status != packet::Ipv6ReassemblyStatus::complete ||
      !completed_ip || !completed_udp ||
      completed_udp->payload.size() != maximum_send_payload.size() ||
      completed_udp->payload.front() != 0x4eU ||
      completed_udp->payload.back() != 0x4eU)
    throw std::runtime_error(
        "endpoint UDP fragments did not reassemble into the sent datagram");
  constexpr std::size_t udp_payload_octets = 2000U;
  packet::Frame udp_packet;
  std::copy(host_mac.begin(), host_mac.end(), udp_packet.bytes.begin());
  std::copy(router_mac.begin(), router_mac.end(), udp_packet.bytes.begin() + 6U);
  udp_packet.bytes[12U] = 0x86U;
  udp_packet.bytes[13U] = 0xddU;
  udp_packet.bytes[14U] = 0x60U;
  const auto ipv6_payload_octets =
      packet::udp::header_octets + udp_payload_octets;
  udp_packet.bytes[18U] =
      static_cast<std::uint8_t>(ipv6_payload_octets >> 8U);
  udp_packet.bytes[19U] = static_cast<std::uint8_t>(ipv6_payload_octets);
  udp_packet.bytes[20U] = packet::ipv6_next_header_udp;
  udp_packet.bytes[21U] = 64U;
  std::copy(router.begin(), router.end(), udp_packet.bytes.begin() + 22U);
  std::copy(host_link_local.begin(), host_link_local.end(),
            udp_packet.bytes.begin() + 38U);
  std::vector<std::uint8_t> udp_payload(udp_payload_octets, 0x6dU);
  const auto encoded_udp = packet::udp::encode_ipv6(
      std::span<std::uint8_t>{udp_packet.bytes}.subspan(54U), router,
      host_link_local, packet::dhcpv6::server_port,
      packet::dhcpv6::client_port, udp_payload);
  if (!encoded_udp)
    throw std::runtime_error("endpoint UDP fixture encoding failed");
  udp_packet.length = static_cast<std::uint16_t>(54U + *encoded_udp);
  const auto fragments = packet::fragment_ipv6(
      udp_packet, packet::ipv6_minimum_link_mtu, 0x10203040U);
  if (!fragments || fragments->count != 2U)
    throw std::runtime_error("endpoint UDP fixture did not fragment");
  static_cast<void>(endpoint.receive(fragments->frames[1U], 0U, false,
                                     start + 7s));

  NetworkCheckpointState state;
  endpoint.checkpoint(state, start + 7s);
  if (state.ipv6.destinations.size() != 1U ||
      state.ipv6.destinations.front().destination != remote ||
      state.ipv6.destinations.front().next_hop != target ||
      state.ipv6.destinations.front().route_first_hop != router)
    throw std::runtime_error("Redirect did not update host Destination Cache");
  const auto learned_target = std::find_if(
      state.ipv6.neighbors.begin(), state.ipv6.neighbors.end(),
      [&](const auto &entry) { return entry.address == target; });
  if (learned_target == state.ipv6.neighbors.end() ||
      learned_target->mac != target_mac || !learned_target->is_router ||
      learned_target->state != lab::Ipv6NeighborState::stale)
    throw std::runtime_error("Redirect TLLA did not create STALE router neighbor");

  // Restore is validated against an independently configured owner. This
  // catches checkpoint formats that accidentally depend on vector indices,
  // process-local clock epochs or pointers retained from the source stack.
  EndpointStack restored;
  if (!restored.configure(configuration))
    throw std::runtime_error("restored endpoint configuration was rejected");
  restored.set_link_state(true, start + 10s);
  if (!restored.restore(state, start + 10s))
    throw std::runtime_error("endpoint IPv6 cache checkpoint did not restore");
  static_cast<void>(restored.receive(fragments->frames[0U], 0U, false,
                                     start + 11s));
  std::vector<std::uint8_t> received_udp(udp_payload.size());
  const auto udp_result = restored.receive_udp(*udp_socket, received_udp);
  if (udp_result.status != transport::UdpReceiveStatus::delivered ||
      udp_result.metadata.source_port != packet::dhcpv6::server_port ||
      udp_result.metadata.destination_port != packet::dhcpv6::client_port ||
      received_udp != udp_payload)
    throw std::runtime_error(
        "restored endpoint did not demultiplex reassembled UDP bytes");
  }

  // The complete DHCPv6 four-message exchange below crosses two independent
  // endpoint stacks as Ethernet, IPv6 and UDP bytes. The server must perform
  // real Neighbor Discovery before its first unicast Advertise, proving that
  // no direct client-to-server method call substitutes for the packet path.
  const packet::Mac client_mac{0x02U, 0U, 0U, 0U, 0U, 0x31U};
  const packet::Mac server_mac{0x02U, 0U, 0U, 0U, 0U, 0x32U};
  NetworkEndpointConfiguration client_endpoint_configuration{
      .endpoint_mac = client_mac,
      .endpoint_address = {198U, 51U, 100U, 2U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {198U, 51U, 100U, 1U},
      .endpoint_mtu = 1500U,
      .endpoint_interface_id = 301U,
      .endpoint_ipv6_autoconfiguration = true,
      .endpoint_transport_secret = transport_secret(51U)};
  NetworkEndpointConfiguration server_endpoint_configuration{
      .endpoint_mac = server_mac,
      .endpoint_address = {198U, 51U, 100U, 3U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {198U, 51U, 100U, 1U},
      .endpoint_mtu = 1500U,
      .endpoint_interface_id = 302U,
      .endpoint_ipv6_autoconfiguration = true,
      .endpoint_transport_secret = transport_secret(52U)};
  // Endpoint stacks own several bounded protocol tables. Put the two extra
  // integration peers on the heap so the Wasm test thread retains its normal
  // production-sized stack instead of hiding a stack-size dependency.
  auto client_endpoint = std::make_unique<EndpointStack>();
  auto server_endpoint = std::make_unique<EndpointStack>();
  if (!client_endpoint->configure(client_endpoint_configuration) ||
      !server_endpoint->configure(server_endpoint_configuration))
    throw std::runtime_error("DHCPv6 endpoint configuration failed");
  const auto exchange_start = EndpointStack::Clock::now();
  client_endpoint->set_link_state(true, exchange_start);
  server_endpoint->set_link_state(true, exchange_start);
  static_cast<void>(client_endpoint->service_maintenance(exchange_start + 2s));
  static_cast<void>(client_endpoint->service_maintenance(exchange_start + 4s));
  static_cast<void>(server_endpoint->service_maintenance(exchange_start + 2s));
  static_cast<void>(server_endpoint->service_maintenance(exchange_start + 4s));

  const auto dhcp_group = parse("ff02::1:2");
  const auto client_dhcp_socket = client_endpoint->bind_udp(
      {.family = transport::IpFamily::ipv6,
       .interface_id = client_endpoint_configuration.endpoint_interface_id,
       .port = packet::dhcpv6::client_port});
  const auto server_dhcp_socket = server_endpoint->bind_udp(
      {.family = transport::IpFamily::ipv6,
       .interface_id = server_endpoint_configuration.endpoint_interface_id,
       .port = packet::dhcpv6::server_port});
  if (!client_dhcp_socket || !server_dhcp_socket ||
      !server_endpoint->join_ipv6_multicast(dhcp_group,
                                            exchange_start + 4s))
    throw std::runtime_error("DHCPv6 sockets or multicast join failed");

  constexpr std::array<std::uint8_t, 7U> client_duid{0U, 3U, 0U, 1U,
                                                     0x31U, 0U, 1U};
  constexpr std::array<std::uint8_t, 7U> server_duid{0U, 3U, 0U, 1U,
                                                     0x32U, 0U, 1U};
  dhcpv6::ClientConfiguration dhcp_client_configuration{
      .duid_octets = static_cast<std::uint16_t>(client_duid.size()),
      .identity_associations = {
          {.iaid = 0x10203040U,
           .kind = dhcpv6::LeaseKind::non_temporary}},
      .requested_options = {},
      .rapid_commit = false};
  std::copy(client_duid.begin(), client_duid.end(),
            dhcp_client_configuration.duid.begin());
  for (std::size_t index = 0;
       index < dhcp_client_configuration.transaction_secret.size(); ++index)
    dhcp_client_configuration.transaction_secret[index] =
        static_cast<std::uint8_t>(0x40U + index);
  dhcpv6::ServerConfiguration dhcp_server_configuration{
      .duid_octets = static_cast<std::uint16_t>(server_duid.size()),
      .preference = 255U,
      .dns_recursive_servers = {},
      .solicit_maximum_retransmission_seconds = std::nullopt,
      .information_maximum_retransmission_seconds = std::nullopt};
  std::copy(server_duid.begin(), server_duid.end(),
            dhcp_server_configuration.duid.begin());
  auto pool_prefix = ip::parse_ipv6_prefix("2001:db8:301::/64");
  if (!pool_prefix)
    throw std::runtime_error("DHCPv6 endpoint pool prefix is invalid");
  dhcpv6::LeasePool dhcp_pool{
      .prefix = *pool_prefix,
      .preferred_lifetime_seconds = 3600U,
      .valid_lifetime_seconds = 7200U,
      .t1_seconds = 1800U,
      .t2_seconds = 2880U};
  for (std::size_t index = 0; index < dhcp_pool.allocation_secret.size();
       ++index)
    dhcp_pool.allocation_secret[index] =
        static_cast<std::uint8_t>(index + 1U);
  auto dhcp_client = std::make_unique<dhcpv6::Client>();
  auto dhcp_server = std::make_unique<dhcpv6::Server>();
  if (!dhcp_client->configure(dhcp_client_configuration) ||
      !dhcp_server->configure(dhcp_server_configuration,
                              std::span<const dhcpv6::LeasePool>{&dhcp_pool,
                                                                 1U},
                              {}, 1h) ||
      !dhcp_client->start(0x010203U, 0x6a09e667U,
                          exchange_start + 4s))
    throw std::runtime_error("DHCPv6 endpoint services failed to start");

  // Full UDP-sized protocol images are endpoint-service arenas in production.
  // Heap-backed vectors preserve the same lifetime in this test without
  // charging almost 200 KiB to the fixed Wasm call stack.
  std::vector<std::uint8_t> client_message(
      packet::dhcpv6::maximum_message_octets);
  std::vector<std::uint8_t> server_message(
      packet::dhcpv6::maximum_message_octets);
  std::vector<std::uint8_t> server_response(
      packet::dhcpv6::maximum_message_octets);
  std::vector<packet::Frame> wire;
  const auto collect_frame = [](void *context,
                                const packet::Frame &frame) noexcept {
    static_cast<std::vector<packet::Frame> *>(context)->push_back(frame);
    return true;
  };
  auto client_poll = dhcp_client->poll(client_message, exchange_start + 6s);
  if (client_poll.status != dhcpv6::ClientPollStatus::transmit)
    throw std::runtime_error("DHCPv6 client did not produce Solicit");
  auto client_send = client_endpoint->send_udp_ipv6(
      *client_dhcp_socket, dhcp_group, packet::dhcpv6::server_port,
      std::span<const std::uint8_t>{client_message}.first(
          client_poll.message_octets),
      &wire, collect_frame, exchange_start + 6s);
  if (client_send.status != EndpointUdpSendStatus::sent || wire.empty())
    throw std::runtime_error("DHCPv6 Solicit did not cross UDP");
  for (const auto &frame : wire)
    static_cast<void>(server_endpoint->receive(frame, 0U, false,
                                               exchange_start + 6s));
  wire.clear();
  auto server_receive =
      server_endpoint->receive_udp(*server_dhcp_socket, server_message);
  if (server_receive.status != transport::UdpReceiveStatus::delivered)
    throw std::runtime_error("DHCPv6 server did not receive Solicit");
  auto server_process = dhcp_server->process(
      std::span<const std::uint8_t>{server_message}.first(
          server_receive.metadata.payload_octets),
      server_response, exchange_start + 6s);
  if (server_process.status != dhcpv6::ServerProcessStatus::response)
    throw std::runtime_error("DHCPv6 server did not produce Advertise");

  // First unicast attempts Neighbor Discovery and emits an NS. Deliver its NA
  // response before retrying the unchanged Advertise payload.
  auto server_send = server_endpoint->send_udp_ipv6(
      *server_dhcp_socket, server_receive.metadata.source_ipv6,
      packet::dhcpv6::client_port,
      std::span<const std::uint8_t>{server_response}.first(
          server_process.message_octets),
      &wire, collect_frame, exchange_start + 6s);
  if (server_send.status !=
          EndpointUdpSendStatus::neighbor_resolution_started ||
      wire.size() != 1U)
    throw std::runtime_error(
        "DHCPv6 server Neighbor Discovery status " +
        std::to_string(static_cast<unsigned>(server_send.status)) +
        " frames " + std::to_string(wire.size()));
  auto neighbor_reply = client_endpoint->receive(
      wire.front(), 0U, false, exchange_start + 6s);
  if (neighbor_reply.count != 1U)
    throw std::runtime_error("DHCPv6 client did not answer Neighbor Solicitation");
  static_cast<void>(server_endpoint->receive(neighbor_reply.frames[0U], 0U,
                                             false, exchange_start + 6s));
  wire.clear();
  server_send = server_endpoint->send_udp_ipv6(
      *server_dhcp_socket, server_receive.metadata.source_ipv6,
      packet::dhcpv6::client_port,
      std::span<const std::uint8_t>{server_response}.first(
          server_process.message_octets),
      &wire, collect_frame, exchange_start + 6s);
  if (server_send.status != EndpointUdpSendStatus::sent || wire.empty())
    throw std::runtime_error("DHCPv6 Advertise did not cross resolved UDP");
  for (const auto &frame : wire)
    static_cast<void>(client_endpoint->receive(frame, 0U, false,
                                               exchange_start + 6s));
  wire.clear();
  auto client_receive =
      client_endpoint->receive_udp(*client_dhcp_socket, client_message);
  if (client_receive.status != transport::UdpReceiveStatus::delivered ||
      dhcp_client->ingest(
          std::span<const std::uint8_t>{client_message}.first(
              client_receive.metadata.payload_octets),
          exchange_start + 6s) != dhcpv6::ClientIngestStatus::accepted)
    throw std::runtime_error("DHCPv6 client did not accept Advertise");

  // Request and Reply reuse the learned neighbor and still traverse both UDP
  // queues. No repository method is invoked from the client side.
  client_poll = dhcp_client->poll(client_message, exchange_start + 6s);
  if (client_poll.status != dhcpv6::ClientPollStatus::transmit ||
      client_endpoint->send_udp_ipv6(
          *client_dhcp_socket, dhcp_group, packet::dhcpv6::server_port,
          std::span<const std::uint8_t>{client_message}.first(
              client_poll.message_octets),
          &wire, collect_frame, exchange_start + 6s)
              .status != EndpointUdpSendStatus::sent)
    throw std::runtime_error("DHCPv6 Request did not cross UDP");
  for (const auto &frame : wire)
    static_cast<void>(server_endpoint->receive(frame, 0U, false,
                                               exchange_start + 6s));
  wire.clear();
  server_receive =
      server_endpoint->receive_udp(*server_dhcp_socket, server_message);
  server_process = dhcp_server->process(
      std::span<const std::uint8_t>{server_message}.first(
          server_receive.metadata.payload_octets),
      server_response, exchange_start + 6s);
  if (server_receive.status != transport::UdpReceiveStatus::delivered ||
      server_process.status != dhcpv6::ServerProcessStatus::response ||
      server_endpoint->send_udp_ipv6(
          *server_dhcp_socket, server_receive.metadata.source_ipv6,
          packet::dhcpv6::client_port,
          std::span<const std::uint8_t>{server_response}.first(
              server_process.message_octets),
          &wire, collect_frame, exchange_start + 6s)
              .status != EndpointUdpSendStatus::sent)
    throw std::runtime_error("DHCPv6 Reply did not cross UDP");
  for (const auto &frame : wire)
    static_cast<void>(client_endpoint->receive(frame, 0U, false,
                                               exchange_start + 6s));
  client_receive =
      client_endpoint->receive_udp(*client_dhcp_socket, client_message);
  if (client_receive.status != transport::UdpReceiveStatus::delivered ||
      dhcp_client->ingest(
          std::span<const std::uint8_t>{client_message}.first(
              client_receive.metadata.payload_octets),
          exchange_start + 6s) != dhcpv6::ClientIngestStatus::accepted ||
      dhcp_client->state() != dhcpv6::ClientState::bound ||
      dhcp_client->leases().size() != 1U)
    throw std::runtime_error(
        "DHCPv6 wire exchange did not install the assigned lease");

  // Reuse the two independently owned link-local interfaces for a complete
  // IPv6 TCP handshake. The first active open cannot know the server MAC and
  // must therefore discard its staged SYN, emit NS, and retry only after the
  // encoded NA has crossed the reverse packet path.
  const auto tcp_listener = server_endpoint->listen_tcp(
      {.family = transport::IpFamily::ipv6,
       .ipv6 = server_endpoint->ipv6_link_local(),
       .interface_id =
           server_endpoint_configuration.endpoint_interface_id,
       .port = 53U});
  if (!tcp_listener)
    throw std::runtime_error("IPv6 TCP listener was rejected");
  auto tcp_open = client_endpoint->connect_tcp(
      {.family = transport::IpFamily::ipv6,
       .interface_id =
           client_endpoint_configuration.endpoint_interface_id},
      {.ipv6 = server_endpoint->ipv6_link_local(), .port = 53U}, {},
      exchange_start + 7s);
  if (tcp_open.status == EndpointTcpSendStatus::neighbor_resolution_started) {
    if (tcp_open.socket)
      throw std::runtime_error(
          "discarded IPv6 active open leaked a stale socket handle");
    const auto tcp_na = server_endpoint->receive(
        tcp_open.frame, 0U, false, exchange_start + 7s);
    if (tcp_na.count != 1U)
      throw std::runtime_error("IPv6 TCP neighbor did not answer NS");
    static_cast<void>(client_endpoint->receive(
        tcp_na.frames.front(), 0U, false, exchange_start + 7s));
    tcp_open = client_endpoint->connect_tcp(
        {.family = transport::IpFamily::ipv6,
         .interface_id =
             client_endpoint_configuration.endpoint_interface_id},
        {.ipv6 = server_endpoint->ipv6_link_local(), .port = 53U}, {},
        exchange_start + 7s);
  }
  if (tcp_open.status != EndpointTcpSendStatus::sent || !tcp_open.socket ||
      !tcp_open.emitted)
    throw std::runtime_error("IPv6 TCP SYN did not enter packet path");
  const auto tcp_syn_ack = server_endpoint->receive(
      tcp_open.frame, 0U, false, exchange_start + 7s);
  if (tcp_syn_ack.count != 1U)
    throw std::runtime_error("IPv6 TCP listener did not emit SYN-ACK");
  const auto tcp_ack = client_endpoint->receive(
      tcp_syn_ack.frames.front(), 0U, false, exchange_start + 7s);
  if (tcp_ack.count != 1U ||
      client_endpoint->tcp_state(*tcp_open.socket) !=
          transport::tcp::State::established)
    throw std::runtime_error("IPv6 TCP client did not establish");
  static_cast<void>(server_endpoint->receive(
      tcp_ack.frames.front(), 0U, false, exchange_start + 7s));
  const auto tcp_accepted = server_endpoint->accept_tcp(*tcp_listener);
  if (!tcp_accepted ||
      server_endpoint->tcp_state(*tcp_accepted) !=
          transport::tcp::State::established)
    throw std::runtime_error("IPv6 TCP passive child did not establish");
}
