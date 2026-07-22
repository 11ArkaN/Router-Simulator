// Dynamic endpoint tests exchange raw checksum-valid TCP segments between two
// independent socket tables. No connection object, state pointer or direct
// protocol message crosses the endpoint boundary.

#include "router/tcp_endpoint.hpp"
#include "router/tcp_checkpoint_codec.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>

void tcp_endpoint_tests() {
  using namespace std::chrono_literals;
  using namespace router::transport;
  using namespace router::transport::tcp;

  router::crypto::Sha256Digest client_secret{};
  router::crypto::Sha256Digest server_secret{};
  for (std::size_t index = 0U; index < client_secret.size(); ++index) {
    client_secret[index] = static_cast<std::uint8_t>(index + 1U);
    server_secret[index] = static_cast<std::uint8_t>(0x80U + index);
  }
  const auto start = TcpEndpoint::Clock::time_point{100s};
  TcpEndpoint client{client_secret, start};
  TcpEndpoint server{server_secret, start};
  const router::packet::Ipv6 client_address{
      0x20U, 1U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U,    0U, 0U,    0U,   0U, 0U, 0U, 1U};
  const router::packet::Ipv6 server_address{
      0x20U, 1U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U,    0U, 0U,    0U,   0U, 0U, 0U, 2U};
  const SocketResources resources{.send_buffer_bytes = 8192U,
                                  .receive_buffer_bytes = 65536U,
                                  .transmission_records = 64U,
                                  .sack_ranges = 64U};
  const auto listener = server.listen(
      {.family = IpFamily::ipv6, .ipv6 = server_address, .port = 443U},
      2U, resources);
  if (!client.valid() || !server.valid() || !listener)
    throw std::runtime_error("TCP endpoint rejected valid owner resources");

  // Full-size wire arenas let this endpoint-level fixture exercise several
  // distinct SMSS segments. A smaller array would make the encoder, rather
  // than congestion control or SACK recovery, become the artificial limit.
  std::array<std::uint8_t, 2048> client_wire{};
  std::array<std::uint8_t, 2048> server_wire{};
  const auto syn = client.prepare_connect(
      {.family = IpFamily::ipv6, .ipv6 = client_address},
      {.ipv6 = server_address, .port = 443U}, 1000U, client_wire, resources,
      start);
  if (syn.status != EndpointPrepareStatus::prepared || !syn.segment.emit ||
      !client.commit(syn.segment, start) ||
      client.state(syn.segment.socket) != State::syn_sent)
    throw std::runtime_error("TCP endpoint did not admit active SYN");

  const auto syn_ack = server.ingest_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(syn.segment.octets),
      client_address, server_address, 1U, 1000U, server_wire, start + 10ms);
  if (syn_ack.status != EndpointPrepareStatus::prepared ||
      !syn_ack.segment.emit || !server.commit(syn_ack.segment, start + 10ms) ||
      server.state(syn_ack.segment.socket) != State::syn_received)
    throw std::runtime_error("TCP listener did not admit encoded SYN,ACK");

  const auto final_ack = client.ingest_ipv6(
      std::span<const std::uint8_t>{server_wire}.first(
          syn_ack.segment.octets),
      server_address, client_address, 1U, 1460U, client_wire, start + 20ms);
  if (final_ack.status != EndpointPrepareStatus::prepared ||
      !final_ack.segment.emit ||
      !client.commit(final_ack.segment, start + 20ms) ||
      client.state(syn.segment.socket) != State::established)
    throw std::runtime_error("TCP endpoint active open did not establish");
  const auto server_established = server.ingest_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          final_ack.segment.octets),
      client_address, server_address, 1U, 1460U, server_wire, start + 30ms);
  const auto accepted = server.accept(*listener);
  if (server_established.status != EndpointPrepareStatus::state_changed ||
      !accepted || *accepted != syn_ack.segment.socket ||
      server.state(*accepted) != State::established)
    throw std::runtime_error("TCP endpoint backlog did not deliver child socket");

  constexpr std::array<std::uint8_t, 7> application{
      'e', 'm', 'u', 'l', 'a', 't', 'e'};
  if (client.write(syn.segment.socket, application, start + 40ms) !=
      application.size())
    throw std::runtime_error("TCP endpoint did not buffer stream bytes");
  const auto data = client.prepare_data(syn.segment.socket, client_wire, true,
                                        start + 40ms);
  if (!data.segment.emit || !client.commit(data.segment, start + 40ms))
    throw std::runtime_error("TCP endpoint did not admit stream segment");
  const auto data_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(data.segment.octets),
      client_address, server_address);
  if (!data_view ||
      client.report_ipv6_error(
          client_address, server_address, 1U, data_view->source_port,
          data_view->destination_port, data_view->sequence + 100000U,
          Ipv6NetworkErrorKind::packet_too_big,
          router::packet::icmpv6_packet_too_big_type, 0U, 1280U) ||
      !client.report_ipv6_error(
          client_address, server_address, 1U, data_view->source_port,
          data_view->destination_port, data_view->sequence,
          Ipv6NetworkErrorKind::packet_too_big,
          router::packet::icmpv6_packet_too_big_type, 0U, 1280U))
    throw std::runtime_error(
        "TCP ICMPv6 correlation accepted the wrong sequence or lost the exact one");
  const auto received = server.ingest_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(data.segment.octets),
      client_address, server_address, 1U, 1460U, server_wire, start + 50ms);
  if (received.status != EndpointPrepareStatus::no_action ||
      server.next_deadline(*accepted) != start + 250ms)
    throw std::runtime_error("TCP endpoint did not retain delayed ACK deadline");
  std::array<std::uint8_t, application.size()> output{};
  if (server.read(*accepted, output, start + 60ms) != application.size() ||
      output != application)
    throw std::runtime_error("TCP endpoint changed received stream bytes");
  const auto delayed_ack = server.prepare_deadline(*accepted, server_wire,
                                                    start + 250ms);
  if (!delayed_ack.segment.emit ||
      !server.commit(delayed_ack.segment, start + 250ms))
    throw std::runtime_error("TCP endpoint did not emit delayed ACK");
  if (client.ingest_ipv6(
          std::span<const std::uint8_t>{server_wire}.first(
              delayed_ack.segment.octets),
          server_address, client_address, 1U, 1460U, client_wire,
          start + 260ms)
          .status != EndpointPrepareStatus::no_action)
    throw std::runtime_error("TCP endpoint did not consume cumulative ACK");

  // RFC 6675 recovery is verified through the endpoint wire boundary, not by
  // calling the scoreboard directly. Four admitted data segments are created,
  // the first is deliberately withheld by the modeled lower layer, and the
  // other three cross the peer parser and receiver. Their successive SACK
  // blocks provide the three duplicate acknowledgments needed to enter loss
  // recovery. No connection object or SACK range is shared between endpoints.
  // An IPv6 SMSS below 1096 octets receives the four-segment initial window
  // specified by RFC 5681 section 3.1. The payload is large enough to produce
  // four segments but remains within that legal initial congestion window.
  std::array<std::uint8_t, 3872> sack_payload{};
  for (std::size_t index = 0U; index < sack_payload.size(); ++index)
    sack_payload[index] = static_cast<std::uint8_t>(index * 37U + 11U);
  if (client.write(syn.segment.socket, sack_payload, start + 300ms) !=
      sack_payload.size())
    throw std::runtime_error("TCP endpoint could not queue SACK test flight");

  std::array<std::array<std::uint8_t, 2048>, 4> sack_frames{};
  std::array<std::size_t, sack_frames.size()> sack_frame_sizes{};
  for (std::size_t index = 0U; index < sack_frames.size(); ++index) {
    const auto prepared = client.prepare_data(
        syn.segment.socket, sack_frames[index], true,
        start + 300ms + std::chrono::milliseconds{index});
    if (!prepared.segment.emit ||
        !client.commit(prepared.segment,
                       start + 300ms + std::chrono::milliseconds{index}))
      throw std::runtime_error(
          "TCP endpoint did not admit SACK test segment index=" +
          std::to_string(index) + " status=" +
          std::to_string(static_cast<unsigned>(prepared.status)));
    sack_frame_sizes[index] = prepared.segment.octets;
  }
  const auto lost_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{sack_frames[0]}.first(
          sack_frame_sizes[0]),
      client_address, server_address);
  if (!lost_view || lost_view->payload.empty())
    throw std::runtime_error("TCP endpoint encoded an invalid lost segment");

  for (std::size_t index = 1U; index < sack_frames.size(); ++index) {
    const auto selective_ack = server.ingest_ipv6(
        std::span<const std::uint8_t>{sack_frames[index]}.first(
            sack_frame_sizes[index]),
        client_address, server_address, 1U, 1460U, server_wire,
        start + 310ms + std::chrono::milliseconds{index});
    if (!selective_ack.segment.emit ||
        !server.commit(selective_ack.segment,
                       start + 310ms + std::chrono::milliseconds{index}))
      throw std::runtime_error("TCP endpoint did not emit an admitted SACK");
    const auto consumed = client.ingest_ipv6(
        std::span<const std::uint8_t>{server_wire}.first(
            selective_ack.segment.octets),
        server_address, client_address, 1U, 1460U, client_wire,
        start + 320ms + std::chrono::milliseconds{index});
    if (consumed.status != EndpointPrepareStatus::no_action)
      throw std::runtime_error("TCP endpoint did not consume advisory SACK");
  }

  const auto repair = client.prepare_data(syn.segment.socket, client_wire,
                                          true, start + 330ms);
  const auto repair_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(repair.segment.octets),
      client_address, server_address);
  if (!repair.segment.emit || !repair_view ||
      repair_view->sequence != lost_view->sequence ||
      repair_view->payload.size() != lost_view->payload.size() ||
      !std::equal(repair_view->payload.begin(), repair_view->payload.end(),
                  lost_view->payload.begin()) ||
      !client.commit(repair.segment, start + 330ms))
    throw std::runtime_error("TCP endpoint did not retransmit the SACK hole");

  const auto cumulative_after_repair = server.ingest_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(repair.segment.octets),
      client_address, server_address, 1U, 1460U, server_wire, start + 340ms);
  if (!cumulative_after_repair.segment.emit ||
      !server.commit(cumulative_after_repair.segment, start + 340ms) ||
      client.ingest_ipv6(
          std::span<const std::uint8_t>{server_wire}.first(
              cumulative_after_repair.segment.octets),
          server_address, client_address, 1U, 1460U, client_wire,
          start + 350ms)
              .status != EndpointPrepareStatus::no_action)
    throw std::runtime_error("TCP endpoint did not finish SACK recovery");
  std::array<std::uint8_t, sack_payload.size()> recovered_payload{};
  if (server.read(*accepted, recovered_payload, start + 360ms) !=
          sack_payload.size() ||
      recovered_payload != sack_payload)
    throw std::runtime_error("TCP SACK recovery changed application bytes");

  // The table checkpoint retains stable handles, listener state, ISN secret,
  // socket arenas and connection timers. A segment awaiting lower admission
  // blocks the boundary, and a corrupt table is rejected transactionally.
  const auto client_checkpoint = client.checkpoint(start + 300ms);
  const auto server_checkpoint = server.checkpoint(start + 300ms);
  TcpEndpoint restored_client{{}, start + 1s};
  TcpEndpoint restored_server{{}, start + 1s};
  if (!client_checkpoint || !server_checkpoint)
    throw std::runtime_error("TCP endpoint refused a clean table checkpoint");
  const auto encoded_client = checkpoint::encode(*client_checkpoint);
  const auto encoded_server = checkpoint::encode(*server_checkpoint);
  const auto decoded_client =
      encoded_client ? checkpoint::decode(*encoded_client) : std::nullopt;
  const auto decoded_server =
      encoded_server ? checkpoint::decode(*encoded_server) : std::nullopt;
  if (!decoded_client || !decoded_server)
    throw std::runtime_error("TCP binary checkpoint codec rejected live state");
  if (!restored_client.restore(*decoded_client, start + 1s))
    throw std::runtime_error("TCP endpoint could not restore client table");
  if (!restored_server.restore(*decoded_server, start + 1s))
    throw std::runtime_error("TCP endpoint could not restore server table");
  if (restored_client.state(syn.segment.socket) != State::established ||
      restored_server.state(*accepted) != State::established ||
      !restored_server.local_binding(*listener))
    throw std::runtime_error("TCP endpoint restore changed stable handles");
  const auto restored_error =
      restored_client.take_network_error(syn.segment.socket);
  if (!restored_error ||
      restored_error->kind != Ipv6NetworkErrorKind::packet_too_big ||
      restored_error->parameter != 1280U ||
      restored_error->remote != server_address ||
      restored_client.take_network_error(syn.segment.socket))
    throw std::runtime_error(
        "TCP checkpoint changed or duplicated its advisory error slot");
  if (restored_client.reduce_ipv6_path_mtu_for_path(server_address, 1U,
                                                    800U) != 1U)
    throw std::runtime_error(
        "TCP path PMTU notification did not reach the active IPv6 connection");
  auto corrupt_endpoint = *server_checkpoint;
  corrupt_endpoint.ephemeral_cursor = 1U;
  if (restored_server.restore(corrupt_endpoint, start + 1100ms) ||
      restored_server.state(*accepted) != State::established)
    throw std::runtime_error("TCP endpoint restore was not transactional");

  if (restored_client.write(syn.segment.socket, application,
                            start + 1200ms) != application.size())
    throw std::runtime_error("TCP restored socket rejected stream write");
  const auto pending_after_restore = restored_client.prepare_data(
      syn.segment.socket, client_wire, true, start + 1200ms);
  if (!pending_after_restore.segment.emit ||
      restored_client.checkpoint(start + 1200ms) ||
      !restored_client.discard(pending_after_restore.segment) ||
      !restored_client.checkpoint(start + 1200ms))
    throw std::runtime_error("TCP endpoint checkpoint captured pending output");
  const auto data_after_restore = restored_client.prepare_data(
      syn.segment.socket, client_wire, true, start + 1210ms);
  if (!data_after_restore.segment.emit ||
      !restored_client.commit(data_after_restore.segment, start + 1210ms))
    throw std::runtime_error("TCP restored socket did not admit stream data");
  if (restored_server.ingest_ipv6(
          std::span<const std::uint8_t>{client_wire}.first(
              data_after_restore.segment.octets),
          client_address, server_address, 1U, 1460U, server_wire,
          start + 1220ms)
          .status != EndpointPrepareStatus::no_action ||
      restored_server.read(*accepted, output, start + 1230ms) !=
          application.size() ||
      output != application)
    throw std::runtime_error("TCP restored endpoints changed stream delivery");

  // A closed tuple emits the exact RFC 9293 reset form without allocating a
  // socket or requiring a commit token because no mutable connection exists.
  std::array<std::uint8_t, 64> closed_syn{};
  const auto closed_syn_octets = router::packet::tcp::encode_ipv6(
      closed_syn, client_address, server_address,
      {.source_port = 60000U,
       .destination_port = 444U,
       .sequence = 123U,
       .flags = router::packet::tcp::syn,
       .window = 65535U},
      {}, {});
  const auto reset = closed_syn_octets
                         ? server.ingest_ipv6(
                               std::span<const std::uint8_t>{closed_syn}.first(
                                   *closed_syn_octets),
                               client_address, server_address, 1U, 1460U,
                               server_wire, start + 300ms)
                         : EndpointPrepareResult{};
  const auto reset_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{server_wire}.first(reset.segment.octets),
      server_address, client_address);
  if (reset.status != EndpointPrepareStatus::stateless_response ||
      reset.segment || !reset.segment.emit || !reset_view ||
      reset_view->flags != static_cast<std::uint8_t>(
                               router::packet::tcp::rst |
                               router::packet::tcp::ack))
    throw std::runtime_error("TCP closed port emitted an invalid reset");
}
