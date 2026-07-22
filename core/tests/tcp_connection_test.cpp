// Encoded IPv4 and IPv6 TCP handshake tests. Independent connection owners
// exchange only checksum-valid segment bytes. Admission failure is represented
// by discard and must leave SYN sequence state and RTO completely untouched.

#include "router/tcp_connection.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>

namespace {
using router::transport::tcp::Connection;
using router::transport::tcp::ConnectionPrepareResult;

struct StreamStorage {
  static constexpr std::size_t maximum_receive = 1024U * 1024U;
  std::array<std::uint8_t, 4096> send{};
  std::array<std::uint8_t, maximum_receive> receive{};
  std::array<std::uint8_t, maximum_receive / 8U> bitmap{};
  std::array<std::uint8_t, 1460> scratch{};
  std::array<router::transport::tcp::TransmissionRecord, 64> history{};
  std::array<router::transport::tcp::SackRange, 64> sack{};
  std::array<router::transport::tcp::SackRange, 64> workspace{};

  router::transport::tcp::ConnectionStorage spans(
      std::size_t receive_capacity = maximum_receive) {
    return {.send_bytes = send,
            .receive_bytes = std::span<std::uint8_t>{receive}.first(
                receive_capacity),
            .receive_bitmap = std::span<std::uint8_t>{bitmap}.first(
                (receive_capacity + 7U) / 8U),
            .transmit_payload_scratch = scratch,
            .transmission_history = history,
            .sack_ranges = sack,
            .sack_workspace = workspace};
  }
};

void admit(Connection &connection, const ConnectionPrepareResult &prepared) {
  if (!prepared.segment || !connection.commit(prepared.segment))
    throw std::runtime_error("TCP fixture could not admit a prepared segment");
}
} // namespace

void tcp_connection_tests() {
  using namespace std::chrono_literals;
  using namespace router::transport::tcp;
  using router::packet::tcp::ack;
  using router::packet::tcp::syn;

  const auto start = Connection::Clock::time_point{100s};
  const router::packet::Ipv6 client_address{
      0x20U, 1U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U,    0U, 0U,    0U,   0U, 0U, 0U, 1U};
  const router::packet::Ipv6 server_address{
      0x20U, 1U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U,    0U, 0U,    0U,   0U, 0U, 0U, 2U};
  const ConnectionOptionPolicy policy{.maximum_transport_message = 1460U,
                                      .receive_capacity =
                                          StreamStorage::maximum_receive,
                                      .timestamp_offset = 0x10203040U};
  // Socket arenas are heap-backed just as they are in the runtime allocator.
  // Keeping multi-megabyte receive windows off the Wasm call stack is part of
  // the production ownership contract, not merely a test accommodation.
  auto client_storage = std::make_unique<StreamStorage>();
  auto server_storage = std::make_unique<StreamStorage>();
  Connection client{{.family = InternetFamily::ipv6,
                     .local_ipv6 = client_address,
                     .remote_ipv6 = server_address,
                     .local_port = 40000U,
                     .remote_port = 443U},
                    policy, client_storage->spans(), start};
  Connection server{{.family = InternetFamily::ipv6,
                     .local_ipv6 = server_address,
                     .remote_ipv6 = client_address,
                     .local_port = 443U,
                     .remote_port = 40000U},
                    policy, server_storage->spans(), start};
  if (!client.valid() || !server.valid() || !server.listen())
    throw std::runtime_error("TCP connection rejected a valid IPv6 tuple");

  std::array<std::uint8_t, 128> client_wire{};
  std::array<std::uint8_t, 128> server_wire{};
  const auto rejected_syn =
      client.prepare_active_open(1000U, client_wire, start);
  if (!rejected_syn.segment.emit || client.state() != State::closed ||
      !client.discard(rejected_syn.segment) || client.next_deadline())
    throw std::runtime_error("TCP staged SYN mutated state before admission");

  const auto syn_segment =
      client.prepare_active_open(1000U, client_wire, start);
  admit(client, syn_segment);
  if (client.state() != State::syn_sent ||
      client.next_deadline() != start + 1s)
    throw std::runtime_error("TCP admitted SYN did not start the control RTO");
  const auto parsed_syn = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          syn_segment.segment.octets),
      client_address, server_address);
  const auto syn_options = parsed_syn
                               ? parse_typed_options(parsed_syn->options)
                               : std::nullopt;
  if (!parsed_syn || parsed_syn->flags != syn || !syn_options ||
      !syn_options->timestamp_value ||
      syn_options->timestamp_echo_reply != 0U)
    throw std::runtime_error("TCP active SYN wire options were malformed");

  const auto syn_ack_segment = server.prepare_ingress(
      std::span<const std::uint8_t>{client_wire}.first(
          syn_segment.segment.octets),
      5000U, server_wire, start + 10ms);
  admit(server, syn_ack_segment);
  const auto parsed_syn_ack = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{server_wire}.first(
          syn_ack_segment.segment.octets),
      server_address, client_address);
  const auto syn_ack_options = parsed_syn_ack
                                   ? parse_typed_options(
                                         parsed_syn_ack->options)
                                   : std::nullopt;
  if (!parsed_syn_ack ||
      parsed_syn_ack->flags != static_cast<std::uint8_t>(syn | ack) ||
      !syn_ack_options ||
      syn_ack_options->timestamp_echo_reply !=
          syn_options->timestamp_value)
    throw std::runtime_error("TCP SYN,ACK did not echo the SYN timestamp");

  const auto final_ack = client.prepare_ingress(
      std::span<const std::uint8_t>{server_wire}.first(
          syn_ack_segment.segment.octets),
      0U, client_wire, start + 20ms);
  admit(client, final_ack);
  const auto server_established = server.prepare_ingress(
      std::span<const std::uint8_t>{client_wire}.first(
          final_ack.segment.octets),
      0U, server_wire, start + 30ms);
  admit(server, server_established);
  if (client.state() != State::established ||
      server.state() != State::established ||
      !client.negotiated_options() ||
      !client.negotiated_options()->timestamps ||
      !client.negotiated_options()->window_scaling ||
      !client.negotiated_options()->sack)
    throw std::runtime_error("TCP encoded handshake lost negotiated options");

  // Stream bytes use the same prepare/commit rule as SYN. Discarding a fully
  // checksummed segment must make the identical sequence range available
  // again, while committing it advances sender and TCB sequence space once.
  constexpr std::array<std::uint8_t, 5> application{1U, 2U, 3U, 4U, 5U};
  if (client.write(application, start + 40ms) != application.size())
    throw std::runtime_error("TCP connection did not buffer application bytes");
  const auto rejected_data =
      client.prepare_data(client_wire, true, start + 40ms);
  const auto rejected_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          rejected_data.segment.octets),
      client_address, server_address);
  if (!rejected_view || rejected_view->sequence != 1001U ||
      rejected_view->payload.size() != application.size() ||
      !client.discard(rejected_data.segment))
    throw std::runtime_error("TCP discarded data did not preserve sequence state");
  const auto admitted_data =
      client.prepare_data(client_wire, true, start + 50ms);
  const auto admitted_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          admitted_data.segment.octets),
      client_address, server_address);
  if (!admitted_view || admitted_view->sequence != 1001U ||
      !client.commit(admitted_data.segment, start + 50ms))
    throw std::runtime_error("TCP admitted data changed the prepared sequence");

  // The server has already admitted the IP packet before this method runs, so
  // accepting stream bytes is not conditional on whether its outbound ACK can
  // enter a temporarily full lower queue. The first in-order data segment is
  // delayed for the profile's RFC 1122 ACK interval. A rejected delayed ACK
  // must remain due and be byte-identical when the queue becomes writable.
  const auto received_data = server.prepare_ingress(
      std::span<const std::uint8_t>{client_wire}.first(
          admitted_data.segment.octets),
      0U, server_wire, start + 60ms);
  if (received_data.status != ConnectionPrepareStatus::no_action ||
      server.next_deadline() != start + 260ms)
    throw std::runtime_error("TCP receiver did not schedule its delayed ACK");
  const auto early_ack = server.prepare_deadline(server_wire, start + 259ms);
  if (early_ack.status != ConnectionPrepareStatus::no_action)
    throw std::runtime_error("TCP delayed ACK fired before its real deadline");
  const auto rejected_ack = server.prepare_deadline(server_wire,
                                                     start + 260ms);
  if (!rejected_ack.segment.emit)
    throw std::runtime_error("TCP delayed ACK was not prepared at its deadline");
  const auto rejected_ack_octets = rejected_ack.segment.octets;
  std::array<std::uint8_t, 128> rejected_ack_wire{};
  std::copy_n(server_wire.begin(), rejected_ack_octets,
              rejected_ack_wire.begin());
  const auto rejected_ack_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{rejected_ack_wire}.first(
          rejected_ack_octets),
      server_address, client_address);
  if (!server.discard(rejected_ack.segment) ||
      server.next_deadline() != start + 260ms)
    throw std::runtime_error("TCP rejected ACK lost its retry deadline");
  const auto admitted_ack = server.prepare_deadline(server_wire,
                                                     start + 261ms);
  const auto admitted_ack_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{server_wire}.first(
          admitted_ack.segment.octets),
      server_address, client_address);
  if (!admitted_ack.segment.emit ||
      admitted_ack.segment.octets != rejected_ack_octets ||
      !rejected_ack_view || !admitted_ack_view ||
      rejected_ack_view->sequence != admitted_ack_view->sequence ||
      rejected_ack_view->acknowledgment !=
          admitted_ack_view->acknowledgment ||
      rejected_ack_view->window != admitted_ack_view->window ||
      !server.commit(admitted_ack.segment, start + 261ms) ||
      server.next_deadline())
    throw std::runtime_error("TCP delayed ACK retry was not transactional");

  const auto accepted_ack = client.prepare_ingress(
      std::span<const std::uint8_t>{server_wire}.first(
          admitted_ack.segment.octets),
      0U, client_wire, start + 270ms);
  // A pure ACK has no lower-layer output to admit. Its cumulative progress is
  // therefore published while consuming the already admitted input packet and
  // correctly reports no outbound action rather than manufacturing a token.
  if (accepted_ack.status != ConnectionPrepareStatus::no_action ||
      accepted_ack.segment)
    throw std::runtime_error("TCP sender did not accept cumulative data ACK");
  std::array<std::uint8_t, application.size()> application_read{};
  if (server.read(application_read, start + 280ms) != application.size() ||
      application_read != application)
    throw std::runtime_error("TCP receive stream changed application bytes");

  // Drop one admitted data segment at the modeled network boundary. The
  // connection must sleep until the RFC 6298 RTO, regenerate the oldest
  // unacknowledged sequence range, retain the deadline after local queue
  // rejection, and apply exponential backoff only after actual admission.
  if (client.write(application, start + 300ms) != application.size())
    throw std::runtime_error("TCP retransmission fixture could not queue data");
  const auto lost_data = client.prepare_data(client_wire, true,
                                              start + 300ms);
  const auto lost_data_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          lost_data.segment.octets),
      client_address, server_address);
  if (!lost_data_view || lost_data_view->sequence != 1006U ||
      !client.commit(lost_data.segment, start + 300ms) ||
      client.next_deadline() != start + 1300ms)
    throw std::runtime_error("TCP data RTO did not start on admission");
  if (client.prepare_deadline(client_wire, start + 1299ms).status !=
      ConnectionPrepareStatus::no_action)
    throw std::runtime_error("TCP retransmitted before one complete RTO");
  const auto rejected_retransmission = client.prepare_deadline(
      client_wire, start + 1300ms);
  const auto rejected_retransmission_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          rejected_retransmission.segment.octets),
      client_address, server_address);
  if (!rejected_retransmission_view ||
      rejected_retransmission_view->sequence != 1006U ||
      !client.discard(rejected_retransmission.segment) ||
      client.next_deadline() != start + 1300ms)
    throw std::runtime_error("TCP rejected RTO repair changed sender state");
  const auto admitted_retransmission = client.prepare_deadline(
      client_wire, start + 1301ms);
  const auto admitted_retransmission_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          admitted_retransmission.segment.octets),
      client_address, server_address);
  if (!admitted_retransmission_view ||
      admitted_retransmission_view->sequence != 1006U ||
      admitted_retransmission_view->payload.size() != application.size() ||
      !client.commit(admitted_retransmission.segment, start + 1301ms) ||
      client.next_deadline() != start + 3301ms)
    throw std::runtime_error("TCP RTO repair did not back off after admission");

  // An active retransmission, unread receive arena, negotiated options and all
  // relative timers survive a cold checkpoint. Restore shifts monotonic
  // deadlines by downtime instead of treating browser suspension as network
  // time, and a prepared but unadmitted segment blocks checkpoint creation.
  const auto saved_client = client.checkpoint(start + 1500ms);
  if (!saved_client)
    throw std::runtime_error("TCP active connection refused a clean checkpoint");

  // A valid scaled-window update can close the peer window independently of
  // application data. Build that update with the negotiated timestamp and a
  // real IPv6 TCP checksum, then prove persist owns the connection indefinitely
  // without converting receiver flow control into path-loss failure.
  const auto last_data_options = admitted_retransmission_view
                                     ? parse_typed_options(
                                           admitted_retransmission_view->options)
                                     : std::nullopt;
  std::array<std::uint8_t, router::packet::tcp::maximum_option_octets>
      zero_window_options{};
  const auto zero_window_timestamp = encode_timestamp_option(
      timestamp_value(start + 1600ms, start, policy.timestamp_offset),
      last_data_options && last_data_options->timestamp_value
          ? *last_data_options->timestamp_value
          : 0U);
  std::copy(zero_window_timestamp.begin(), zero_window_timestamp.end(),
            zero_window_options.begin());
  const auto zero_window_ack_octets = router::packet::tcp::encode_ipv6(
      server_wire, server_address, client_address,
      {.source_port = 443U,
       .destination_port = 40000U,
       .sequence = 5001U,
       .acknowledgment = 1011U,
       .flags = ack,
       .window = 0U},
      std::span<const std::uint8_t>{zero_window_options}.first(
          zero_window_timestamp.size()),
      {});
  const auto closed_window = zero_window_ack_octets
                                 ? client.prepare_ingress(
                                       std::span<const std::uint8_t>{server_wire}
                                           .first(*zero_window_ack_octets),
                                       0U, client_wire, start + 1600ms)
                                 : ConnectionPrepareResult{};
  constexpr std::array<std::uint8_t, 1> probe_byte{0xa5U};
  if (!zero_window_ack_octets ||
      closed_window.status != ConnectionPrepareStatus::no_action ||
      client.write(probe_byte, start + 1600ms) != probe_byte.size() ||
      client.next_deadline() != start + 2600ms)
    throw std::runtime_error("TCP zero-window update did not start persist");
  if (client.prepare_deadline(client_wire, start + 2599ms).status !=
      ConnectionPrepareStatus::no_action)
    throw std::runtime_error("TCP persist probe fired before current RTO");
  const auto rejected_probe = client.prepare_deadline(client_wire,
                                                       start + 2600ms);
  const auto rejected_probe_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          rejected_probe.segment.octets),
      client_address, server_address);
  if (!rejected_probe_view || rejected_probe_view->sequence != 1011U ||
      rejected_probe_view->payload.size() != 1U ||
      !client.discard(rejected_probe.segment) ||
      client.next_deadline() != start + 2600ms)
    throw std::runtime_error("TCP rejected persist probe changed progress");
  const auto admitted_probe = client.prepare_deadline(client_wire,
                                                       start + 2601ms);
  if (!admitted_probe.segment.emit ||
      !client.commit(admitted_probe.segment, start + 2601ms) ||
      client.next_deadline() != start + 4601ms)
    throw std::runtime_error("TCP persist did not double after admission");
  const auto second_probe = client.prepare_deadline(client_wire,
                                                     start + 4601ms);
  const auto second_probe_view = router::packet::tcp::parse_ipv6(
      std::span<const std::uint8_t>{client_wire}.first(
          second_probe.segment.octets),
      client_address, server_address);
  if (!second_probe_view || second_probe_view->sequence != 1011U ||
      second_probe_view->payload.size() != 1U ||
      !client.commit(second_probe.segment, start + 4601ms) ||
      client.next_deadline() != start + 8601ms)
    throw std::runtime_error("TCP persist did not retransmit with backoff");

  auto restored_storage = std::make_unique<StreamStorage>();
  Connection restored_client{{.family = InternetFamily::ipv6,
                              .local_ipv6 = client_address,
                              .remote_ipv6 = server_address,
                              .local_port = 40000U,
                              .remote_port = 443U},
                             policy, restored_storage->spans(), start + 2000ms};
  if (!restored_client.restore(*saved_client, start + 2000ms) ||
      restored_client.state() != State::established ||
      restored_client.next_deadline() != start + 3801ms)
    throw std::runtime_error("TCP checkpoint changed active RTO progress");
  auto corrupt_client = *saved_client;
  corrupt_client.next_token = 0U;
  if (restored_client.restore(corrupt_client, start + 2100ms) ||
      restored_client.next_deadline() != start + 3801ms)
    throw std::runtime_error("TCP accepted a corrupt checkpoint transaction");
  const auto restored_pending = restored_client.prepare_deadline(
      client_wire, start + 3801ms);
  if (!restored_pending.segment.emit ||
      restored_client.checkpoint(start + 3801ms) ||
      !restored_client.discard(restored_pending.segment))
    throw std::runtime_error("TCP checkpoint captured an unadmitted segment");
  const auto restored_retransmission = restored_client.prepare_deadline(
      client_wire, start + 3802ms);
  const auto restored_retransmission_view =
      router::packet::tcp::parse_ipv6(
          std::span<const std::uint8_t>{client_wire}.first(
              restored_retransmission.segment.octets),
          client_address, server_address);
  if (!restored_retransmission_view ||
      restored_retransmission_view->sequence != 1006U ||
      restored_retransmission_view->payload.size() != application.size() ||
      !std::equal(restored_retransmission_view->payload.begin(),
                  restored_retransmission_view->payload.end(),
                  application.begin()))
    throw std::runtime_error("TCP checkpoint lost unacknowledged stream bytes");
  static_cast<void>(
      restored_client.discard(restored_retransmission.segment));

  // IPv4 uses the same state owner and option mechanics but a distinct
  // mandatory checksum pseudo-header. Exchanging one complete handshake proves
  // neither family bypasses the wire codec.
  const router::packet::Ipv4 left_address{192U, 0U, 2U, 1U};
  const router::packet::Ipv4 right_address{192U, 0U, 2U, 2U};
  auto left_storage = std::make_unique<StreamStorage>();
  auto right_storage = std::make_unique<StreamStorage>();
  Connection left{{.family = InternetFamily::ipv4,
                   .local_ipv4 = left_address,
                   .remote_ipv4 = right_address,
                   .local_port = 12000U,
                   .remote_port = 12001U},
                  {.maximum_transport_message = 1480U,
                   .receive_capacity = 65535U,
                   .timestamp_offset = 1U},
                  left_storage->spans(65535U), start};
  Connection right{{.family = InternetFamily::ipv4,
                    .local_ipv4 = right_address,
                    .remote_ipv4 = left_address,
                    .local_port = 12001U,
                    .remote_port = 12000U},
                   {.maximum_transport_message = 1480U,
                    .receive_capacity = 65535U,
                    .timestamp_offset = 2U},
                   right_storage->spans(65535U), start};
  static_cast<void>(right.listen());
  const auto left_syn = left.prepare_active_open(7U, client_wire, start);
  admit(left, left_syn);
  const auto right_syn_ack = right.prepare_ingress(
      std::span<const std::uint8_t>{client_wire}.first(left_syn.segment.octets),
      17U, server_wire, start);
  admit(right, right_syn_ack);
  const auto left_ack = left.prepare_ingress(
      std::span<const std::uint8_t>{server_wire}.first(
          right_syn_ack.segment.octets),
      0U, client_wire, start);
  admit(left, left_ack);
  const auto right_done = right.prepare_ingress(
      std::span<const std::uint8_t>{client_wire}.first(left_ack.segment.octets),
      0U, server_wire, start);
  admit(right, right_done);
  if (left.state() != State::established || right.state() != State::established)
    throw std::runtime_error("TCP IPv4 wire handshake did not establish");

  // Normal active close traverses FIN-WAIT-1, FIN-WAIT-2 and TIME-WAIT while
  // the peer traverses CLOSE-WAIT and LAST-ACK. Every FIN and ACK is a real
  // checksum-valid IPv4 segment, and TIME-WAIT expires after the generated
  // two-MSL interval rather than being deleted when the final ACK is sent.
  const auto left_fin = left.prepare_close(client_wire, start + 10ms);
  if (!left_fin.segment.emit ||
      !left.commit(left_fin.segment, start + 10ms) ||
      left.state() != State::fin_wait_1)
    throw std::runtime_error("TCP active close did not enter FIN-WAIT-1");
  const auto right_fin_ack = right.prepare_ingress(
      std::span<const std::uint8_t>{client_wire}.first(
          left_fin.segment.octets),
      0U, server_wire, start + 20ms);
  if (!right_fin_ack.segment.emit ||
      !right.commit(right_fin_ack.segment, start + 20ms) ||
      right.state() != State::close_wait)
    throw std::runtime_error("TCP passive close did not enter CLOSE-WAIT");
  const auto left_fin_accepted = left.prepare_ingress(
      std::span<const std::uint8_t>{server_wire}.first(
          right_fin_ack.segment.octets),
      0U, client_wire, start + 30ms);
  if (left_fin_accepted.status != ConnectionPrepareStatus::no_action ||
      left.state() != State::fin_wait_2)
    throw std::runtime_error("TCP FIN acknowledgment did not enter FIN-WAIT-2");
  const auto right_fin = right.prepare_close(server_wire, start + 40ms);
  if (!right_fin.segment.emit ||
      !right.commit(right_fin.segment, start + 40ms) ||
      right.state() != State::last_ack)
    throw std::runtime_error("TCP CLOSE-WAIT close did not enter LAST-ACK");
  const auto left_last_ack = left.prepare_ingress(
      std::span<const std::uint8_t>{server_wire}.first(
          right_fin.segment.octets),
      0U, client_wire, start + 50ms);
  if (!left_last_ack.segment.emit ||
      !left.commit(left_last_ack.segment, start + 50ms) ||
      left.state() != State::time_wait)
    throw std::runtime_error("TCP peer FIN did not enter TIME-WAIT");
  const auto right_closed = right.prepare_ingress(
      std::span<const std::uint8_t>{client_wire}.first(
          left_last_ack.segment.octets),
      0U, server_wire, start + 60ms);
  if (right_closed.status != ConnectionPrepareStatus::no_action ||
      right.state() != State::closed)
    throw std::runtime_error("TCP final ACK did not close LAST-ACK");
  const auto time_wait_due =
      start + 50ms + 2 * router::device_catalog::tcp_maximum_segment_lifetime;
  if (left.prepare_deadline(client_wire, time_wait_due - 1ms).status !=
          ConnectionPrepareStatus::no_action ||
      left.state() != State::time_wait)
    throw std::runtime_error("TCP TIME-WAIT expired before two MSL");
  const auto time_wait_expired = left.prepare_deadline(client_wire,
                                                        time_wait_due);
  if (time_wait_expired.segment.emit || !time_wait_expired.segment ||
      !left.commit(time_wait_expired.segment, time_wait_due) ||
      left.state() != State::closed)
    throw std::runtime_error("TCP TIME-WAIT did not close at two MSL");
}
