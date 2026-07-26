// TCB tests exchange header values between independent client and server
// owners. They cover active, passive and simultaneous open, control-byte
// retransmission, normal close, TIME-WAIT and checkpoint continuation.

#include "router/tcp_control_block.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

router::packet::tcp::View view(const router::packet::tcp::Fields &fields) {
  return {.source_port = fields.source_port,
          .destination_port = fields.destination_port,
          .sequence = fields.sequence,
          .acknowledgment = fields.acknowledgment,
          .flags = fields.flags,
          .window = fields.window,
          .urgent_pointer = fields.urgent_pointer};
}

} // namespace

void tcp_control_block_tests() {
  using namespace std::chrono_literals;
  using namespace router::transport::tcp;
  using router::packet::tcp::ack;
  using router::packet::tcp::fin;
  using router::packet::tcp::rst;
  using router::packet::tcp::syn;

  const auto start = ControlBlock::Clock::time_point{10s};
  ControlBlock client{40000U, 443U, 65535U, 1460U};
  ControlBlock server{443U, 0U, 65535U, 1460U};
  static_cast<void>(server.passive_open());
  const auto client_syn = client.active_open(1000U, start);
  if (!client_syn.emit || client.state() != State::syn_sent ||
      client_syn.segment.flags != syn || client.send_next() != 1001U)
    throw std::runtime_error("TCP active OPEN did not publish one SYN");

  // A lost SYN is retransmitted only at the live one-second RFC 6298 deadline.
  if (client.service_deadline(start + 999ms).emit)
    throw std::runtime_error("TCP retransmitted a SYN before its RTO");
  const auto retransmitted_syn = client.service_deadline(start + 1s);
  if (!retransmitted_syn.emit ||
      retransmitted_syn.segment.sequence != client_syn.segment.sequence ||
      client.next_deadline() != start + 3s)
    throw std::runtime_error("TCP SYN retransmission lost sequence or backoff");

  const auto server_syn_ack =
      server.on_segment(view(retransmitted_syn.segment), 5000U, start + 1100ms);
  if (!server_syn_ack.emit || server.state() != State::syn_received ||
      server_syn_ack.segment.sequence != 5000U ||
      server_syn_ack.segment.acknowledgment != 1001U ||
      server_syn_ack.segment.flags != static_cast<std::uint8_t>(syn | ack))
    throw std::runtime_error("TCP passive OPEN did not publish SYN,ACK");

  const auto client_ack =
      client.on_segment(view(server_syn_ack.segment), 0U, start + 1200ms);
  if (!client_ack.emit || client_ack.event != ControlEvent::established ||
      client.state() != State::established ||
      client_ack.segment.acknowledgment != 5001U ||
      client_ack.segment.flags != ack)
    throw std::runtime_error("TCP client did not finish the three-way handshake");
  const auto server_established =
      server.on_segment(view(client_ack.segment), 0U, start + 1300ms);
  if (server_established.emit ||
      server_established.event != ControlEvent::established ||
      server.state() != State::established)
    throw std::runtime_error("TCP server did not accept the final ACK");

  // Data sequence space advances only after the stream owner confirms packet
  // admission and receive storage. This prevents either TCB from acknowledging
  // bytes that were dropped by a full queue or receive arena.
  if (!client.commit_sent_data(1001U, 5U))
    throw std::runtime_error("TCP TCB rejected committed stream bytes");
  constexpr std::array<std::uint8_t, 5> data{1U, 2U, 3U, 4U, 5U};
  auto data_view = view(client_ack.segment);
  data_view.source_port = 40000U;
  data_view.destination_port = 443U;
  data_view.sequence = 1001U;
  data_view.acknowledgment = 5001U;
  data_view.flags = ack;
  data_view.payload = data;
  if (server.on_segment(data_view, 0U, start + 1500ms).event !=
          ControlEvent::data_requires_stream_owner)
    throw std::runtime_error("TCP TCB consumed data without its stream owner");
  const auto data_ack = server.commit_received_data(
      1006U, 65530U, std::nullopt, start + 1500ms);
  if (!data_ack || !data_ack->emit ||
      data_ack->segment.acknowledgment != 1006U ||
      client.on_segment(view(data_ack->segment), 0U, start + 1600ms).emit)
    throw std::runtime_error("TCP stream commit did not synchronize sequence space");

  // Normal active close retains the initiator in TIME-WAIT for the full RFC
  // 9293 2*MSL interval while the passive closer leaves after its FIN ACK.
  const auto client_fin = client.close(start + 2s);
  if (!client_fin.emit || client.state() != State::fin_wait_1 ||
      client_fin.segment.flags != static_cast<std::uint8_t>(fin | ack))
    throw std::runtime_error("TCP active close did not send FIN,ACK");
  const auto server_fin_ack =
      server.on_segment(view(client_fin.segment), 0U, start + 2100ms);
  if (!server_fin_ack.emit || server.state() != State::close_wait ||
      server_fin_ack.event != ControlEvent::peer_closed ||
      server_fin_ack.segment.acknowledgment != 1007U)
    throw std::runtime_error("TCP peer FIN did not create CLOSE-WAIT");
  static_cast<void>(client.on_segment(view(server_fin_ack.segment), 0U,
                                      start + 2200ms));
  if (client.state() != State::fin_wait_2)
    throw std::runtime_error("TCP FIN acknowledgment did not enter FIN-WAIT-2");
  const auto server_fin = server.close(start + 3s);
  const auto client_final_ack =
      client.on_segment(view(server_fin.segment), 0U, start + 3100ms);
  if (!client_final_ack.emit || client.state() != State::time_wait ||
      client_final_ack.segment.acknowledgment != 5002U)
    throw std::runtime_error("TCP second FIN did not enter TIME-WAIT");
  const auto server_closed =
      server.on_segment(view(client_final_ack.segment), 0U, start + 3200ms);
  if (server_closed.event != ControlEvent::connection_closed ||
      server.state() != State::closed)
    throw std::runtime_error("TCP LAST-ACK did not close after FIN ACK");
  if (client.service_deadline(start + 3100ms + 239s).event !=
          ControlEvent::none ||
      client.service_deadline(start + 3100ms + 240s).event !=
          ControlEvent::connection_closed ||
      client.state() != State::closed)
    throw std::runtime_error("TCP TIME-WAIT did not last exactly 2*MSL");

  // Simultaneous open must remember that SYN-RECEIVED came from an active OPEN
  // so a reset closes rather than returning the endpoint to LISTEN.
  ControlBlock left{10000U, 10001U, 32768U, 1200U};
  ControlBlock right{10001U, 10000U, 32768U, 1200U};
  const auto left_syn = left.active_open(10U, start);
  const auto right_syn = right.active_open(20U, start);
  const auto left_syn_ack = left.on_segment(view(right_syn.segment), 0U, start);
  const auto right_syn_ack = right.on_segment(view(left_syn.segment), 0U, start);
  if (!left_syn_ack.emit || !right_syn_ack.emit ||
      left.state() != State::syn_received || right.state() != State::syn_received)
    throw std::runtime_error("TCP simultaneous open skipped SYN-RECEIVED");
  const auto left_done = left.on_segment(view(right_syn_ack.segment), 0U, start);
  const auto right_done = right.on_segment(view(left_syn_ack.segment), 0U, start);
  if (left_done.event != ControlEvent::established ||
      right_done.event != ControlEvent::established ||
      left.state() != State::established || right.state() != State::established)
    throw std::runtime_error("TCP simultaneous open did not establish both TCBs");

  // Payload plus FIN is split deliberately: the TCB validates the header and
  // ACK first, then the stream owner stores all bytes before committing FIN.
  const auto left_data_sequence = left.send_next();
  if (!left.commit_sent_data(left_data_sequence, 3U))
    throw std::runtime_error("TCP simultaneous flow rejected committed data");
  constexpr std::array<std::uint8_t, 3> final_data{7U, 8U, 9U};
  router::packet::tcp::View data_fin{
      .source_port = 10000U,
      .destination_port = 10001U,
      .sequence = left_data_sequence,
      .acknowledgment = right.send_next(),
      .flags = static_cast<std::uint8_t>(ack | fin),
      .window = 32768U,
      .payload = final_data};
  if (right.on_segment(data_fin, 0U, start).event !=
          ControlEvent::data_requires_stream_owner)
    throw std::runtime_error("TCP payload plus FIN bypassed receive storage");
  const auto data_fin_ack = right.commit_received_data(
      right.receive_next() + 3U, 32765U,
      left_data_sequence + static_cast<std::uint32_t>(final_data.size()), start);
  if (!data_fin_ack || data_fin_ack->event != ControlEvent::peer_closed ||
      right.state() != State::close_wait ||
      data_fin_ack->segment.acknowledgment != left_data_sequence + 4U)
    throw std::runtime_error("TCP committed FIN before or after the wrong byte");

  // An in-window but non-exact reset is challenged. Only RST at RCV.NXT may
  // destroy synchronized state under RFC 5961 processing.
  router::packet::tcp::Fields blind_reset{
      .source_port = 10001U,
      .destination_port = 10000U,
      .sequence = left.receive_next() + 1U,
      .flags = rst};
  const auto challenge = left.on_segment(view(blind_reset), 0U, start);
  if (!challenge.emit || challenge.segment.flags != ack ||
      left.state() != State::established)
    throw std::runtime_error("TCP accepted a blind in-window reset");
  blind_reset.sequence = left.receive_next();
  if (left.on_segment(view(blind_reset), 0U, start).event !=
          ControlEvent::connection_reset ||
      left.state() != State::closed)
    throw std::runtime_error("TCP ignored an exact synchronized reset");

  // Active control retransmission state must continue from its remaining real
  // deadline after checkpoint restore rather than restarting at a full RTO.
  ControlBlock pending{20000U, 20001U, 4096U, 1000U};
  static_cast<void>(pending.active_open(99U, start));
  const auto saved = pending.checkpoint(start + 400ms);
  ControlBlock restored{1U, 1U, 1U, 1U};
  const auto restored_at = start + 10s;
  if (!restored.restore(saved, restored_at) ||
      restored.service_deadline(restored_at + 599ms).emit ||
      !restored.service_deadline(restored_at + 600ms).emit)
    throw std::runtime_error("TCP TCB checkpoint reset its control deadline");

  // The connection option owner decodes the 16-bit advertised field after
  // negotiation. Supplying that value must update the TCB without changing the
  // packet view or losing a scaled receive window above 65535 octets.
  ControlBlock scaled_client{30000U, 443U, 4U * 1024U * 1024U, 1460U};
  ControlBlock scaled_server{443U, 0U, 4U * 1024U * 1024U, 1460U};
  static_cast<void>(scaled_server.passive_open());
  const auto scaled_syn = scaled_client.active_open(8000U, start);
  const auto scaled_syn_ack =
      scaled_server.on_segment(view(scaled_syn.segment), 9000U, start);
  const auto scaled_ack =
      scaled_client.on_segment(view(scaled_syn_ack.segment), 0U, start);
  static_cast<void>(scaled_server.on_segment(view(scaled_ack.segment), 0U,
                                              start));
  auto scaled_window_update = view(scaled_ack.segment);
  scaled_window_update.source_port = 443U;
  scaled_window_update.destination_port = 30000U;
  scaled_window_update.sequence = scaled_client.receive_next();
  scaled_window_update.acknowledgment = scaled_client.send_next();
  scaled_window_update.window = 32768U;
  static_cast<void>(scaled_client.on_segment(scaled_window_update, 0U, start,
                                             4U * 1024U * 1024U));
  const auto scaled_checkpoint = scaled_client.checkpoint(start);
  if (scaled_checkpoint.send_window != 4U * 1024U * 1024U)
    throw std::runtime_error("TCP TCB truncated a decoded scaled window");
}
