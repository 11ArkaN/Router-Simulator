// Typed TCP option tests cover family defaults, negotiation symmetry, scaled
// windows, exact effective MSS, SACK parsing, timestamp echoing and PAWS.

#include "router/tcp_options.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

void tcp_options_tests() {
  using namespace router::transport::tcp;

  const auto local = make_syn_offer(1480U, 4U * 1024U * 1024U, true, true,
                                    true, 0x01020304U);
  if (!local || local->receive_mss != 1460U ||
      local->receive_window_shift != 7U)
    throw std::runtime_error("TCP SYN offer miscomputed MSS or window scale");
  std::array<std::uint8_t, 40> wire{};
  const auto wire_size = encode_syn_options(wire, *local);
  const auto typed = wire_size
                         ? parse_typed_options(
                               std::span<const std::uint8_t>{wire}.first(*wire_size))
                         : std::nullopt;
  if (!typed || typed->maximum_segment_size != 1460U ||
      typed->window_scale != 7U || !typed->sack_permitted ||
      typed->timestamp_value != 0x01020304U ||
      typed->timestamp_echo_reply != 0U)
    throw std::runtime_error("TCP typed SYN options changed wire values");

  const auto negotiated = negotiate_options(InternetFamily::ipv6, *local, *typed);
  if (!negotiated.window_scaling || negotiated.send_window_shift != 7U ||
      negotiated.receive_window_shift != 7U || !negotiated.timestamps ||
      !negotiated.sack || negotiated.send_mss != 1460U)
    throw std::runtime_error("TCP option handshake was not symmetric");
  if (decode_peer_window(32768U, false, negotiated) != 4194304U ||
      decode_peer_window(32768U, true, negotiated) != 32768U ||
      encode_receive_window(4194304U, false, negotiated) != 32768U ||
      encode_receive_window(4194304U, true, negotiated) != 65535U)
    throw std::runtime_error("TCP scaled a SYN window or lost true window");

  TypedOptions no_options{};
  const auto defaults = negotiate_options(InternetFamily::ipv6, *local, no_options);
  if (defaults.send_mss != 1220U || defaults.window_scaling ||
      defaults.timestamps || defaults.sack ||
      default_send_mss(InternetFamily::ipv4) != 536U)
    throw std::runtime_error("TCP did not use mandatory family MSS defaults");
  if (effective_send_mss(1460U, 1480U, 32U, 8U) != 1440U ||
      effective_send_mss(1460U, 30U, 32U, 0U) != 0U)
    throw std::runtime_error("TCP effective MSS ignored concrete headers");

  // Four blocks consume the largest standard SACK option. A wrapped block is
  // valid when its right edge follows its left edge in TCP serial arithmetic.
  constexpr std::array<std::uint8_t, 34> sacks{
      5U, 34U,
      0U, 0U, 0U, 10U, 0U, 0U, 0U, 20U,
      0U, 0U, 0U, 30U, 0U, 0U, 0U, 40U,
      0U, 0U, 0U, 50U, 0U, 0U, 0U, 60U,
      0xffU, 0xffU, 0xffU, 0xf0U, 0U, 0U, 0U, 4U};
  const auto parsed_sacks = parse_typed_options(sacks);
  if (!parsed_sacks || parsed_sacks->sack_block_count != 4U ||
      parsed_sacks->sack_blocks[3].right_edge != 4U)
    throw std::runtime_error("TCP SACK parser rejected valid serial wrap");
  auto invalid_sacks = sacks;
  invalid_sacks[6U] = 0U;
  invalid_sacks[7U] = 0U;
  invalid_sacks[8U] = 0U;
  invalid_sacks[9U] = 5U;
  if (parse_typed_options(invalid_sacks))
    throw std::runtime_error("TCP accepted a non-positive SACK block");
  std::array<std::uint8_t, 40> encoded_sacks{};
  const std::array<SackBlock, 2> sack_values{{{10U, 20U}, {30U, 40U}}};
  const auto encoded_sack_size = encode_sack_option(encoded_sacks, sack_values);
  const auto round_trip_sacks = encoded_sack_size
                                    ? parse_typed_options(
                                          std::span<const std::uint8_t>{
                                              encoded_sacks}
                                              .first(*encoded_sack_size))
                                    : std::nullopt;
  if (!round_trip_sacks || round_trip_sacks->sack_block_count != 2U ||
      round_trip_sacks->sack_blocks[1].left_edge != 30U)
    throw std::runtime_error("TCP SACK encoder changed receiver blocks");

  using Clock = TimestampState::Clock;
  const auto start = Clock::time_point{std::chrono::hours{1000}};
  TimestampState timestamps{true};
  timestamps.acknowledge_sent(100U);
  if (timestamps.accept(false, 500U, 90U, start) != TimestampAccept::accepted ||
      timestamps.echo_reply() != 500U ||
      timestamps.accept(false, std::nullopt, 90U, start) !=
          TimestampAccept::missing_required ||
      timestamps.accept(false, 499U, 90U, start + std::chrono::hours{1}) !=
          TimestampAccept::stale ||
      timestamps.accept(true, std::nullopt, 90U, start) !=
          TimestampAccept::accepted)
    throw std::runtime_error("TCP PAWS did not enforce timestamp negotiation");

  // TS.Recent must expire after 24 days, including across checkpoint restore.
  // The lower timestamp is then accepted and becomes the new echo value.
  const auto saved = timestamps.checkpoint(start + std::chrono::hours{2});
  TimestampState restored{};
  const auto restore_now = start + std::chrono::hours{3};
  if (!restored.restore(saved, restore_now) ||
      restored.accept(false, 400U, 90U,
                      restore_now + std::chrono::hours{24 * 24 + 1}) !=
          TimestampAccept::accepted ||
      restored.echo_reply() != 400U)
    throw std::runtime_error("TCP PAWS checkpoint froze a long-idle flow");

  const auto origin = Clock::time_point{std::chrono::seconds{10}};
  if (timestamp_value(origin + std::chrono::milliseconds{1234}, origin,
                      0xfffffff0U) != 0x000004c2U)
    throw std::runtime_error("TCP timestamp clock did not wrap modulo 32 bits");
  const auto timestamp_wire = encode_timestamp_option(1U, 2U);
  if (timestamp_wire[0] != 8U || timestamp_wire[1] != 10U ||
      timestamp_wire[5] != 1U || timestamp_wire[9] != 2U)
    throw std::runtime_error("TCP timestamp option used host byte order");

  auto syn_ack_offer = *local;
  syn_ack_offer.timestamp_echo_reply = 0xa1b2c3d4U;
  const auto syn_ack_size = encode_syn_options(wire, syn_ack_offer);
  const auto syn_ack_options = syn_ack_size
                                   ? parse_typed_options(
                                         std::span<const std::uint8_t>{wire}
                                             .first(*syn_ack_size))
                                   : std::nullopt;
  if (!syn_ack_options ||
      syn_ack_options->timestamp_echo_reply != 0xa1b2c3d4U)
    throw std::runtime_error("TCP SYN,ACK did not echo the peer timestamp");
}
