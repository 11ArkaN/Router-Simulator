// TCP MSS, Window Scale, Timestamp and SACK option mechanics. Wire parsing is
// delegated to the packet codec, while this unit applies handshake semantics,
// scaled-window arithmetic and PAWS using serial number comparisons.

#include "router/tcp_options.hpp"

#include "router/tcp_sequence.hpp"

#include <algorithm>

namespace router::transport::tcp {
namespace {

[[nodiscard]] std::uint16_t read16(
    std::span<const std::uint8_t> bytes, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1U]);
}

[[nodiscard]] std::uint32_t read32(
    std::span<const std::uint8_t> bytes, std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
         bytes[offset + 3U];
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

} // namespace

std::optional<TypedOptions>
parse_typed_options(std::span<const std::uint8_t> options) noexcept {
  if (!router::packet::tcp::validate_options(options))
    return std::nullopt;
  TypedOptions parsed{};
  std::size_t cursor{};
  while (const auto option = router::packet::tcp::next_option(options, cursor)) {
    const auto raw = option->raw;
    switch (option->kind) {
    case 0U:
    case 1U:
      break;
    case 2U:
      // A zero MSS is syntactically encodable but cannot describe a useful
      // receive segment. Treat it as absent so the family default is used.
      if (!parsed.maximum_segment_size) {
        const auto value = read16(raw, 2U);
        if (value != 0U)
          parsed.maximum_segment_size = value;
      }
      break;
    case 3U:
      if (!parsed.window_scale)
        parsed.window_scale = raw[2U];
      break;
    case 4U:
      parsed.sack_permitted = true;
      break;
    case 5U:
      for (std::size_t offset = 2U; offset < raw.size(); offset += 8U) {
        if (parsed.sack_block_count >= parsed.sack_blocks.size())
          return std::nullopt;
        const auto left = read32(raw, offset);
        const auto right = read32(raw, offset + 4U);
        if (!sequence::after(right, left))
          return std::nullopt;
        parsed.sack_blocks[parsed.sack_block_count++] = {left, right};
      }
      break;
    case 8U:
      if (!parsed.timestamp_value) {
        parsed.timestamp_value = read32(raw, 2U);
        parsed.timestamp_echo_reply = read32(raw, 6U);
      }
      break;
    default:
      // RFC 9293 MUST-6 requires an unknown well-formed option to be ignored.
      // The packet View still retains its raw bytes for capture inspection.
      break;
    }
  }
  return parsed;
}

std::optional<SynOptionOffer>
make_syn_offer(std::uint32_t maximum_transport_message,
               std::uint32_t receive_capacity, bool window_scale,
               bool timestamps, bool sack,
               std::uint32_t timestamp) noexcept {
  if (maximum_transport_message <= router::packet::tcp::minimum_header_octets ||
      receive_capacity == 0U || receive_capacity > 0x40000000U)
    return std::nullopt;
  const auto raw_mss = maximum_transport_message -
                       static_cast<std::uint32_t>(
                           router::packet::tcp::minimum_header_octets);
  // 65535 has special jumbogram meaning. The ordinary IPv6 codec currently
  // caps payload length, so this offer stays at the 16-bit ceiling and PMTUD
  // remains authoritative for every concrete packet.
  const auto mss = static_cast<std::uint16_t>(
      std::min<std::uint32_t>(raw_mss, 65535U));

  std::uint8_t shift{};
  if (window_scale) {
    // Choose the smallest exponent that can express the receive arena. This
    // retains the finest possible advertised-window granularity.
    while (shift < 14U && (receive_capacity >> shift) > 65535U)
      ++shift;
  }
  return SynOptionOffer{.receive_mss = mss,
                        .receive_window_shift = shift,
                        .offer_window_scale = window_scale,
                        .offer_timestamps = timestamps,
                        .offer_sack = sack,
                        .timestamp_value = timestamp,
                        .timestamp_echo_reply = 0U};
}

std::optional<std::size_t>
encode_syn_options(std::span<std::uint8_t> output,
                   const SynOptionOffer &offer) noexcept {
  if (offer.receive_mss == 0U || offer.receive_window_shift > 14U)
    return std::nullopt;
  const auto required = 4U + (offer.offer_sack ? 2U : 0U) +
                        (offer.offer_timestamps ? 10U : 0U) +
                        (offer.offer_window_scale ? 3U : 0U);
  if (required > output.size() ||
      required > router::packet::tcp::maximum_option_octets)
    return std::nullopt;
  std::size_t cursor{};
  output[cursor++] = 2U;
  output[cursor++] = 4U;
  output[cursor++] = static_cast<std::uint8_t>(offer.receive_mss >> 8U);
  output[cursor++] = static_cast<std::uint8_t>(offer.receive_mss);
  if (offer.offer_sack) {
    output[cursor++] = 4U;
    output[cursor++] = 2U;
  }
  if (offer.offer_timestamps) {
    const auto timestamp = encode_timestamp_option(
        offer.timestamp_value, offer.timestamp_echo_reply);
    std::copy(timestamp.begin(), timestamp.end(), output.begin() + cursor);
    cursor += timestamp.size();
  }
  if (offer.offer_window_scale) {
    output[cursor++] = 3U;
    output[cursor++] = 3U;
    output[cursor++] = offer.receive_window_shift;
  }
  return cursor;
}

NegotiatedOptions negotiate_options(InternetFamily family,
                                    const SynOptionOffer &local_offer,
                                    const TypedOptions &peer_syn) noexcept {
  const auto peer_shift = static_cast<std::uint8_t>(
      std::min<std::uint32_t>(peer_syn.window_scale.value_or(0U), 14U));
  const auto scaling = local_offer.offer_window_scale &&
                       peer_syn.window_scale.has_value();
  return {.send_mss = peer_syn.maximum_segment_size.value_or(
              static_cast<std::uint16_t>(default_send_mss(family))),
          .send_window_shift = static_cast<std::uint8_t>(
              scaling ? peer_shift : 0U),
          .receive_window_shift =
              static_cast<std::uint8_t>(
                  scaling ? local_offer.receive_window_shift : 0U),
          .window_scaling = scaling,
          .timestamps = local_offer.offer_timestamps &&
                        peer_syn.timestamp_value.has_value(),
          .sack = local_offer.offer_sack && peer_syn.sack_permitted};
}

std::uint32_t effective_send_mss(std::uint32_t negotiated_send_mss,
                                 std::uint32_t maximum_transport_message,
                                 std::uint32_t tcp_header_octets,
                                 std::uint32_t ip_option_octets) noexcept {
  if (negotiated_send_mss == 0U ||
      tcp_header_octets < router::packet::tcp::minimum_header_octets)
    return 0U;
  const auto peer_limit = static_cast<std::uint64_t>(negotiated_send_mss) +
                          router::packet::tcp::minimum_header_octets;
  const auto transport_limit = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(peer_limit, maximum_transport_message));
  const auto overhead = static_cast<std::uint64_t>(tcp_header_octets) +
                        ip_option_octets;
  return overhead >= transport_limit
             ? 0U
             : transport_limit - static_cast<std::uint32_t>(overhead);
}

std::uint32_t decode_peer_window(
    std::uint16_t wire_window, bool syn_segment,
    const NegotiatedOptions &options) noexcept {
  if (syn_segment || !options.window_scaling)
    return wire_window;
  return static_cast<std::uint32_t>(wire_window)
         << options.send_window_shift;
}

std::uint16_t encode_receive_window(
    std::uint32_t receive_window, bool syn_segment,
    const NegotiatedOptions &options) noexcept {
  const auto scaled = syn_segment || !options.window_scaling
                          ? receive_window
                          : receive_window >> options.receive_window_shift;
  return static_cast<std::uint16_t>(std::min(scaled, 65535U));
}

TimestampAccept TimestampState::accept(
    bool rst, std::optional<std::uint32_t> timestamp,
    std::uint32_t segment_sequence, Clock::time_point now) noexcept {
  if (!negotiated_ || rst)
    return TimestampAccept::accepted;
  if (!timestamp)
    return TimestampAccept::missing_required;

  if (recent_present_ && sequence::before(*timestamp, recent_)) {
    if (now - recent_updated_at_ <= maximum_recent_age)
      return TimestampAccept::stale;
    // After 24 days the saved comparison point is invalid. Accepting the new
    // value prevents PAWS from freezing a valid long-idle connection.
    recent_present_ = false;
  }
  if (!recent_present_ ||
      (!sequence::before(*timestamp, recent_) &&
       !sequence::after(segment_sequence, last_ack_sent_))) {
    recent_ = *timestamp;
    recent_updated_at_ = now;
    recent_present_ = true;
  }
  return TimestampAccept::accepted;
}

TimestampCheckpoint
TimestampState::checkpoint(Clock::time_point now) const noexcept {
  const auto age = recent_present_ && now >= recent_updated_at_
                       ? now - recent_updated_at_
                       : Clock::duration::zero();
  return {.recent = recent_,
          .last_ack_sent = last_ack_sent_,
          .recent_age_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(age).count(),
          .negotiated = negotiated_,
          .recent_present = recent_present_};
}

bool TimestampState::restore(const TimestampCheckpoint &state,
                             Clock::time_point now) noexcept {
  if (state.recent_age_nanoseconds < 0 ||
      (!state.recent_present && state.recent_age_nanoseconds != 0))
    return false;
  const auto age = std::chrono::nanoseconds{state.recent_age_nanoseconds};
  if (age > now.time_since_epoch())
    return false;
  recent_ = state.recent;
  last_ack_sent_ = state.last_ack_sent;
  negotiated_ = state.negotiated;
  recent_present_ = state.recent_present;
  recent_updated_at_ = now - age;
  return true;
}

std::uint32_t timestamp_value(
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::time_point origin,
    std::uint32_t connection_offset) noexcept {
  if (now < origin)
    return connection_offset;
  const auto ticks = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - origin)
                         .count();
  return connection_offset + static_cast<std::uint32_t>(ticks);
}

std::array<std::uint8_t, 10>
encode_timestamp_option(std::uint32_t value, std::uint32_t echo) noexcept {
  std::array<std::uint8_t, 10> bytes{8U, 10U};
  write32(bytes, 2U, value);
  write32(bytes, 6U, echo);
  return bytes;
}

std::optional<std::size_t>
encode_sack_option(std::span<std::uint8_t> output,
                   std::span<const SackBlock> blocks) noexcept {
  if (blocks.empty() || blocks.size() > 4U)
    return std::nullopt;
  const auto length = 2U + blocks.size() * 8U;
  if (output.size() < length)
    return std::nullopt;
  output[0U] = 5U;
  output[1U] = static_cast<std::uint8_t>(length);
  std::size_t cursor = 2U;
  for (const auto &block : blocks) {
    if (!sequence::after(block.right_edge, block.left_edge))
      return std::nullopt;
    write32(output, cursor, block.left_edge);
    write32(output, cursor + 4U, block.right_edge);
    cursor += 8U;
  }
  return length;
}

} // namespace router::transport::tcp
