// RFC 9293 TCP header, option and checksum serialization. Connection state
// deliberately remains outside this wire module so a parser cannot mutate a
// TCB or bypass the endpoint owner that received the encoded IP packet.

#include "router/tcp_packet.hpp"

#include <algorithm>

namespace router::packet::tcp {
namespace {

[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
      bytes[offset + 1U]);
}

[[nodiscard]] std::uint32_t read32(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
         bytes[offset + 3U];
}

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  // Explicit network byte order keeps native Windows and Wasm builds wire
  // identical without relying on host representation or packed structs.
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] bool standard_length_is_valid(
    std::uint8_t kind, std::uint8_t length) noexcept {
  // Recognized option lengths come from RFC 9293, RFC 7323 and RFC 2018.
  // Unknown options retain the general RFC 9293 two-octet minimum so future
  // IANA assignments do not require a wire-codec release to cross the parser.
  switch (kind) {
  case 2U: // Maximum Segment Size
    return length == 4U;
  case 3U: // Window Scale
    return length == 3U;
  case 4U: // SACK Permitted
    return length == 2U;
  case 5U: // SACK: two header octets followed by one or more 8-byte blocks
    return length >= 10U && ((length - 2U) % 8U) == 0U;
  case 8U: // Timestamp Value and Timestamp Echo Reply
    return length == 10U;
  default:
    return length >= 2U;
  }
}

[[nodiscard]] std::optional<std::size_t> encode_shape(
    std::span<std::uint8_t> output, const Fields &fields,
    std::span<const std::uint8_t> options,
    std::span<const std::uint8_t> payload,
    std::size_t maximum_segment_octets) noexcept {
  if (!validate_options(options) || options.size() > maximum_option_octets)
    return std::nullopt;
  const auto padded_options = (options.size() + 3U) & ~std::size_t{3U};
  if (padded_options > maximum_option_octets)
    return std::nullopt;
  const auto header = minimum_header_octets + padded_options;
  if (payload.size() > maximum_segment_octets - header)
    return std::nullopt;
  const auto length = header + payload.size();
  if (output.size() < length)
    return std::nullopt;

  auto bytes = output.first(length);
  write16(bytes, 0U, fields.source_port);
  write16(bytes, 2U, fields.destination_port);
  write32(bytes, 4U, fields.sequence);
  write32(bytes, 8U, fields.acknowledgment);
  // The upper nibble is Data Offset in 32-bit words. Reserved bits are zero;
  // all currently assigned RFC 9293 control bits occupy the following octet.
  bytes[12U] = static_cast<std::uint8_t>((header / 4U) << 4U);
  bytes[13U] = fields.flags;
  write16(bytes, 14U, fields.window);
  write16(bytes, 16U, 0U);
  write16(bytes, 18U, fields.urgent_pointer);
  std::copy(options.begin(), options.end(), bytes.begin() + minimum_header_octets);
  std::fill(bytes.begin() + minimum_header_octets + options.size(),
            bytes.begin() + header, std::uint8_t{0});
  std::copy(payload.begin(), payload.end(), bytes.begin() + header);
  return length;
}

[[nodiscard]] std::optional<View>
parse_shape(std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.size() < minimum_header_octets)
    return std::nullopt;
  const auto header = static_cast<std::size_t>(bytes[12U] >> 4U) * 4U;
  if (header < minimum_header_octets || header > maximum_header_octets ||
      header > bytes.size())
    return std::nullopt;
  const auto options = bytes.subspan(minimum_header_octets,
                                     header - minimum_header_octets);
  if (!validate_options(options))
    return std::nullopt;
  return View{.source_port = read16(bytes, 0U),
              .destination_port = read16(bytes, 2U),
              .sequence = read32(bytes, 4U),
              .acknowledgment = read32(bytes, 8U),
              .flags = bytes[13U],
              .window = read16(bytes, 14U),
              .urgent_pointer = read16(bytes, 18U),
              .checksum = read16(bytes, 16U),
              .options = options,
              .payload = bytes.subspan(header)};
}

} // namespace

bool validate_options(std::span<const std::uint8_t> options) noexcept {
  std::size_t cursor{};
  while (cursor < options.size()) {
    const auto kind = options[cursor];
    if (kind == 0U) {
      // Once EOL appears, RFC 9293 MUST-69 permits only zero header padding.
      return std::all_of(options.begin() + cursor, options.end(),
                         [](std::uint8_t value) { return value == 0U; });
    }
    if (kind == 1U) {
      ++cursor;
      continue;
    }
    if (cursor + 2U > options.size())
      return false;
    const auto length = options[cursor + 1U];
    if (!standard_length_is_valid(kind, length) ||
        cursor + length > options.size())
      return false;
    cursor += length;
  }
  return true;
}

std::optional<OptionView>
next_option(std::span<const std::uint8_t> options,
            std::size_t &cursor) noexcept {
  if (cursor >= options.size())
    return std::nullopt;
  const auto kind = options[cursor];
  if (kind == 0U) {
    const auto start = cursor;
    cursor = options.size();
    return OptionView{.kind = kind, .raw = options.subspan(start, 1U)};
  }
  if (kind == 1U) {
    return OptionView{.kind = kind, .raw = options.subspan(cursor++, 1U)};
  }
  if (cursor + 2U > options.size())
    return std::nullopt;
  const auto length = options[cursor + 1U];
  if (!standard_length_is_valid(kind, length) ||
      cursor + length > options.size())
    return std::nullopt;
  const auto start = cursor;
  cursor += length;
  return OptionView{.kind = kind, .raw = options.subspan(start, length)};
}

std::optional<std::size_t>
encode_ipv4(std::span<std::uint8_t> output, Ipv4 source, Ipv4 destination,
            const Fields &fields, std::span<const std::uint8_t> options,
            std::span<const std::uint8_t> payload) noexcept {
  const auto length = encode_shape(output, fields, options, payload,
                                   maximum_ipv4_segment_octets);
  if (!length)
    return std::nullopt;
  auto bytes = output.first(*length);
  auto value = ipv4_upper_layer_checksum(source, destination,
                                         ipv6_next_header_tcp, bytes);
  write16(bytes, 16U, value);
  return length;
}

std::optional<std::size_t>
encode_ipv6(std::span<std::uint8_t> output, Ipv6 source, Ipv6 destination,
            const Fields &fields, std::span<const std::uint8_t> options,
            std::span<const std::uint8_t> payload) noexcept {
  const auto length = encode_shape(output, fields, options, payload,
                                   maximum_ipv6_segment_octets);
  if (!length)
    return std::nullopt;
  auto bytes = output.first(*length);
  auto value = ipv6_upper_layer_checksum(source, destination,
                                         ipv6_next_header_tcp, bytes);
  write16(bytes, 16U, value);
  return length;
}

std::optional<View> parse_ipv4(std::span<const std::uint8_t> bytes,
                               Ipv4 source, Ipv4 destination) noexcept {
  if (bytes.size() > maximum_ipv4_segment_octets ||
      ipv4_upper_layer_checksum(source, destination, ipv6_next_header_tcp,
                                bytes) != 0U)
    return std::nullopt;
  return parse_shape(bytes);
}

std::optional<View> parse_ipv6(std::span<const std::uint8_t> bytes,
                               Ipv6 source, Ipv6 destination) noexcept {
  if (bytes.size() > maximum_ipv6_segment_octets ||
      ipv6_upper_layer_checksum(source, destination, ipv6_next_header_tcp,
                                bytes) != 0U)
    return std::nullopt;
  return parse_shape(bytes);
}

} // namespace router::packet::tcp
