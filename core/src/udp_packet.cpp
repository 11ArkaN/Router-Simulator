// RFC 768 UDP serialization and checksum validation. Address pseudo-headers
// are supplied by the IP owner, so the codec cannot bypass routing or retain
// mutable interface state.

#include "router/udp_packet.hpp"

#include <algorithm>

namespace router::packet::udp {
namespace {

[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
      bytes[offset + 1U]);
}

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  // UDP is network byte order even when the native Windows test build and the
  // Wasm runtime use different host representations for integer objects.
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] std::optional<std::size_t> encode_header_and_payload(
    std::span<std::uint8_t> output, std::uint16_t source_port,
    std::uint16_t destination_port,
    std::span<const std::uint8_t> payload) noexcept {
  if (payload.size() > maximum_payload_octets)
    return std::nullopt;
  const auto length = header_octets + payload.size();
  if (output.size() < length)
    return std::nullopt;
  auto bytes = output.first(length);
  write16(bytes, 0U, source_port);
  write16(bytes, 2U, destination_port);
  write16(bytes, 4U, static_cast<std::uint16_t>(length));
  write16(bytes, 6U, 0U);
  std::copy(payload.begin(), payload.end(), bytes.begin() + header_octets);
  return length;
}

[[nodiscard]] std::optional<View>
parse_shape(std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.size() < header_octets)
    return std::nullopt;
  const auto length = read16(bytes, 4U);
  // Requiring equality rejects both truncation and trailing bytes. At this
  // layer the caller already sliced exactly the IP upper-layer payload, so
  // neither condition can be interpreted as Ethernet padding.
  if (length < header_octets || length != bytes.size())
    return std::nullopt;
  return View{.source_port = read16(bytes, 0U),
              .destination_port = read16(bytes, 2U),
              .checksum = read16(bytes, 6U),
              .payload = bytes.subspan(header_octets)};
}

} // namespace

std::optional<std::size_t>
encode_ipv6(std::span<std::uint8_t> output, Ipv6 source, Ipv6 destination,
            std::uint16_t source_port, std::uint16_t destination_port,
            std::span<const std::uint8_t> payload) noexcept {
  const auto length = encode_header_and_payload(
      output, source_port, destination_port, payload);
  if (!length)
    return std::nullopt;
  auto bytes = output.first(*length);
  auto value = ipv6_upper_layer_checksum(source, destination,
                                         ipv6_next_header_udp, bytes);
  // RFC 768 transmits a computed zero as all ones. This distinction matters
  // for IPv6 because an actual all-zero checksum field is invalid.
  if (value == 0U)
    value = 0xffffU;
  write16(bytes, 6U, value);
  return length;
}

std::optional<std::size_t>
encode_ipv4(std::span<std::uint8_t> output, Ipv4 source, Ipv4 destination,
            std::uint16_t source_port, std::uint16_t destination_port,
            std::span<const std::uint8_t> payload,
            bool checksum_enabled) noexcept {
  // RFC 791 Total Length includes the minimum 20-octet IPv4 header. A larger
  // UDP payload could be represented by UDP's own length field but cannot be
  // carried by a standards-conforming non-jumbo IPv4 datagram, fragmented or
  // otherwise.
  if (payload.size() > maximum_ipv4_payload_octets)
    return std::nullopt;
  const auto length = encode_header_and_payload(
      output, source_port, destination_port, payload);
  if (!length)
    return std::nullopt;
  if (!checksum_enabled)
    return length;
  auto bytes = output.first(*length);
  auto value = ipv4_upper_layer_checksum(source, destination,
                                         ipv6_next_header_udp, bytes);
  if (value == 0U)
    value = 0xffffU;
  write16(bytes, 6U, value);
  return length;
}

std::optional<View> parse_ipv6(std::span<const std::uint8_t> bytes,
                               Ipv6 source, Ipv6 destination) noexcept {
  const auto result = parse_shape(bytes);
  // RFC 8200 section 8.1 makes the UDP checksum mandatory in normal IPv6
  // packets. The explicitly scoped tunnel exceptions do not apply to the
  // emulator's ordinary UDP socket contract.
  if (!result || result->checksum == 0U ||
      ipv6_upper_layer_checksum(source, destination, ipv6_next_header_udp,
                                bytes) != 0U)
    return std::nullopt;
  return result;
}

std::optional<View> parse_ipv4(std::span<const std::uint8_t> bytes,
                               Ipv4 source, Ipv4 destination) noexcept {
  const auto result = parse_shape(bytes);
  if (!result)
    return std::nullopt;
  // In IPv4, zero means the sender intentionally omitted the checksum. Any
  // nonzero field must validate over the pseudo-header and the full datagram.
  if (result->checksum != 0U &&
      ipv4_upper_layer_checksum(source, destination, ipv6_next_header_udp,
                                bytes) != 0U)
    return std::nullopt;
  return result;
}

} // namespace router::packet::udp
