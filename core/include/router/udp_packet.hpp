// Allocation-free RFC 768 UDP wire codec for the emulator transport boundary.
// The caller owns datagram storage and address selection. This module owns no
// sockets, queues or timers and may depend only on packet-layer value types.

#pragma once

#include "router/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::udp {

inline constexpr std::size_t header_octets = 8U;
inline constexpr std::size_t maximum_datagram_octets = 65535U;
inline constexpr std::size_t maximum_payload_octets =
    maximum_datagram_octets - header_octets;
// A normal IPv4 datagram has a 16-bit Total Length that includes at least the
// 20-octet IPv4 header. With no IPv4 options, 65,507 application octets is the
// largest UDP payload that can exist in one original IPv4 datagram. IP
// fragmentation does not extend that original Total Length domain.
inline constexpr std::size_t maximum_ipv4_payload_octets =
    maximum_datagram_octets - 20U - header_octets;

struct View {
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  std::uint16_t checksum{};
  // payload borrows the caller's input span. It remains valid only while the
  // received packet storage remains owned by the parsing component.
  std::span<const std::uint8_t> payload{};
};

// Encoding writes a complete header and payload into caller-owned transport
// storage and returns its wire length. This codec does not equate a datagram
// with one link frame: the IP owner may fragment a legal 65535-octet datagram
// across as many frames as the selected path MTU requires. Failure leaves the
// caller-provided bytes unspecified and publishes no length.
[[nodiscard]] std::optional<std::size_t>
encode_ipv6(std::span<std::uint8_t> output, Ipv6 source, Ipv6 destination,
            std::uint16_t source_port, std::uint16_t destination_port,
            std::span<const std::uint8_t> payload) noexcept;

// IPv4 transmitters normally calculate the checksum. checksum_enabled exists
// only because RFC 768 assigns an all-zero field the explicit meaning that the
// sender generated no checksum. Receivers must therefore accept both forms.
[[nodiscard]] std::optional<std::size_t>
encode_ipv4(std::span<std::uint8_t> output, Ipv4 source, Ipv4 destination,
            std::uint16_t source_port, std::uint16_t destination_port,
            std::span<const std::uint8_t> payload,
            bool checksum_enabled = true) noexcept;

// Parsers require the UDP length to describe the complete supplied IP payload.
// This stage does not admit IPv6 jumbograms because every generated link MTU
// is below 65535 octets and a zero UDP length would be unreachable valid state.
[[nodiscard]] std::optional<View>
parse_ipv6(std::span<const std::uint8_t> bytes, Ipv6 source,
           Ipv6 destination) noexcept;
[[nodiscard]] std::optional<View>
parse_ipv4(std::span<const std::uint8_t> bytes, Ipv4 source,
           Ipv4 destination) noexcept;

} // namespace router::packet::udp
