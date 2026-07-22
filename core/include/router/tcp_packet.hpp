// Allocation-free TCP wire codec shared by IPv4 and IPv6 endpoint owners.
// The caller owns segment storage, address selection and connection state.
// This module owns no sockets, retransmission timers, queues or mutable state.

#pragma once

#include "router/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::tcp {

inline constexpr std::size_t minimum_header_octets = 20U;
inline constexpr std::size_t maximum_header_octets = 60U;
inline constexpr std::size_t maximum_option_octets = 40U;
inline constexpr std::size_t maximum_ipv4_segment_octets =
    maximum_ipv4_datagram_octets - 20U;
inline constexpr std::size_t maximum_ipv6_segment_octets =
    maximum_ipv6_payload_octets;

// RFC 9293 assigns the low eight control bits in their wire order. Keeping the
// representation integral preserves combinations without manufacturing an
// enum value for every legal set of flags.
enum Flag : std::uint8_t {
  fin = 0x01U,
  syn = 0x02U,
  rst = 0x04U,
  psh = 0x08U,
  ack = 0x10U,
  urg = 0x20U,
  ece = 0x40U,
  cwr = 0x80U,
};

struct Fields {
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  std::uint32_t sequence{};
  std::uint32_t acknowledgment{};
  std::uint8_t flags{};
  // The window is deliberately unsigned. RFC 9293 MUST-1 forbids treating the
  // 16-bit wire value as signed even before window scaling is negotiated.
  std::uint16_t window{};
  std::uint16_t urgent_pointer{};
};

struct View {
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  std::uint32_t sequence{};
  std::uint32_t acknowledgment{};
  std::uint8_t flags{};
  std::uint16_t window{};
  std::uint16_t urgent_pointer{};
  std::uint16_t checksum{};
  // Both spans borrow the parser input and become invalid when its owner
  // releases or mutates that storage. Options includes zero header padding.
  std::span<const std::uint8_t> options{};
  std::span<const std::uint8_t> payload{};
};

struct OptionView {
  std::uint8_t kind{};
  // raw includes Kind and Length for multi-octet options. EOL and NOP contain
  // their single kind octet. Unknown kinds remain available to higher layers.
  std::span<const std::uint8_t> raw{};
};

// Options supplied to the encoder need not include alignment padding. The
// encoder validates their internal lengths and pads the complete TCP header
// with zero EOL octets to a 32-bit boundary. Bytes after an explicit EOL must
// already be zero as required by RFC 9293 MUST-69.
[[nodiscard]] bool
validate_options(std::span<const std::uint8_t> options) noexcept;

// Iteration is allocation-free. cursor is advanced past the returned option.
// EOL advances to options.size(), because subsequent bytes are header padding,
// not independent EOL options. A null result means end or malformed input;
// callers that need to distinguish them first call validate_options().
[[nodiscard]] std::optional<OptionView>
next_option(std::span<const std::uint8_t> options,
            std::size_t &cursor) noexcept;

// Encoding writes exactly one TCP segment into caller-owned storage. It does
// not fragment IP or enqueue frames. Failure publishes no length and leaves
// output bytes unspecified. TCP checksum generation is never optional.
[[nodiscard]] std::optional<std::size_t>
encode_ipv4(std::span<std::uint8_t> output, Ipv4 source, Ipv4 destination,
            const Fields &fields, std::span<const std::uint8_t> options,
            std::span<const std::uint8_t> payload) noexcept;
[[nodiscard]] std::optional<std::size_t>
encode_ipv6(std::span<std::uint8_t> output, Ipv6 source, Ipv6 destination,
            const Fields &fields, std::span<const std::uint8_t> options,
            std::span<const std::uint8_t> payload) noexcept;

// Parsing rejects truncation, malformed options and a bad mandatory checksum.
// Reserved header bits are ignored on receive per RFC 9293, while encoders
// always generate them as zero.
[[nodiscard]] std::optional<View>
parse_ipv4(std::span<const std::uint8_t> bytes, Ipv4 source,
           Ipv4 destination) noexcept;
[[nodiscard]] std::optional<View>
parse_ipv6(std::span<const std::uint8_t> bytes, Ipv6 source,
           Ipv6 destination) noexcept;

} // namespace router::packet::tcp
