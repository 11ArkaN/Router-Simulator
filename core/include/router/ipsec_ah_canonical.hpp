// RFC 4302 AH canonicalization for complete IPv4 and IPv6 packets. The first
// executable profile accepts base headers with AH immediately following them.
// Unsupported option or extension chains fail closed instead of authenticating
// an incorrectly normalized packet.

#pragma once

#include "router/ipsec_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ipsec::ah {

enum class CanonicalStatus : std::uint8_t {
  ok,
  malformed,
  output_too_small,
  fragmented,
  unsupported_header_chain,
  unsupported_icv_length
};

struct CanonicalResult {
  CanonicalStatus status{CanonicalStatus::malformed};
  std::size_t packet_octets{};
  AhView ah{};
};

// Output receives a complete canonical packet and may alias no input bytes.
// AH's transmitted ICV is replaced by zeros while immutable bytes retain
// canonical network order. The result view borrows the caller's output.
[[nodiscard]] CanonicalResult
canonicalize_ipv4(std::span<const std::uint8_t> packet,
                  std::span<std::uint8_t> output) noexcept;
[[nodiscard]] CanonicalResult
canonicalize_ipv6(std::span<const std::uint8_t> packet,
                  std::span<std::uint8_t> output) noexcept;

} // namespace router::ipsec::ah
