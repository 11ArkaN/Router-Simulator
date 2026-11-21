// ISO modulo-255 checksum arithmetic shared by link-state wire codecs. The
// caller owns all bytes; this module has no mutable state, allocation or shard
// affinity and depends only on standard value types.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::packet::iso {

struct ChecksumState {
  std::int32_t c0{};
  std::int32_t c1{};
};

// Source: iso.ospf.lsa_fletcher_checksum. RFC 905 Annex B defines the same
// modulo-255 arithmetic referenced by ISO 10589 7.3.11. A saved prefix state
// lets an originator seed calculation from its immutable configured system ID.
[[nodiscard]] inline ChecksumState
accumulate(std::span<const std::uint8_t> bytes,
           ChecksumState state = {}) noexcept {
  for (const auto byte : bytes) {
    state.c0 = (state.c0 + byte) % 255;
    state.c1 = (state.c1 + state.c0) % 255;
  }
  return state;
}

// Preconditions: bytes is the protected region, including checksum octets.
// Returns the mathematical verification result without interpreting a zero
// checksum or protocol-specific purge rules. No mutation or borrowed retention.
[[nodiscard]] inline bool
valid(std::span<const std::uint8_t> bytes) noexcept {
  const auto state = accumulate(bytes);
  return !bytes.empty() && state.c0 == 0 && state.c1 == 0;
}

// Preconditions: optional seed is the checksum state of exactly prefix_octets
// immutable bytes. On success only the two checksum octets change. Invalid
// bounds return false without mutation. The 16-bit length bound prevents signed
// multiplication overflow and matches the consumers' PDU/LSA length fields.
[[nodiscard]] inline bool
insert(std::span<std::uint8_t> bytes, std::size_t checksum_offset,
       std::size_t prefix_octets = 0U, ChecksumState seed = {}) noexcept {
  if (bytes.size() > 65535U || checksum_offset >= bytes.size() ||
      bytes.size() - checksum_offset < 2U || prefix_octets > checksum_offset ||
      seed.c0 < 0 || seed.c0 >= 255 || seed.c1 < 0 || seed.c1 >= 255)
    return false;
  bytes[checksum_offset] = 0U;
  bytes[checksum_offset + 1U] = 0U;
  const auto state = accumulate(bytes.subspan(prefix_octets), seed);
  const auto distance = static_cast<std::int32_t>(bytes.size() - checksum_offset - 1U);
  auto x = (distance * state.c0 - state.c1) % 255;
  if (x <= 0)
    x += 255;
  auto y = 510 - state.c0 - x;
  if (y > 255)
    y -= 255;
  bytes[checksum_offset] = static_cast<std::uint8_t>(x);
  bytes[checksum_offset + 1U] = static_cast<std::uint8_t>(y);
  return true;
}

} // namespace router::packet::iso
