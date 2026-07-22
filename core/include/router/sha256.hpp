// Allocation-free SHA-256 and HMAC-SHA-256 primitives used by deterministic
// protocol identifiers. This module owns no keys and performs no entropy
// generation. Callers retain ownership of every input byte and output digest.
// Higher protocol layers may depend on it, while it must not depend on packet,
// runtime, storage or UI state.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace router::crypto {

inline constexpr std::size_t sha256_digest_octets = 32U;
using Sha256Digest = std::array<std::uint8_t, sha256_digest_octets>;

// Sha256 is a short-lived value context. update preserves byte order exactly;
// finish consumes the current logical message and returns the FIPS 180-4
// digest. Copying a context copies no pointers or shared mutable state.
class Sha256 final {
public:
  Sha256() noexcept;

  void update(std::span<const std::uint8_t> input) noexcept;
  [[nodiscard]] Sha256Digest finish() noexcept;

private:
  void compress(const std::uint8_t *block) noexcept;

  std::array<std::uint32_t, 8U> state_{};
  std::array<std::uint8_t, 64U> block_{};
  std::uint64_t total_octets_{};
  std::size_t block_octets_{};
};

[[nodiscard]] Sha256Digest
sha256(std::span<const std::uint8_t> input) noexcept;

// HMAC accepts message segments so protocol callers can authenticate a typed
// tuple without concatenating it into a temporary heap allocation. Segment
// order is part of the message and empty segments are permitted.
[[nodiscard]] Sha256Digest hmac_sha256(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> message) noexcept;

} // namespace router::crypto
