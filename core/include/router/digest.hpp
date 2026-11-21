// Segmented digest and HMAC contracts shared by routing protocol codecs.
// Callers own keys, messages and outputs. Each call owns temporary provider
// contexts and cleans key-derived storage before returning; no shared state.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::crypto {

enum class DigestAlgorithm : std::uint8_t { md5, sha1, sha256 };
enum class KeyNormalization : std::uint8_t { rfc2104, digest_length };

[[nodiscard]] constexpr std::size_t digest_octets(DigestAlgorithm algorithm) noexcept {
  switch (algorithm) {
  case DigestAlgorithm::md5: return 16U;
  case DigestAlgorithm::sha1: return 20U;
  case DigestAlgorithm::sha256: return 32U;
  }
  return 0U;
}

// Output must match the selected digest size. Invalid arguments or provider
// failure return false and leave output unchanged. Segments are processed in
// order without packet concatenation; output may alias an input. SHA-256 uses
// the allocation-free value implementation. Legacy hashes use local EVP
// contexts, so these functions belong on paced control paths, not forwarding.
[[nodiscard]] bool digest(DigestAlgorithm algorithm,
    std::span<const std::span<const std::uint8_t>> segments,
    std::span<std::uint8_t> output) noexcept;

// RFC 2104 hashes keys longer than the compression block. RFC 5709 and 5310
// instead normalize keys to digest length before HMAC. The caller must select
// the source-required rule explicitly. Key material is never retained.
[[nodiscard]] bool hmac(DigestAlgorithm algorithm, KeyNormalization normalization,
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> segments,
    std::span<std::uint8_t> output) noexcept;

} // namespace router::crypto
