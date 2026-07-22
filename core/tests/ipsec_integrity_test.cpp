// RFC 4868 section 2.7.2.1 AUTH256-1 verifies both the full input ordering and
// exact 128-bit truncation. Negative cases cover key size, ICV size and a
// complete constant-work mismatch path.

#include "router/ipsec_integrity.hpp"

#include <array>
#include <stdexcept>

void ipsec_integrity_tests() {
  using namespace router::ipsec::integrity;
  std::array<std::uint8_t, hmac_sha256_key_octets> key{};
  key.fill(0x0bU);
  constexpr std::array<std::uint8_t, 8U> data{'H', 'i', ' ', 'T',
                                              'h', 'e', 'r', 'e'};
  constexpr std::array<std::uint8_t, hmac_sha256_128_icv_octets> expected{
      0x19U, 0x8aU, 0x60U, 0x7eU, 0xb4U, 0x4bU, 0xfbU, 0xc6U,
      0x99U, 0x03U, 0xa0U, 0xf1U, 0xcfU, 0x2bU, 0xbdU, 0xc5U};
  const std::array segments{std::span<const std::uint8_t>{data}};
  std::array<std::uint8_t, hmac_sha256_128_icv_octets> output{};
  if (compute_hmac_sha256_128(key, segments, output) != Status::ok ||
      output != expected ||
      verify_hmac_sha256_128(key, segments, expected) != Status::ok)
    throw std::runtime_error("RFC 4868 HMAC-SHA-256-128 vector failed");
  const auto engine = HmacSha256128Engine::create(key);
  if (!engine || engine->compute(segments, output) != Status::ok ||
      engine->verify(segments, expected) != Status::ok)
    throw std::runtime_error("protected AH integrity engine failed");
  output[0U] ^= 1U;
  if (verify_hmac_sha256_128(key, segments, output) !=
          Status::authentication_failed ||
      compute_hmac_sha256_128(std::span{key}.first(key.size() - 1U), segments,
                              output) != Status::invalid_key_length ||
      verify_hmac_sha256_128(key, segments,
                             std::span{output}.first(output.size() - 1U)) !=
          Status::invalid_icv_length)
    throw std::runtime_error("IPsec integrity rejection policy failed");
}
