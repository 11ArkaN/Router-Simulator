// HMAC-SHA-256 computation and RFC 4868 128-bit truncation. The portable hash
// implementation keeps this primitive identical in native and Wasm builds.

#include "router/ipsec_integrity.hpp"

#include "router/sha256.hpp"

#include <algorithm>
#include <array>
#include <new>

namespace router::ipsec::integrity {

Status compute_hmac_sha256_128(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> authenticated_segments,
    std::span<std::uint8_t> output) noexcept {
  if (key.size() != hmac_sha256_key_octets)
    return Status::invalid_key_length;
  if (output.size() != hmac_sha256_128_icv_octets)
    return Status::invalid_icv_length;
  auto digest = crypto::hmac_sha256(key, authenticated_segments);
  std::copy_n(digest.begin(), output.size(), output.begin());
  std::fill(digest.begin(), digest.end(), std::uint8_t{0});
  return Status::ok;
}

Status verify_hmac_sha256_128(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> authenticated_segments,
    std::span<const std::uint8_t> received_icv) noexcept {
  if (key.size() != hmac_sha256_key_octets)
    return Status::invalid_key_length;
  if (received_icv.size() != hmac_sha256_128_icv_octets)
    return Status::invalid_icv_length;
  std::array<std::uint8_t, hmac_sha256_128_icv_octets> expected{};
  const auto status =
      compute_hmac_sha256_128(key, authenticated_segments, expected);
  if (status != Status::ok)
    return status;
  std::uint8_t difference{};
  for (std::size_t index = 0U; index < expected.size(); ++index)
    difference = static_cast<std::uint8_t>(
        difference | (expected[index] ^ received_icv[index]));
  std::fill(expected.begin(), expected.end(), std::uint8_t{0});
  return difference == 0U ? Status::ok : Status::authentication_failed;
}

std::unique_ptr<HmacSha256128Engine>
HmacSha256128Engine::create(std::span<const std::uint8_t> key) noexcept {
  if (key.size() != hmac_sha256_key_octets)
    return nullptr;
  return std::unique_ptr<HmacSha256128Engine>(
      new (std::nothrow) HmacSha256128Engine(key));
}

HmacSha256128Engine::HmacSha256128Engine(
    std::span<const std::uint8_t> key) noexcept {
  std::copy(key.begin(), key.end(), key_.begin());
}

HmacSha256128Engine::~HmacSha256128Engine() {
  // Volatile writes prevent ordinary dead-store elimination from retaining
  // the long-lived AH key in freed engine storage.
  volatile auto *bytes = key_.data();
  for (std::size_t index = 0U; index < key_.size(); ++index)
    bytes[index] = 0U;
}

Status HmacSha256128Engine::compute(
    std::span<const std::span<const std::uint8_t>> authenticated_segments,
    std::span<std::uint8_t> output) const noexcept {
  return compute_hmac_sha256_128(key_, authenticated_segments, output);
}

Status HmacSha256128Engine::verify(
    std::span<const std::span<const std::uint8_t>> authenticated_segments,
    std::span<const std::uint8_t> received_icv) const noexcept {
  return verify_hmac_sha256_128(key_, authenticated_segments, received_icv);
}

} // namespace router::ipsec::integrity
