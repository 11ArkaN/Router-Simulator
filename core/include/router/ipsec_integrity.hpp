// RFC 4868 AUTH_HMAC_SHA2_256_128 primitive shared by AH and non-AEAD ESP.
// It owns no SA, sequence number or packet canonicalization. The caller passes
// authenticated segments in exact wire order and retains all key ownership.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace router::ipsec::integrity {

inline constexpr std::size_t hmac_sha256_key_octets = 32U;
inline constexpr std::size_t hmac_sha256_128_icv_octets = 16U;

enum class Status : std::uint8_t {
  ok,
  invalid_key_length,
  invalid_icv_length,
  authentication_failed
};

[[nodiscard]] Status compute_hmac_sha256_128(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> authenticated_segments,
    std::span<std::uint8_t> output) noexcept;

// Verification always compares all 128 transmitted bits. It never returns a
// partially matched prefix and clears the temporary expected authenticator.
[[nodiscard]] Status verify_hmac_sha256_128(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> authenticated_segments,
    std::span<const std::uint8_t> received_icv) noexcept;

class HmacSha256128Engine final {
public:
  [[nodiscard]] static std::unique_ptr<HmacSha256128Engine>
  create(std::span<const std::uint8_t> key) noexcept;
  ~HmacSha256128Engine();

  HmacSha256128Engine(const HmacSha256128Engine &) = delete;
  HmacSha256128Engine &operator=(const HmacSha256128Engine &) = delete;

  [[nodiscard]] Status compute(
      std::span<const std::span<const std::uint8_t>> authenticated_segments,
      std::span<std::uint8_t> output) const noexcept;
  [[nodiscard]] Status verify(
      std::span<const std::span<const std::uint8_t>> authenticated_segments,
      std::span<const std::uint8_t> received_icv) const noexcept;

private:
  explicit HmacSha256128Engine(
      std::span<const std::uint8_t> key) noexcept;

  std::array<std::uint8_t, hmac_sha256_key_octets> key_{};
};

} // namespace router::ipsec::integrity
