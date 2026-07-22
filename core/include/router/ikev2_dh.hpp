// OpenSSL-backed IKEv2 Diffie-Hellman group 19 ephemeral key agreement. One
// pending IKE_SA_INIT exchange owns an EphemeralKey. Private material remains
// inside EVP_PKEY and is destroyed with the exchange owner.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace router::ikev2::dh {

inline constexpr std::uint16_t group_19 = 19U;
inline constexpr std::size_t group_19_public_octets = 64U;
inline constexpr std::size_t group_19_secret_octets = 32U;

enum class Status : std::uint8_t {
  ok,
  invalid_peer_value,
  output_too_small,
  provider_failure
};

class EphemeralKey final {
public:
  [[nodiscard]] static std::unique_ptr<EphemeralKey>
  generate_group_19() noexcept;
  ~EphemeralKey();

  EphemeralKey(const EphemeralKey &) = delete;
  EphemeralKey &operator=(const EphemeralKey &) = delete;

  [[nodiscard]] Status public_value(std::span<std::uint8_t> output) const noexcept;
  [[nodiscard]] Status derive(
      std::span<const std::uint8_t> peer_public_value,
      std::span<std::uint8_t> shared_secret_output) const noexcept;

private:
  explicit EphemeralKey(void *key) noexcept : key_(key) {}
  void *key_{};
};

} // namespace router::ikev2::dh
