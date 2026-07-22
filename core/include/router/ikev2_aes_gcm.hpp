// OpenSSL-backed RFC 5282 AES-GCM transform for the IKEv2 Encrypted Payload.
// One IKE SA owner calls an Engine serially. The caller owns the packet buffer,
// IV counter and key lifetime; this class owns only its reusable provider state.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace router::ikev2::aes_gcm {

struct KeyMaterial {
  std::array<std::uint8_t, 32U> key{};
  std::uint8_t key_octets{};
  std::array<std::uint8_t, 4U> salt{};
};

enum class Status : std::uint8_t {
  ok,
  invalid_argument,
  output_too_small,
  provider_failure,
  authentication_failed,
  invalid_padding
};

struct ProtectResult {
  Status status{Status::invalid_argument};
  std::size_t encrypted_body_octets{};
};

struct UnprotectResult {
  Status status{Status::invalid_argument};
  std::size_t payload_octets{};
};

class Engine final {
public:
  [[nodiscard]] static std::unique_ptr<Engine>
  create(const KeyMaterial &material) noexcept;
  ~Engine();

  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;

  // associated_data is the exact IKE message prefix through the four-octet
  // Encrypted Payload header. output receives IV, ciphertext and the full tag.
  [[nodiscard]] ProtectResult
  protect(std::uint64_t unique_iv,
          std::span<const std::uint8_t> associated_data,
          std::span<const std::uint8_t> plaintext_payloads,
          std::span<const std::uint8_t> padding,
          std::span<std::uint8_t> output) noexcept;

  [[nodiscard]] UnprotectResult
  unprotect(std::span<const std::uint8_t> associated_data,
            std::span<const std::uint8_t> encrypted_body,
            std::span<std::uint8_t> plaintext_output) noexcept;

private:
  Engine(void *context, const KeyMaterial &material) noexcept;
  [[nodiscard]] const void *cipher() const noexcept;

  void *context_{};
  KeyMaterial material_{};
};

} // namespace router::ikev2::aes_gcm
