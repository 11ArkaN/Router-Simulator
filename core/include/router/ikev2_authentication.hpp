// IKEv2 shared-secret AUTH computation and verification. The IKE SA owner
// supplies the exact SignedOctets segments already assembled from its retained
// first exchange, peer nonce and MACed ID payload. This module owns no secret.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ikev2 {

enum class AuthenticationStatus : std::uint8_t {
  ok,
  invalid_argument,
  output_too_small,
  authentication_failed
};

[[nodiscard]] AuthenticationStatus compute_psk_auth_sha256(
    std::span<const std::uint8_t> pre_shared_key,
    std::span<const std::span<const std::uint8_t>> signed_octets,
    std::span<std::uint8_t> output) noexcept;

[[nodiscard]] AuthenticationStatus verify_psk_auth_sha256(
    std::span<const std::uint8_t> pre_shared_key,
    std::span<const std::span<const std::uint8_t>> signed_octets,
    std::span<const std::uint8_t> received_auth) noexcept;

} // namespace router::ikev2
