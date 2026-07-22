// IKE control-owner SK payload framing. It composes the RFC 7296 message codec
// with one directional RFC 5282 AEAD engine and releases inner payload views
// only after authentication. The caller owns the engine, IV sequence, packet
// buffers and session state, so this module cannot transmit or advance a SA.

#pragma once

#include "router/ikev2_aes_gcm.hpp"
#include "router/ikev2_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ikev2 {

enum class EncryptedPayloadStatus : std::uint8_t {
  ok,
  invalid_argument,
  output_too_small,
  malformed_message,
  encrypted_payload_required,
  payload_capacity_exhausted,
  authentication_failed,
  invalid_protected_payloads,
  provider_failure
};

struct EncryptedProtectResult {
  EncryptedPayloadStatus status{EncryptedPayloadStatus::invalid_argument};
  std::size_t message_octets{};
};

struct EncryptedUnprotectResult {
  EncryptedPayloadStatus status{EncryptedPayloadStatus::invalid_argument};
  Header header{};
  std::size_t payload_count{};
  std::size_t plaintext_octets{};
};

// plaintext_payloads is an already encoded generic payload chain. The
// first_plaintext_payload value is stored in the SK generic header and is zero
// for an empty INFORMATIONAL exchange. unique_iv is allocated by the key-set
// owner and must never repeat for one directional key.
[[nodiscard]] EncryptedProtectResult protect_encrypted_payload(
    aes_gcm::Engine &engine, std::uint64_t unique_iv, const Header &header,
    std::uint8_t first_plaintext_payload,
    std::span<const std::uint8_t> plaintext_payloads,
    std::span<const std::uint8_t> padding,
    std::span<std::uint8_t> output) noexcept;

// payload_views borrow plaintext_output. On every authentication or structural
// failure the written plaintext region is cleansed before return.
[[nodiscard]] EncryptedUnprotectResult unprotect_encrypted_payload(
    aes_gcm::Engine &engine, std::span<const std::uint8_t> message,
    std::span<std::uint8_t> plaintext_output,
    std::span<PayloadView> payload_views) noexcept;

} // namespace router::ikev2
