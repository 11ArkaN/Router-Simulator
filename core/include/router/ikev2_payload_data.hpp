// Bounded views for the non-SA IKEv2 payload bodies used while establishing,
// authenticating and deleting IKE and Child SAs. The codec owns no session
// state and retains no packet pointer beyond the returned spans. Its caller is
// the single IKE SA owner on the control shard.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ikev2 {

enum class BodyParseStatus : std::uint8_t {
  ok,
  truncated,
  invalid_reserved,
  invalid_length,
  invalid_protocol,
  invalid_count,
  invalid_value,
  capacity_exhausted
};

struct KeyExchangeView {
  std::uint16_t group{};
  std::span<const std::uint8_t> data;
};

// RFC 7296 section 3.4 requires a four-octet fixed prefix. The DH public value
// is opaque here because group-specific size and public-key checks belong to
// the selected cryptographic transform, not the wire codec.
[[nodiscard]] BodyParseStatus
parse_key_exchange(std::span<const std::uint8_t> body,
                   KeyExchangeView &view) noexcept;

// RFC 7296 section 2.10 requires nonce material between 16 and 256 octets.
[[nodiscard]] BodyParseStatus
parse_nonce(std::span<const std::uint8_t> body,
            std::span<const std::uint8_t> &nonce) noexcept;

struct NotifyView {
  std::uint8_t protocol_id{};
  std::uint16_t message_type{};
  std::span<const std::uint8_t> spi;
  std::span<const std::uint8_t> data;
};

[[nodiscard]] BodyParseStatus
parse_notify(std::span<const std::uint8_t> body, NotifyView &view) noexcept;

struct DeleteView {
  std::uint8_t protocol_id{};
  std::size_t spi_count{};
  std::span<const std::uint8_t> encoded_spis;
};

[[nodiscard]] BodyParseStatus
parse_delete(std::span<const std::uint8_t> body, DeleteView &view) noexcept;

struct IdentificationView {
  std::uint8_t type{};
  std::span<const std::uint8_t> data;
};

[[nodiscard]] BodyParseStatus
parse_identification(std::span<const std::uint8_t> body,
                     IdentificationView &view) noexcept;

struct AuthenticationView {
  std::uint8_t method{};
  std::span<const std::uint8_t> data;
};

[[nodiscard]] BodyParseStatus
parse_authentication(std::span<const std::uint8_t> body,
                     AuthenticationView &view) noexcept;

inline constexpr std::uint8_t digital_signature_authentication_method = 14U;
inline constexpr std::uint16_t signature_hash_algorithms_notify = 16431U;

enum class SignatureHashAlgorithm : std::uint16_t {
  sha1 = 1U,
  sha2_256 = 2U,
  sha2_384 = 3U,
  sha2_512 = 4U
};

struct DigitalSignatureView {
  std::span<const std::uint8_t> algorithm_identifier_der;
  std::span<const std::uint8_t> signature;
};

// RFC 7427 prefixes the DER AlgorithmIdentifier with one length octet. DER
// interpretation and public-key policy belong to the certificate owner.
[[nodiscard]] BodyParseStatus parse_digital_signature_authentication(
    const AuthenticationView &authentication,
    DigitalSignatureView &view) noexcept;

// The Notify parser has already validated Protocol ID and SPI framing. This
// helper validates the RFC 7427 status type and decodes its packed u16 list.
[[nodiscard]] BodyParseStatus parse_signature_hash_algorithms(
    const NotifyView &notification,
    std::span<std::uint16_t> algorithms,
    std::size_t &algorithm_count) noexcept;

[[nodiscard]] std::size_t encode_signature_hash_algorithms(
    std::span<const std::uint16_t> algorithms,
    std::span<std::uint8_t> output) noexcept;

[[nodiscard]] std::size_t encode_digital_signature_authentication(
    std::span<const std::uint8_t> algorithm_identifier_der,
    std::span<const std::uint8_t> signature,
    std::span<std::uint8_t> output) noexcept;

struct ConfigurationAttributeView {
  std::uint16_t type{};
  std::span<const std::uint8_t> value;
};

struct ConfigurationParseResult {
  BodyParseStatus status{BodyParseStatus::truncated};
  std::uint8_t configuration_type{};
  std::size_t attribute_count{};
};

[[nodiscard]] ConfigurationParseResult parse_configuration(
    std::span<const std::uint8_t> body,
    std::span<ConfigurationAttributeView> attributes) noexcept;

struct EncryptedFragmentView {
  std::uint16_t number{};
  std::uint16_t total{};
  std::span<const std::uint8_t> encrypted_data;
};

// RFC 7383 permits at most 65535 fragments on the wire. Resource policy may
// impose a smaller configured limit after this structural check.
[[nodiscard]] BodyParseStatus
parse_encrypted_fragment(std::span<const std::uint8_t> body,
                         EncryptedFragmentView &view) noexcept;

} // namespace router::ikev2
