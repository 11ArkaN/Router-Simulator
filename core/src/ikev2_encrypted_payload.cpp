// Authenticated SK construction and parsing. The complete IKE header and SK
// generic header are AEAD associated data. Ciphertext is never interpreted as
// a generic payload chain and malformed authenticated plaintext is cleansed.

#include "router/ikev2_encrypted_payload.hpp"

#include <openssl/crypto.h>

#include <limits>

namespace router::ikev2 {
namespace {

constexpr std::size_t explicit_iv_octets{8U};
constexpr std::size_t tag_octets{16U};

void cleanse(std::span<std::uint8_t> bytes) noexcept {
  if (!bytes.empty())
    OPENSSL_cleanse(bytes.data(), bytes.size());
}

EncryptedPayloadStatus map_protect_status(aes_gcm::Status status) noexcept {
  switch (status) {
  case aes_gcm::Status::output_too_small:
    return EncryptedPayloadStatus::output_too_small;
  case aes_gcm::Status::invalid_argument:
    return EncryptedPayloadStatus::invalid_argument;
  default:
    return EncryptedPayloadStatus::provider_failure;
  }
}

EncryptedPayloadStatus map_unprotect_status(aes_gcm::Status status) noexcept {
  switch (status) {
  case aes_gcm::Status::output_too_small:
    return EncryptedPayloadStatus::output_too_small;
  case aes_gcm::Status::authentication_failed:
  case aes_gcm::Status::invalid_padding:
    return EncryptedPayloadStatus::authentication_failed;
  case aes_gcm::Status::invalid_argument:
    return EncryptedPayloadStatus::invalid_argument;
  default:
    return EncryptedPayloadStatus::provider_failure;
  }
}

} // namespace

EncryptedProtectResult protect_encrypted_payload(
    aes_gcm::Engine &engine, std::uint64_t unique_iv, const Header &header,
    std::uint8_t first_plaintext_payload,
    std::span<const std::uint8_t> plaintext_payloads,
    std::span<const std::uint8_t> padding,
    std::span<std::uint8_t> output) noexcept {
  if (unique_iv == 0U || padding.size() > 255U ||
      (first_plaintext_payload == 0U && !plaintext_payloads.empty()) ||
      (first_plaintext_payload != 0U && plaintext_payloads.empty()))
    return {.status = EncryptedPayloadStatus::invalid_argument};
  if (plaintext_payloads.size() >
      std::numeric_limits<std::size_t>::max() - padding.size() - 29U)
    return {.status = EncryptedPayloadStatus::invalid_argument};

  // SK body is explicit IV, ciphertext(payloads|padding|PadLength), and ICV.
  const auto encrypted_body_octets =
      explicit_iv_octets + plaintext_payloads.size() + padding.size() + 1U +
      tag_octets;
  const auto sk_payload_octets =
      generic_payload_header_octets + encrypted_body_octets;
  const auto message_octets = header_octets + sk_payload_octets;
  if (sk_payload_octets > std::numeric_limits<std::uint16_t>::max() ||
      message_octets > std::numeric_limits<std::uint32_t>::max())
    return {.status = EncryptedPayloadStatus::invalid_argument};
  if (output.size() < message_octets)
    return {.status = EncryptedPayloadStatus::output_too_small};

  auto encoded_header = header;
  encoded_header.first_payload =
      static_cast<std::uint8_t>(PayloadType::encrypted);
  encoded_header.length = static_cast<std::uint32_t>(message_octets);
  if (!encode_header(encoded_header, output) ||
      !encode_payload_header(first_plaintext_payload, false,
                             sk_payload_octets,
                             output.subspan(header_octets)))
    return {.status = EncryptedPayloadStatus::invalid_argument};

  const auto associated_data_octets =
      header_octets + generic_payload_header_octets;
  const auto protected_result = engine.protect(
      unique_iv, output.first(associated_data_octets), plaintext_payloads,
      padding, output.subspan(associated_data_octets, encrypted_body_octets));
  if (protected_result.status != aes_gcm::Status::ok ||
      protected_result.encrypted_body_octets != encrypted_body_octets) {
    cleanse(output.first(message_octets));
    return {.status = map_protect_status(protected_result.status)};
  }
  return {.status = EncryptedPayloadStatus::ok,
          .message_octets = message_octets};
}

EncryptedUnprotectResult unprotect_encrypted_payload(
    aes_gcm::Engine &engine, std::span<const std::uint8_t> message,
    std::span<std::uint8_t> plaintext_output,
    std::span<PayloadView> payload_views) noexcept {
  PayloadView outer_payload{};
  const auto parsed = parse(message, std::span{&outer_payload, 1U});
  if (parsed.status == ParseStatus::payload_capacity_exhausted)
    return {.status = EncryptedPayloadStatus::malformed_message,
            .header = parsed.header};
  if (parsed.status != ParseStatus::ok || parsed.payload_count != 1U)
    return {.status = EncryptedPayloadStatus::malformed_message,
            .header = parsed.header};
  if (outer_payload.type !=
      static_cast<std::uint8_t>(PayloadType::encrypted))
    return {.status = EncryptedPayloadStatus::encrypted_payload_required,
            .header = parsed.header};

  const auto associated_data_octets =
      outer_payload.offset + generic_payload_header_octets;
  const auto unprotected = engine.unprotect(
      message.first(associated_data_octets), outer_payload.body,
      plaintext_output);
  if (unprotected.status != aes_gcm::Status::ok)
    return {.status = map_unprotect_status(unprotected.status),
            .header = parsed.header};

  const auto plaintext = plaintext_output.first(unprotected.payload_octets);
  const auto inner = parse_payload_chain(outer_payload.next_payload, plaintext,
                                         payload_views);
  if (inner.status != ParseStatus::ok) {
    cleanse(plaintext);
    return {.status =
                inner.status == ParseStatus::payload_capacity_exhausted
                    ? EncryptedPayloadStatus::payload_capacity_exhausted
                    : EncryptedPayloadStatus::invalid_protected_payloads,
            .header = parsed.header};
  }
  return {.status = EncryptedPayloadStatus::ok,
          .header = parsed.header,
          .payload_count = inner.payload_count,
          .plaintext_octets = unprotected.payload_octets};
}

} // namespace router::ikev2
