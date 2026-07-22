// SK integration tests protect and authenticate a complete IKE message, parse
// its inner payload chain only after verification and prove that a forged tag
// cannot release plaintext or a Message ID candidate to higher state code.

#include "router/ikev2_encrypted_payload.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void ikev2_encrypted_payload_tests() {
  using namespace router::ikev2;
  aes_gcm::KeyMaterial material{};
  material.key_octets = 16U;
  for (std::size_t index = 0U; index < material.key_octets; ++index)
    material.key[index] = static_cast<std::uint8_t>(index + 1U);
  material.salt = {0xa0U, 0xa1U, 0xa2U, 0xa3U};
  auto engine = aes_gcm::Engine::create(material);
  if (!engine)
    throw std::runtime_error("IKE SK test could not create AEAD engine");

  const std::array<std::uint8_t, 4U> notify_body{0U, 0U, 0x40U, 0x2fU};
  std::array<std::uint8_t, 8U> inner{};
  if (encode_payload(0U, false, notify_body, inner) != inner.size())
    throw std::runtime_error("IKE SK inner payload encoding failed");
  Header header{.initiator_spi = 0x0102030405060708ULL,
                .responder_spi = 0x1112131415161718ULL,
                .first_payload = 0U,
                .major_version = 2U,
                .minor_version = 0U,
                .exchange_type =
                    static_cast<std::uint8_t>(ExchangeType::informational),
                .initiator = true,
                .higher_version_supported = false,
                .response = false,
                .message_id = 3U,
                .length = 0U};
  const std::array<std::uint8_t, 2U> padding{0x5aU, 0xa5U};
  std::array<std::uint8_t, 128U> message{};
  const auto protected_result = protect_encrypted_payload(
      *engine, 1U, header, static_cast<std::uint8_t>(PayloadType::notify),
      inner, padding, message);
  if (protected_result.status != EncryptedPayloadStatus::ok)
    throw std::runtime_error("IKE SK protection failed");

  std::array<std::uint8_t, 64U> plaintext{};
  std::array<PayloadView, 4U> views{};
  const auto unprotected = unprotect_encrypted_payload(
      *engine, std::span{message}.first(protected_result.message_octets),
      plaintext, views);
  if (unprotected.status != EncryptedPayloadStatus::ok ||
      unprotected.header.message_id != 3U ||
      unprotected.payload_count != 1U ||
      views[0].type != static_cast<std::uint8_t>(PayloadType::notify) ||
      views[0].body.size() != notify_body.size() ||
      !std::equal(notify_body.begin(), notify_body.end(),
                  views[0].body.begin()))
    throw std::runtime_error("IKE SK authenticated parse failed");

  message[protected_result.message_octets - 1U] ^= 1U;
  plaintext.fill(0x7eU);
  const auto forged = unprotect_encrypted_payload(
      *engine, std::span{message}.first(protected_result.message_octets),
      plaintext, views);
  if (forged.status != EncryptedPayloadStatus::authentication_failed ||
      std::any_of(plaintext.begin(), plaintext.begin() + inner.size(),
                  [](std::uint8_t byte) { return byte != 0U; }))
    throw std::runtime_error("forged IKE SK plaintext escaped authentication");
}
