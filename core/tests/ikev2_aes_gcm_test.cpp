// IKEv2 AES-GCM tests authenticate the IKE prefix, accept arbitrary padding
// bytes and prove that tag failure releases no plaintext to the payload parser.

#include "router/ikev2_aes_gcm.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void ikev2_aes_gcm_tests() {
  using namespace router::ikev2::aes_gcm;
  KeyMaterial material{};
  material.key_octets = 16U;
  for (std::size_t index = 0U; index < material.key_octets; ++index)
    material.key[index] = static_cast<std::uint8_t>(index);
  material.salt = {0xa0U, 0xa1U, 0xa2U, 0xa3U};
  auto engine = Engine::create(material);
  if (!engine)
    throw std::runtime_error("IKEv2 AES-GCM provider initialization failed");

  std::array<std::uint8_t, 32U> associated_data{};
  associated_data[0U] = 1U;
  associated_data[31U] = 2U;
  const std::array<std::uint8_t, 5U> plaintext{33U, 0U, 0U, 5U, 9U};
  const std::array<std::uint8_t, 3U> padding{0xaaU, 0xbbU, 0xccU};
  std::array<std::uint8_t, 64U> encrypted{};
  const auto protected_result = engine->protect(
      7U, associated_data, plaintext, padding, encrypted);
  if (protected_result.status != Status::ok)
    throw std::runtime_error("IKEv2 AES-GCM protection failed");

  std::array<std::uint8_t, 32U> decrypted{};
  const auto unprotected = engine->unprotect(
      associated_data,
      std::span{encrypted}.first(protected_result.encrypted_body_octets),
      decrypted);
  if (unprotected.status != Status::ok ||
      unprotected.payload_octets != plaintext.size() ||
      !std::equal(plaintext.begin(), plaintext.end(), decrypted.begin()))
    throw std::runtime_error("IKEv2 AES-GCM round trip failed");

  encrypted[protected_result.encrypted_body_octets - 1U] ^= 1U;
  decrypted.fill(0x5aU);
  if (engine->unprotect(
          associated_data,
          std::span{encrypted}.first(protected_result.encrypted_body_octets),
          decrypted)
          .status != Status::authentication_failed ||
      std::any_of(decrypted.begin(),
                  decrypted.begin() +
                      static_cast<std::ptrdiff_t>(plaintext.size() +
                                                  padding.size() + 1U),
                  [](std::uint8_t byte) { return byte != 0U; }))
    throw std::runtime_error("unauthenticated IKEv2 plaintext was exposed");
}
