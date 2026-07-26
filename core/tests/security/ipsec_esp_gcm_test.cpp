// RFC 4106 ESP AES-GCM tests execute against the pinned OpenSSL Wasm provider.
// They verify wire expansion, round-trip semantics, ESN AAD and fail-closed
// handling of modified ciphertext, ICV and sequence values.

#include "router/ipsec_esp_gcm.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void ipsec_esp_gcm_tests() {
  using namespace router::ipsec::esp_gcm;
  KeyMaterial material{};
  material.key_octets = 16U;
  for (std::size_t index = 0U; index < material.key_octets; ++index)
    material.key[index] = static_cast<std::uint8_t>(index);
  material.salt = {0xa0U, 0xa1U, 0xa2U, 0xa3U};
  auto engine = Engine::create(material);
  if (!engine)
    throw std::runtime_error("ESP AES-GCM provider creation failed");

  const std::array<std::uint8_t, 13> plaintext{
      'I', 'P', 's', 'e', 'c', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd'};
  std::array<std::uint8_t, 128> protected_packet{};
  const auto protected_result = engine->protect(
      0x10203040U, 7U, false, 17U, plaintext, protected_packet);
  // Thirteen data octets need one padding octet before Pad Length and Next
  // Header. Total expansion is 8 + 8 + 3 + 16 octets.
  if (protected_result.status != Status::ok ||
      protected_result.packet_octets != plaintext.size() + 35U ||
      protected_packet[0] != 0x10U || protected_packet[7] != 7U)
    throw std::runtime_error("ESP AES-GCM wire construction failed");

  std::array<std::uint8_t, 64> recovered{};
  const auto unprotected = engine->unprotect(
      7U, false,
      std::span<const std::uint8_t>{protected_packet}.first(
          protected_result.packet_octets),
      recovered);
  if (unprotected.status != Status::ok ||
      unprotected.plaintext_octets != plaintext.size() ||
      unprotected.next_header != 17U || unprotected.spi != 0x10203040U ||
      !std::equal(plaintext.begin(), plaintext.end(), recovered.begin()))
    throw std::runtime_error("ESP AES-GCM authenticated recovery failed");

  // Authentication covers ciphertext, trailer, SPI and low sequence. A failed
  // tag check must cleanse all possibly written plaintext before returning.
  auto tampered = protected_packet;
  tampered[20] ^= 0x01U;
  recovered.fill(0x5aU);
  const auto rejected = engine->unprotect(
      7U, false,
      std::span<const std::uint8_t>{tampered}.first(
          protected_result.packet_octets),
      recovered);
  if (rejected.status != Status::authentication_failed ||
      recovered[0] != 0U)
    throw std::runtime_error("modified ESP ciphertext exposed plaintext");

  // ESN AAD contains SPI followed by the complete 64-bit sequence while the
  // transmitted Sequence field remains only low32, including zero at rollover.
  const auto esn_sequence = 0x100000000ULL;
  const auto esn_packet = engine->protect(0x50607080U, esn_sequence, true, 41U,
                                          plaintext, protected_packet);
  if (esn_packet.status != Status::ok || protected_packet[4] != 0U ||
      protected_packet[7] != 0U)
    throw std::runtime_error("ESP ESN low word was encoded incorrectly");
  const auto esn_recovered = engine->unprotect(
      esn_sequence, true,
      std::span<const std::uint8_t>{protected_packet}.first(
          esn_packet.packet_octets),
      recovered);
  if (esn_recovered.status != Status::ok ||
      esn_recovered.plaintext_octets != plaintext.size())
    throw std::runtime_error("ESP ESN AAD did not authenticate");
  if (engine->unprotect(
          0U, false,
          std::span<const std::uint8_t>{protected_packet}.first(
              esn_packet.packet_octets),
          recovered)
          .status != Status::invalid_argument)
    throw std::runtime_error("ESP sequence zero was accepted without ESN");
}
