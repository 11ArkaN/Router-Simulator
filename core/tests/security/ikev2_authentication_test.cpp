// Shared-key AUTH tests use an independently generated HMAC-SHA-256 vector and
// verify that any changed AUTH octet fails without a prefix comparison.

#include "router/ikev2_authentication.hpp"

#include <array>
#include <stdexcept>

void ikev2_authentication_tests() {
  using namespace router::ikev2;
  const std::array<std::uint8_t, 6U> key{'s', 'e', 'c', 'r', 'e', 't'};
  const std::array<std::uint8_t, 13U> signed_bytes{
      's', 'i', 'g', 'n', 'e', 'd', '-', 'o', 'c', 't', 'e', 't', 's'};
  const std::array signed_segments{
      std::span<const std::uint8_t>{signed_bytes}};
  const std::array<std::uint8_t, 32U> expected{
      0x54U, 0xc0U, 0x71U, 0x70U, 0x09U, 0x87U, 0x45U, 0x3aU,
      0x17U, 0x81U, 0xb6U, 0x0bU, 0x19U, 0xd5U, 0xceU, 0x3aU,
      0x96U, 0x4dU, 0x20U, 0xd9U, 0xabU, 0x96U, 0x85U, 0x17U,
      0xbaU, 0xe5U, 0x74U, 0xc2U, 0x66U, 0xa4U, 0xfeU, 0x5eU};
  std::array<std::uint8_t, 32U> computed{};
  if (compute_psk_auth_sha256(key, signed_segments, computed) !=
          AuthenticationStatus::ok ||
      computed != expected ||
      verify_psk_auth_sha256(key, signed_segments, expected) !=
          AuthenticationStatus::ok)
    throw std::runtime_error("IKEv2 shared-key AUTH vector mismatch");
  computed[31U] ^= 1U;
  if (verify_psk_auth_sha256(key, signed_segments, computed) !=
      AuthenticationStatus::authentication_failed)
    throw std::runtime_error("modified IKEv2 shared-key AUTH was accepted");
}
