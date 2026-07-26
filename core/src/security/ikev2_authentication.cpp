// RFC 7296 section 2.16 shared-key AUTH. The first PRF derives a dedicated
// authentication key from the PSK and the fixed ASCII pad, and the second PRF
// authenticates SignedOctets. Comparison scans the complete digest every time.

#include "router/ikev2_authentication.hpp"

#include "router/ikev2_kdf.hpp"
#include "router/sha256.hpp"

#include <algorithm>
#include <array>

namespace router::ikev2 {
namespace {

constexpr std::array<std::uint8_t, 17U> key_pad{
    'K', 'e', 'y', ' ', 'P', 'a', 'd', ' ', 'f',
    'o', 'r', ' ', 'I', 'K', 'E', 'v', '2'};

} // namespace

AuthenticationStatus compute_psk_auth_sha256(
    std::span<const std::uint8_t> pre_shared_key,
    std::span<const std::span<const std::uint8_t>> signed_octets,
    std::span<std::uint8_t> output) noexcept {
  if (pre_shared_key.empty())
    return AuthenticationStatus::invalid_argument;
  if (output.size() < router::crypto::sha256_digest_octets)
    return AuthenticationStatus::output_too_small;
  std::array<std::uint8_t, router::crypto::sha256_digest_octets> auth_key{};
  const std::array pad_segments{std::span<const std::uint8_t>{key_pad}};
  if (prf_sha256(pre_shared_key, pad_segments, auth_key) != KdfStatus::ok ||
      prf_sha256(auth_key, signed_octets,
                 output.first(router::crypto::sha256_digest_octets)) !=
          KdfStatus::ok) {
    std::fill(auth_key.begin(), auth_key.end(), std::uint8_t{0});
    return AuthenticationStatus::invalid_argument;
  }
  std::fill(auth_key.begin(), auth_key.end(), std::uint8_t{0});
  return AuthenticationStatus::ok;
}

AuthenticationStatus verify_psk_auth_sha256(
    std::span<const std::uint8_t> pre_shared_key,
    std::span<const std::span<const std::uint8_t>> signed_octets,
    std::span<const std::uint8_t> received_auth) noexcept {
  if (received_auth.size() != router::crypto::sha256_digest_octets)
    return AuthenticationStatus::invalid_argument;
  std::array<std::uint8_t, router::crypto::sha256_digest_octets> expected{};
  const auto computed =
      compute_psk_auth_sha256(pre_shared_key, signed_octets, expected);
  if (computed != AuthenticationStatus::ok)
    return computed;
  std::uint8_t difference{};
  for (std::size_t index = 0U; index < expected.size(); ++index)
    difference = static_cast<std::uint8_t>(difference |
                                           (expected[index] ^
                                            received_auth[index]));
  std::fill(expected.begin(), expected.end(), std::uint8_t{0});
  return difference == 0U ? AuthenticationStatus::ok
                          : AuthenticationStatus::authentication_failed;
}

} // namespace router::ikev2
