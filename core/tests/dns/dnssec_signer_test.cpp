// Generated-key tests cross the private signing contract with the independent
// public verification adapter for every compiled DNSSEC backend.

#include "router/dnssec_openssl.hpp"
#include "router/dnssec_signer.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void dnssec_signer_tests() {
  using namespace router::dnssec;

  const std::array<std::uint8_t, 3U> algorithms{8U, 13U, 15U};
  const std::array<std::uint8_t, 9U> data{0U, 1U, 2U, 3U, 0xffU,
                                          5U, 6U, 7U, 8U};
  OpenSslCryptoVerifier verifier;
  for (const auto algorithm : algorithms) {
    const auto key = generate_signing_key(
        algorithm,
        {.rsa_bits = static_cast<std::uint16_t>(algorithm == 8U ? 1024U
                                                                : 2048U)});
    if (!key || key->algorithm() != algorithm || key->public_key().empty())
      throw std::runtime_error("DNSSEC signing key generation failed");
    std::vector<std::uint8_t> signature;
    if (!key->sign(data, signature) || signature.empty() ||
        !verifier.verify(algorithm, key->public_key(), data, signature))
      throw std::runtime_error("DNSSEC generated signature did not verify");

    std::array<std::uint8_t, 32U> wrapping_key{};
    wrapping_key.fill(static_cast<std::uint8_t>(algorithm + 1U));
    const std::array<std::uint8_t, 4U> context{'z', 'o', 'n', 'e'};
    std::vector<std::uint8_t> sealed;
    if (!key->seal(wrapping_key, context, sealed) || sealed.empty())
      throw std::runtime_error("DNSSEC private key sealing failed");
    const auto restored = unseal_signing_key(sealed, wrapping_key, context);
    std::vector<std::uint8_t> restored_signature;
    if (!restored || restored->algorithm() != algorithm ||
        !std::ranges::equal(restored->public_key(), key->public_key()) ||
        !restored->sign(data, restored_signature) ||
        !verifier.verify(algorithm, restored->public_key(), data,
                         restored_signature))
      throw std::runtime_error("DNSSEC sealed private key did not round trip");

    auto tampered = sealed;
    tampered.back() ^= 1U;
    auto wrong_key = wrapping_key;
    wrong_key[0] ^= 1U;
    const std::array<std::uint8_t, 5U> wrong_context{'o', 't', 'h', 'e', 'r'};
    if (unseal_signing_key(tampered, wrapping_key, context) ||
        unseal_signing_key(sealed, wrong_key, context) ||
        unseal_signing_key(sealed, wrapping_key, wrong_context))
      throw std::runtime_error("DNSSEC vault accepted unauthenticated key data");
  }

  if (generate_signing_key(1U) ||
      generate_signing_key(8U, {.rsa_bits = 511U}) ||
      generate_signing_key(8U, {.rsa_bits = 4097U}))
    throw std::runtime_error("DNSSEC generated a prohibited key");
}
