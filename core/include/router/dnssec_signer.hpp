// DNSSEC private-key signing contract. A concrete provider owns private key
// material and exposes only DNS wire public bytes plus signature generation.
// Zone management owns key roles and lifetimes. DNSSEC record code owns RRSIG
// metadata. Dependency direction: zone signer -> this contract -> crypto adapter.

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace router::dnssec {

class SigningKey {
public:
  virtual ~SigningKey() = default;
  SigningKey(const SigningKey &) = delete;
  SigningKey &operator=(const SigningKey &) = delete;

  // The algorithm and public key are the exact DNSKEY wire fields. The span
  // remains valid until destruction and never aliases private provider data.
  [[nodiscard]] virtual std::uint8_t algorithm() const noexcept = 0;
  [[nodiscard]] virtual std::span<const std::uint8_t>
  public_key() const noexcept = 0;

  // sign emits the raw RFC-specific RRSIG Signature field. output remains
  // unchanged on provider or allocation failure.
  [[nodiscard]] virtual bool
  sign(std::span<const std::uint8_t> signed_data,
       std::vector<std::uint8_t> &output) const noexcept = 0;

  // wrapping_key must contain 32 bytes of project-vault entropy. The provider
  // serializes private material only into temporary cleansed memory and emits
  // an authenticated encrypted blob bound to caller-supplied context.
  [[nodiscard]] virtual bool
  seal(std::span<const std::uint8_t> wrapping_key,
       std::span<const std::uint8_t> context,
       std::vector<std::uint8_t> &output) const noexcept = 0;

protected:
  SigningKey() = default;
};

struct SigningKeyGeneration {
  // Consulted only by RSA-backed algorithms. RFC 5702 permits 512 through
  // 4096 bits, while operational policy should normally choose at least 2048.
  std::uint16_t rsa_bits{2048U};
};

// Failure is explicit. There is no deterministic or placeholder key fallback.
[[nodiscard]] std::unique_ptr<SigningKey>
generate_signing_key(std::uint8_t algorithm,
                     SigningKeyGeneration options = {}) noexcept;

// Authentication, context, format, algorithm and private/public consistency
// are checked before a provider key is published. Plaintext key bytes never
// cross this API boundary.
[[nodiscard]] std::unique_ptr<SigningKey>
unseal_signing_key(std::span<const std::uint8_t> sealed,
                   std::span<const std::uint8_t> wrapping_key,
                   std::span<const std::uint8_t> context) noexcept;

} // namespace router::dnssec
