// OpenSSL-backed DNSSEC signature verification. This module owns only
// temporary EVP key and digest objects. The resolver owns DNS records, trust
// state and time, while generated policy owns the algorithm-to-backend map.
// Dependency direction: dnssec validation -> this adapter -> OpenSSL libcrypto.

#pragma once

#include "router/dnssec_validation.hpp"

namespace router::dnssec {

class OpenSslCryptoVerifier final : public CryptoVerifier,
                                    public DigestCalculator {
public:
  // True means the pinned registry profile maps the wire algorithm to a
  // compiled cryptographic backend. It does not claim that a particular key
  // is syntactically valid or trusted.
  [[nodiscard]] bool supports(std::uint8_t algorithm) const noexcept override;

  // DNSKEY public_key and RRSIG signature use their DNS wire encodings rather
  // than ASN.1 containers. Malformed keys, signatures and allocation failures
  // are rejected as false. No OpenSSL error is allowed across this boundary.
  [[nodiscard]] bool verify(
      std::uint8_t algorithm, std::span<const std::uint8_t> public_key,
      std::span<const std::uint8_t> signed_data,
      std::span<const std::uint8_t> signature) const noexcept override;

  [[nodiscard]] bool supports_digest(
      std::uint8_t digest_type) const noexcept override;
  [[nodiscard]] bool calculate_digest(
      std::uint8_t digest_type, std::span<const std::uint8_t> input,
      std::vector<std::uint8_t> &output) const noexcept override;
};

} // namespace router::dnssec
