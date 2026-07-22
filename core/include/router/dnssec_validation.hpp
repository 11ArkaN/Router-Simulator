// DNSSEC RRset canonicalization and signature validation policy. The caller
// owns zone records, keys, signatures, wall time and the crypto provider. This
// module owns only temporary canonical bytes and publishes no resolver state.

#pragma once

#include "router/dns_authoritative.hpp"
#include "router/dnssec_record.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace router::dnssec {

enum class ValidationState : std::uint8_t { secure, bogus, indeterminate };

enum class ValidationFailure : std::uint8_t {
  none,
  malformed_rrset,
  no_matching_key,
  unsupported_algorithm,
  signature_not_yet_valid,
  signature_expired,
  invalid_signature,
  resource_exhausted
};

struct ValidationResult {
  ValidationState state{ValidationState::indeterminate};
  ValidationFailure failure{ValidationFailure::no_matching_key};
  std::uint16_t key_tag{};
  std::uint8_t algorithm{};
  // The Labels field belongs to the signature that actually verified. It is
  // needed to distinguish an ordinary positive answer from a wildcard
  // expansion without trusting a different, invalid RRSIG in the response.
  std::uint8_t labels{};
  // These values come from the signature that actually verified. Validators
  // use them to cap cached TTLs and to stop using an authenticated DNSKEY once
  // its RRSIG validity interval ends.
  std::uint32_t original_ttl{};
  std::uint32_t valid_until{};
};

class CryptoVerifier {
public:
  virtual ~CryptoVerifier() = default;

  // The implementation advertises only algorithms backed by real crypto.
  // verify receives the DNSKEY public-key field, RFC 4034 signed data and raw
  // RRSIG signature. It must not access sockets, resolver state or wall time.
  [[nodiscard]] virtual bool supports(std::uint8_t algorithm) const noexcept = 0;
  [[nodiscard]] virtual bool verify(
      std::uint8_t algorithm, std::span<const std::uint8_t> public_key,
      std::span<const std::uint8_t> signed_data,
      std::span<const std::uint8_t> signature) const noexcept = 0;
};

class DigestCalculator {
public:
  virtual ~DigestCalculator() = default;

  // DS digest support is distinct from signature support because IANA assigns
  // the two numeric spaces independently. output remains unchanged on error.
  [[nodiscard]] virtual bool supports_digest(
      std::uint8_t digest_type) const noexcept = 0;
  [[nodiscard]] virtual bool calculate_digest(
      std::uint8_t digest_type, std::span<const std::uint8_t> input,
      std::vector<std::uint8_t> &output) const noexcept = 0;
};

// Builds RRSIG RDATA without Signature followed by sorted canonical RR forms.
// All records must belong to the covered RRset. The output remains unchanged
// on malformed input or allocation failure and has no artificial message-size
// ceiling because signed data can legitimately contain many resource records.
[[nodiscard]] bool canonical_signed_data(
    const Rrsig &signature, std::span<const dns::ZoneRecord> records,
    std::vector<std::uint8_t> &output) noexcept;

// now is unsigned POSIX time modulo 2^32 as carried in RRSIG. RFC 1982 serial
// arithmetic is used so signatures crossing the 2038 boundary remain valid.
// The function tries every matching signature and key before reporting bogus.
[[nodiscard]] ValidationResult validate_rrset(
    std::span<const dns::ZoneRecord> records,
    std::span<const dns::ZoneRecord> signatures,
    std::span<const dns::ZoneRecord> dnskeys, std::uint32_t now,
    const CryptoVerifier &crypto) noexcept;

} // namespace router::dnssec
