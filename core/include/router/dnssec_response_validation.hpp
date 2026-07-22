// DNSSEC validation of one response from an already authenticated zone. The
// resolver owns packet records, authenticated zone DNSKEYs, time and cache.
// This module groups RRsets, validates every authoritative set, and evaluates
// denial proofs before the caller may publish any response data to its cache.
// Dependency direction: resolver -> response validation -> chain primitives.

#pragma once

#include "router/dnssec_denial.hpp"

#include <cstdint>
#include <span>

namespace router::dnssec {

enum class ResponseSecurity : std::uint8_t {
  secure,
  insecure_delegation,
  bogus,
  indeterminate
};

enum class ResponseValidationFailure : std::uint8_t {
  none,
  malformed_response,
  missing_signature,
  invalid_rrset,
  missing_denial,
  unsupported_denial,
  resource_exhausted
};

struct ResponseValidationResult {
  ResponseSecurity security{ResponseSecurity::indeterminate};
  ResponseValidationFailure failure{
      ResponseValidationFailure::malformed_response};
  ValidationFailure rrset_failure{ValidationFailure::none};
  bool wildcard_expansion{};
};

// dnskeys must already be authenticated by a configured trust anchor or a
// validated parent DS RRset. Additional-section glue is intentionally absent:
// glue is routing input, not authenticated child data. An insecure result is
// possible only for a referral carrying an authenticated proof of no DS.
[[nodiscard]] ResponseValidationResult validate_secure_zone_response(
    const packet::dns::Question &question, packet::dns::Rcode rcode,
    std::span<dns::ZoneRecord> answers,
    std::span<dns::ZoneRecord> authorities,
    const packet::dns::Name &zone,
    std::span<const dns::ZoneRecord> dnskeys, std::uint32_t now,
    const CryptoVerifier &crypto, const DigestCalculator &digests,
    Nsec3IterationPolicy nsec3_policy = {}) noexcept;

} // namespace router::dnssec
