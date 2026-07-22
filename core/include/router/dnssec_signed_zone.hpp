// Transactional signed-zone snapshot builder. The caller owns unsigned zone
// data and ZoneKeyStore. A successful result contains ordinary records,
// published DNSKEYs, a complete NSEC chain and all required RRSIG RRsets.

#pragma once

#include "router/dnssec_zone_keys.hpp"
#include "router/dnssec_validation.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dnssec {

enum class DenialMode : std::uint8_t { nsec, nsec3, nsec3_opt_out };

struct ZoneSigningPolicy {
  std::uint32_t dnskey_ttl{};
  std::uint32_t denial_ttl{};
  std::uint32_t signature_inception{};
  std::uint32_t signature_expiration{};
  DenialMode denial_mode{DenialMode::nsec};
};

// Existing DNSKEY, RRSIG, NSEC and NSEC3 records are rejected so stale
// generated material cannot coexist with the new generation. At least one
// active KSK and ZSK is required. The source records remain unchanged on error.
[[nodiscard]] std::optional<std::vector<dns::ZoneRecord>> sign_zone_snapshot(
    const packet::dns::Name &origin,
    std::span<const dns::ZoneRecord> unsigned_records,
    const ZoneKeyStore &keys, std::uint64_t now,
    const ZoneSigningPolicy &policy,
    const DigestCalculator *digests = nullptr) noexcept;

} // namespace router::dnssec
