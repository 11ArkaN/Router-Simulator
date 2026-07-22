// DNSSEC zone-record signing helpers. The caller owns private SigningKey
// instances and decides lifecycle, KSK/ZSK policy and wall-clock intervals.
// This module owns only temporary DNSKEY/RRSIG records and canonical bytes.
// Dependency direction: authoritative zone manager -> this module -> DNSSEC.

#pragma once

#include "router/dns_authoritative.hpp"
#include "router/dnssec_signer.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace router::dnssec {

enum class KeyRole : std::uint8_t { zone_signing, key_signing };

// Produces the complete apex DNSKEY resource record. The SEP flag follows the
// configured operational role; validators do not treat it as authorization.
[[nodiscard]] std::optional<dns::ZoneRecord>
make_dnskey_record(const packet::dns::Name &zone, std::uint32_t ttl,
                   const SigningKey &key, KeyRole role) noexcept;

// Signs one homogeneous RRset and returns its RRSIG record. inception and
// expiration are unsigned POSIX seconds as encoded by RFC 4034. The caller
// must enforce any refresh policy before an active signature expires.
[[nodiscard]] std::optional<dns::ZoneRecord>
sign_rrset(std::span<const dns::ZoneRecord> records,
           const dns::ZoneRecord &key_record, const SigningKey &key,
           std::uint32_t inception, std::uint32_t expiration) noexcept;

} // namespace router::dnssec
