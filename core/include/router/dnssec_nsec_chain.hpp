// Offline NSEC chain construction for one authoritative zone. The caller owns
// unsigned zone records and chooses the denial TTL. This module returns owned
// NSEC records and never mutates the source zone or signs records.

#pragma once

#include "router/dns_authoritative.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dnssec {

// The chain contains each authoritative RR owner in RFC 4034 canonical order.
// Glue below a zone cut is excluded. Every bitmap anticipates the NSEC's RRSIG
// because callers must sign the completed chain before serving it.
[[nodiscard]] std::optional<std::vector<dns::ZoneRecord>>
build_nsec_chain(const packet::dns::Name &origin,
                 std::span<const dns::ZoneRecord> records,
                 std::uint32_t denial_ttl) noexcept;

} // namespace router::dnssec
