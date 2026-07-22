// Offline NSEC3 chain construction for one authoritative zone. The caller
// owns source records and digest provider. This module owns temporary names,
// hashes and output records, but never signs records or mutates a live Zone.

#pragma once

#include "router/dnssec_denial.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dnssec {

struct Nsec3PublisherPolicy {
  // Opt-Out is an explicit operator choice suitable only for large delegation
  // zones. RFC 9276 requires publishers to use zero additional iterations and
  // recommends an empty salt, so unsafe alternate values are not exposed.
  bool opt_out{};
};

struct Nsec3Chain {
  dns::ZoneRecord parameter;
  std::vector<dns::ZoneRecord> records;
};

// The result includes an apex NSEC3PARAM and the complete circular SHA-1 hash
// chain. Empty non-terminals are present. Glue is absent. Under Opt-Out only
// unsigned delegation owners may be omitted, and only covering spans carry
// the Opt-Out flag. A hash collision fails the whole transaction.
[[nodiscard]] std::optional<Nsec3Chain> build_nsec3_chain(
    const packet::dns::Name &origin,
    std::span<const dns::ZoneRecord> records, std::uint32_t denial_ttl,
    Nsec3PublisherPolicy policy,
    const DigestCalculator &digests) noexcept;

} // namespace router::dnssec
