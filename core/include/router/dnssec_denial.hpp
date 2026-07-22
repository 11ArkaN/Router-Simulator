// Authenticated NSEC denial proofs. The module owns temporary decoded NSEC
// values only. Resolver cache and RRset validation remain external owners.
// An AuthenticatedNsec can be created only from a secure validation result,
// preventing unverified denial data from being treated as authoritative.

#pragma once

#include "router/dnssec_validation.hpp"

#include <optional>
#include <span>
#include <utility>

namespace router::dnssec {

class AuthenticatedNsec {
public:
  [[nodiscard]] const dns::ZoneRecord &record() const noexcept {
    return record_;
  }
  [[nodiscard]] const Nsec &value() const noexcept { return value_; }

private:
  friend std::optional<AuthenticatedNsec>
  authenticate_nsec(const dns::ZoneRecord &, const ValidationResult &) noexcept;
  AuthenticatedNsec(dns::ZoneRecord record, Nsec value)
      : record_(std::move(record)), value_(std::move(value)) {}

  dns::ZoneRecord record_;
  Nsec value_;
};

// Returns no value unless the exact NSEC RRset was cryptographically secure.
// The owned copy prevents cache eviction or mutation from invalidating a proof
// while it is evaluated.
[[nodiscard]] std::optional<AuthenticatedNsec>
authenticate_nsec(const dns::ZoneRecord &record,
                  const ValidationResult &validation) noexcept;

// Canonical DNSSEC name order compares labels from the root toward the leaf,
// folds ASCII case and orders an otherwise equal shorter label first.
[[nodiscard]] std::optional<int>
canonical_name_compare(const packet::dns::Name &left,
                       const packet::dns::Name &right) noexcept;

// Exact-owner bitmap proof for an existing name that lacks qtype and CNAME.
[[nodiscard]] bool prove_nsec_nodata(
    const packet::dns::Name &name, std::uint16_t qtype,
    std::span<const AuthenticatedNsec> nsecs) noexcept;

// NXDOMAIN requires both the next-closer name and the wildcard at the closest
// encloser to be covered. One interval alone can satisfy both only if it truly
// covers both canonical names.
[[nodiscard]] bool prove_nsec_name_error(
    const packet::dns::Name &name,
    std::span<const AuthenticatedNsec> nsecs) noexcept;

[[nodiscard]] bool prove_nsec_wildcard_nodata(
    const packet::dns::Name &name, std::uint16_t qtype,
    std::span<const AuthenticatedNsec> nsecs) noexcept;

// A positive answer whose RRSIG Labels field is smaller than QNAME was
// synthesized from a wildcard. RFC 4035 section 5.3.4 requires an
// authenticated NSEC interval covering the next-closer name. The signature
// itself authenticates the wildcard owner, so this proof must not also demand
// wildcard non-existence as an NXDOMAIN proof would.
[[nodiscard]] bool prove_nsec_wildcard_expansion(
    const packet::dns::Name &name, std::uint8_t wildcard_labels,
    std::span<const AuthenticatedNsec> nsecs) noexcept;

// At a delegation, authenticated NS presence with DS and SOA absence proves
// an insecure child. This result can feed classify_unsigned_delegation(true).
[[nodiscard]] bool prove_nsec_no_ds(
    const packet::dns::Name &delegation,
    std::span<const AuthenticatedNsec> nsecs) noexcept;

enum class Nsec3ProofState : std::uint8_t {
  proved,
  not_proved,
  unsupported_iterations,
  malformed,
  resource_exhausted
};

struct Nsec3IterationPolicy {
  // RFC 9276 recommends zero additional iterations for publishers and permits
  // validators to reject larger values. The selected resolver profile owns
  // this explicit policy, so the protocol module has no hidden CPU ceiling.
  std::uint16_t maximum{0U};
};

class AuthenticatedNsec3 {
public:
  [[nodiscard]] const dns::ZoneRecord &record() const noexcept {
    return record_;
  }
  [[nodiscard]] const Nsec3 &value() const noexcept { return value_; }

private:
  friend std::optional<AuthenticatedNsec3>
  authenticate_nsec3(const dns::ZoneRecord &, const ValidationResult &) noexcept;
  AuthenticatedNsec3(dns::ZoneRecord record, Nsec3 value)
      : record_(std::move(record)), value_(std::move(value)) {}

  dns::ZoneRecord record_;
  Nsec3 value_;
};

[[nodiscard]] std::optional<AuthenticatedNsec3>
authenticate_nsec3(const dns::ZoneRecord &record,
                   const ValidationResult &validation) noexcept;

// RFC 5155 hashes the lowercase canonical name once and then performs the
// configured number of additional SHA-1 hashes over previous_hash || salt.
[[nodiscard]] Nsec3ProofState nsec3_hash(
    const packet::dns::Name &name, const Nsec3 &parameters,
    Nsec3IterationPolicy policy, const DigestCalculator &digests,
    std::vector<std::uint8_t> &output) noexcept;

[[nodiscard]] Nsec3ProofState prove_nsec3_nodata(
    const packet::dns::Name &name, std::uint16_t qtype,
    const packet::dns::Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept;

[[nodiscard]] Nsec3ProofState prove_nsec3_name_error(
    const packet::dns::Name &name, const packet::dns::Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept;

[[nodiscard]] Nsec3ProofState prove_nsec3_wildcard_nodata(
    const packet::dns::Name &name, std::uint16_t qtype,
    const packet::dns::Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept;

[[nodiscard]] Nsec3ProofState prove_nsec3_wildcard_expansion(
    const packet::dns::Name &name, std::uint8_t wildcard_labels,
    const packet::dns::Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept;

[[nodiscard]] Nsec3ProofState prove_nsec3_no_ds(
    const packet::dns::Name &delegation, const packet::dns::Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept;

} // namespace router::dnssec
