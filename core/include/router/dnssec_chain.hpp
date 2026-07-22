// DNSSEC trust-anchor and delegation-chain validation. TrustAnchorStore owns
// configured anchor records. Callers own live DNS responses and wall time.
// Signature and digest work is delegated through narrow provider interfaces.
// Dependency direction: resolver -> chain -> record/validation contracts.

#pragma once

#include "router/dnssec_validation.hpp"

#include <span>
#include <vector>

namespace router::dnssec {

enum class ChainState : std::uint8_t { secure, insecure, bogus, indeterminate };

enum class ChainFailure : std::uint8_t {
  none,
  malformed_dnskey,
  malformed_ds,
  no_trust_anchor,
  no_delegation_proof,
  unsupported_digest,
  ds_mismatch,
  dnskey_signature_invalid,
  resource_exhausted
};

struct ChainResult {
  ChainState state{ChainState::indeterminate};
  ChainFailure failure{ChainFailure::no_delegation_proof};
  std::uint16_t key_tag{};
  std::uint8_t algorithm{};
  std::uint32_t valid_until{};
};

enum class AnchorMutation : std::uint8_t {
  applied,
  duplicate,
  not_found,
  invalid_record,
  resource_exhausted
};

class TrustAnchorStore {
public:
  // Anchors are complete DNSKEY records, including owner and RDATA. add makes
  // an owned copy so project configuration cannot mutate live trust state.
  [[nodiscard]] AnchorMutation add(const dns::ZoneRecord &dnskey) noexcept;
  [[nodiscard]] AnchorMutation remove(const dns::ZoneRecord &dnskey) noexcept;
  void clear() noexcept { anchors_.clear(); }
  [[nodiscard]] std::span<const dns::ZoneRecord> records() const noexcept {
    return anchors_;
  }

private:
  std::vector<dns::ZoneRecord> anchors_;
};

// A configured trust anchor validates only when that exact key is present and
// signs the DNSKEY RRset. Another key in the same response cannot silently
// replace the configured anchor.
[[nodiscard]] ChainResult validate_from_trust_anchor(
    std::span<const dns::ZoneRecord> dnskeys,
    std::span<const dns::ZoneRecord> signatures,
    const TrustAnchorStore &anchors, std::uint32_t now,
    const CryptoVerifier &crypto) noexcept;

// Parent DS records must already belong to an authenticated parent response.
// An empty span is indeterminate, never insecure, because absence requires a
// separately validated NSEC or NSEC3 proof.
[[nodiscard]] ChainResult validate_dnskey_delegation(
    std::span<const dns::ZoneRecord> dnskeys,
    std::span<const dns::ZoneRecord> signatures,
    std::span<const dns::ZoneRecord> parent_ds, std::uint32_t now,
    const CryptoVerifier &crypto,
    const DigestCalculator &digests) noexcept;

// The denial module is the only intended caller. An authenticated absence of
// DS establishes an insecure delegation; an unauthenticated absence does not.
[[nodiscard]] constexpr ChainResult
classify_unsigned_delegation(bool authenticated_absence) noexcept {
  return authenticated_absence
             ? ChainResult{.state = ChainState::insecure,
                           .failure = ChainFailure::none}
             : ChainResult{.state = ChainState::indeterminate,
                           .failure = ChainFailure::no_delegation_proof};
}

} // namespace router::dnssec
