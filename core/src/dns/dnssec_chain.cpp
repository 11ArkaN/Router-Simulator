// RFC 4035 section 5.2 authentication of DNSKEY RRsets from trust anchors or
// DS records. This layer does not infer unsigned delegations from missing data.
// Source: ietf.dnssec.chain.rfc4035

#include "router/dnssec_chain.hpp"

#include "router/dnssec_record.hpp"

#include <algorithm>

namespace router::dnssec {
namespace {

bool same_record(const dns::ZoneRecord &left,
                 const dns::ZoneRecord &right) noexcept {
  return left.type == right.type && left.record_class == right.record_class &&
         packet::dns::equal_case_insensitive(left.owner, right.owner) &&
         left.rdata == right.rdata;
}

bool eligible_key_record(const dns::ZoneRecord &record) noexcept {
  if (record.type != packet::dns::type_dnskey)
    return false;
  const auto key = decode_dnskey(record.rdata);
  return key && (key->flags & dnskey_zone_flag) != 0U;
}

bool append_canonical_owner(const packet::dns::Name &owner,
                            std::vector<std::uint8_t> &output) noexcept {
  packet::dns::Name parsed;
  const auto consumed = packet::dns::parse_name(owner.view(), 0U, parsed);
  if (!consumed || *consumed != owner.octets)
    return false;
  for (std::size_t offset{}; offset < parsed.octets && parsed.wire[offset] != 0U;) {
    const auto length = parsed.wire[offset++];
    for (std::size_t index{}; index < length; ++index) {
      auto &octet = parsed.wire[offset + index];
      if (octet >= 'A' && octet <= 'Z')
        octet = static_cast<std::uint8_t>(octet + ('a' - 'A'));
    }
    offset += length;
  }
  try {
    output.insert(output.end(), parsed.wire.begin(),
                  parsed.wire.begin() + parsed.octets);
    return true;
  } catch (...) {
    return false;
  }
}

ChainResult signature_result(const ValidationResult &result) noexcept {
  if (result.state == ValidationState::secure)
    return {.state = ChainState::secure,
            .failure = ChainFailure::none,
            .key_tag = result.key_tag,
            .algorithm = result.algorithm,
            .valid_until = result.valid_until};
  return {.state = result.state == ValidationState::indeterminate
                       ? ChainState::indeterminate
                       : ChainState::bogus,
          .failure = ChainFailure::dnskey_signature_invalid};
}

} // namespace

AnchorMutation TrustAnchorStore::add(const dns::ZoneRecord &dnskey) noexcept {
  if (!eligible_key_record(dnskey))
    return AnchorMutation::invalid_record;
  if (std::ranges::any_of(anchors_, [&](const auto &existing) {
        return same_record(existing, dnskey);
      }))
    return AnchorMutation::duplicate;
  try {
    anchors_.push_back(dnskey);
    return AnchorMutation::applied;
  } catch (...) {
    return AnchorMutation::resource_exhausted;
  }
}

AnchorMutation TrustAnchorStore::remove(
    const dns::ZoneRecord &dnskey) noexcept {
  const auto found = std::ranges::find_if(anchors_, [&](const auto &existing) {
    return same_record(existing, dnskey);
  });
  if (found == anchors_.end())
    return AnchorMutation::not_found;
  anchors_.erase(found);
  return AnchorMutation::applied;
}

ChainResult validate_from_trust_anchor(
    std::span<const dns::ZoneRecord> dnskeys,
    std::span<const dns::ZoneRecord> signatures,
    const TrustAnchorStore &anchors, std::uint32_t now,
    const CryptoVerifier &crypto) noexcept {
  if (dnskeys.empty())
    return {.state = ChainState::bogus,
            .failure = ChainFailure::malformed_dnskey};
  try {
    std::vector<dns::ZoneRecord> matching;
    for (const auto &anchor : anchors.records())
      for (const auto &key : dnskeys)
        if (same_record(anchor, key)) {
          matching.push_back(anchor);
          break;
        }
    if (matching.empty())
      return {.state = ChainState::indeterminate,
              .failure = ChainFailure::no_trust_anchor};
    return signature_result(
        validate_rrset(dnskeys, signatures, matching, now, crypto));
  } catch (...) {
    return {.state = ChainState::indeterminate,
            .failure = ChainFailure::resource_exhausted};
  }
}

ChainResult validate_dnskey_delegation(
    std::span<const dns::ZoneRecord> dnskeys,
    std::span<const dns::ZoneRecord> signatures,
    std::span<const dns::ZoneRecord> parent_ds, std::uint32_t now,
    const CryptoVerifier &crypto,
    const DigestCalculator &digests) noexcept {
  if (dnskeys.empty())
    return {.state = ChainState::bogus,
            .failure = ChainFailure::malformed_dnskey};
  if (parent_ds.empty())
    return {.state = ChainState::indeterminate,
            .failure = ChainFailure::no_delegation_proof};

  bool supported_ds{};
  bool valid_ds{};
  try {
    std::vector<dns::ZoneRecord> matched_keys;
    for (const auto &ds_record : parent_ds) {
      if (ds_record.type != packet::dns::type_ds ||
          !packet::dns::equal_case_insensitive(ds_record.owner,
                                               dnskeys.front().owner))
        return {.state = ChainState::bogus,
                .failure = ChainFailure::malformed_ds};
      const auto ds = decode_ds(ds_record.rdata);
      if (!ds)
        return {.state = ChainState::bogus,
                .failure = ChainFailure::malformed_ds};
      // RFC 6840 section 5.2 says a delegation with no DS combination that
      // the validator supports is treated as insecure. Both the DNSKEY
      // algorithm and DS digest algorithm must therefore be usable before a
      // record can make a failed match bogus.
      if (!crypto.supports(ds->algorithm) ||
          !digests.supports_digest(ds->digest_type))
        continue;
      supported_ds = true;

      for (const auto &key_record : dnskeys) {
        if (!eligible_key_record(key_record) ||
            !packet::dns::equal_case_insensitive(key_record.owner,
                                                 ds_record.owner))
          continue;
        const auto key = decode_dnskey(key_record.rdata);
        if (!key || key->algorithm != ds->algorithm ||
            key_tag(key_record.rdata) != ds->key_tag)
          continue;
        std::vector<std::uint8_t> digest_input;
        if (!append_canonical_owner(key_record.owner, digest_input))
          return {.state = ChainState::indeterminate,
                  .failure = ChainFailure::resource_exhausted};
        digest_input.insert(digest_input.end(), key_record.rdata.begin(),
                            key_record.rdata.end());
        std::vector<std::uint8_t> actual_digest;
        if (!digests.calculate_digest(ds->digest_type, digest_input,
                                      actual_digest))
          continue;
        if (actual_digest == ds->digest) {
          valid_ds = true;
          matched_keys.push_back(key_record);
        }
      }
    }
    if (!supported_ds)
      return {.state = ChainState::insecure,
              .failure = ChainFailure::unsupported_digest};
    if (!valid_ds)
      return {.state = ChainState::bogus,
              .failure = ChainFailure::ds_mismatch};
    return signature_result(
        validate_rrset(dnskeys, signatures, matched_keys, now, crypto));
  } catch (...) {
    return {.state = ChainState::indeterminate,
            .failure = ChainFailure::resource_exhausted};
  }
}

} // namespace router::dnssec
