// RFC 4035 offline zone signing. RRsets are grouped by canonical owner, class
// and type. All active keys sign during overlap, preserving rollover validity.
// NSEC bitmaps decide authoritative data and prevent glue from being signed.
// Source: ietf.dnssec.signing.rfc4034
// Source: ietf.dnssec.validation.rfc4035

#include "router/dnssec_signed_zone.hpp"

#include "router/dnssec_nsec_chain.hpp"
#include "router/dnssec_nsec3_chain.hpp"
#include "router/dnssec_record.hpp"
#include "router/dnssec_zone_signer.hpp"

#include <algorithm>

namespace router::dnssec {
namespace {

bool same_name(const packet::dns::Name &left,
               const packet::dns::Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

bool generated_type(std::uint16_t type) noexcept {
  return type == packet::dns::type_dnskey ||
         type == packet::dns::type_rrsig || type == packet::dns::type_nsec ||
         type == packet::dns::type_nsec3 ||
         type == packet::dns::type_nsec3param;
}

std::vector<packet::dns::Name>
delegation_cuts(const packet::dns::Name &origin,
                std::span<const dns::ZoneRecord> records) {
  std::vector<packet::dns::Name> cuts;
  for (const auto &record : records)
    if (record.type == packet::dns::type_ns &&
        !same_name(record.owner, origin) &&
        dns::is_subdomain(record.owner, origin) &&
        std::ranges::none_of(cuts, [&](const auto &cut) {
          return same_name(cut, record.owner);
        }))
      cuts.push_back(record.owner);
  return cuts;
}

bool should_sign(const dns::ZoneRecord &record,
                 std::span<const packet::dns::Name> cuts) noexcept {
  // Generated denial records are authoritative even when an NSEC happens to
  // share a delegation owner. NSEC3 records use hashed owners and likewise do
  // not inherit the original owner's cut classification.
  if (record.type == packet::dns::type_dnskey ||
      record.type == packet::dns::type_nsec ||
      record.type == packet::dns::type_nsec3 ||
      record.type == packet::dns::type_nsec3param)
    return true;
  for (const auto &cut : cuts) {
    if (same_name(record.owner, cut))
      // Parent-side DS is authoritative and signed. Delegation NS is referral
      // data and RFC 4035 section 2.2 explicitly forbids signing it.
      return record.type == packet::dns::type_ds;
    if (dns::is_subdomain(record.owner, cut))
      return false;
  }
  return true;
}

bool same_rrset(const dns::ZoneRecord &left,
                const dns::ZoneRecord &right) noexcept {
  return left.type == right.type && left.record_class == right.record_class &&
         same_name(left.owner, right.owner);
}

} // namespace

std::optional<std::vector<dns::ZoneRecord>> sign_zone_snapshot(
    const packet::dns::Name &origin,
    std::span<const dns::ZoneRecord> unsigned_records,
    const ZoneKeyStore &keys, std::uint64_t now,
    const ZoneSigningPolicy &policy,
    const DigestCalculator *digests) noexcept {
  if (unsigned_records.empty() || policy.dnskey_ttl == 0U ||
      policy.denial_ttl == 0U ||
      policy.denial_mode > DenialMode::nsec3_opt_out ||
      policy.signature_inception == policy.signature_expiration ||
      std::ranges::any_of(unsigned_records, [](const auto &record) {
        return generated_type(record.type);
      }))
    return std::nullopt;
  try {
    const auto ksks = keys.active(KeyRole::key_signing, now);
    const auto zsks = keys.active(KeyRole::zone_signing, now);
    const auto dnskeys = keys.published_dnskeys(origin, policy.dnskey_ttl, now);
    if (ksks.empty() || zsks.empty() || !dnskeys || dnskeys->empty())
      return std::nullopt;

    std::vector<dns::ZoneRecord> result{unsigned_records.begin(),
                                        unsigned_records.end()};
    result.insert(result.end(), dnskeys->begin(), dnskeys->end());
    if (policy.denial_mode == DenialMode::nsec) {
      const auto nsecs = build_nsec_chain(origin, result, policy.denial_ttl);
      if (!nsecs || nsecs->empty())
        return std::nullopt;
      result.insert(result.end(), nsecs->begin(), nsecs->end());
    } else {
      if (!digests)
        return std::nullopt;
      const auto nsec3 = build_nsec3_chain(
          origin, result, policy.denial_ttl,
          {.opt_out = policy.denial_mode == DenialMode::nsec3_opt_out},
          *digests);
      if (!nsec3 || nsec3->records.empty())
        return std::nullopt;
      result.push_back(nsec3->parameter);
      result.insert(result.end(), nsec3->records.begin(),
                    nsec3->records.end());
    }

    const auto cuts = delegation_cuts(origin, result);
    const auto unsigned_generation_size = result.size();
    std::vector<bool> consumed(unsigned_generation_size, false);
    for (std::size_t index{}; index < unsigned_generation_size; ++index) {
      if (consumed[index])
        continue;
      const auto &first = result[index];
      if (!should_sign(first, cuts))
        continue;
      std::vector<dns::ZoneRecord> rrset;
      for (std::size_t candidate = index; candidate < unsigned_generation_size;
           ++candidate) {
        if (!same_rrset(first, result[candidate]))
          continue;
        if (result[candidate].ttl != first.ttl)
          return std::nullopt;
        consumed[candidate] = true;
        rrset.push_back(result[candidate]);
      }
      const auto &signers = first.type == packet::dns::type_dnskey ? ksks : zsks;
      for (const auto *managed : signers) {
        const auto signer_record = make_dnskey_record(
            origin, policy.dnskey_ttl, managed->key(), managed->role());
        const auto signature = signer_record
                                   ? sign_rrset(rrset, *signer_record,
                                                managed->key(),
                                                policy.signature_inception,
                                                policy.signature_expiration)
                                   : std::nullopt;
        if (!signature)
          return std::nullopt;
        result.push_back(*signature);
      }
    }
    return result;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace router::dnssec
