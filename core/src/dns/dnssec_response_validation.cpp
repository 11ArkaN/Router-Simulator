// Whole-response DNSSEC validation for an authenticated zone. No record may
// enter resolver cache through this module unless its RRset signature and any
// required denial proof succeed. Source: ietf.dnssec.validation.rfc4035
// Source: ietf.dnssec.nsec3.rfc5155

#include "router/dnssec_response_validation.hpp"

#include <algorithm>
#include <optional>
#include <vector>

namespace router::dnssec {
namespace {

using Name = packet::dns::Name;
using Record = dns::ZoneRecord;

bool same_name(const Name &left, const Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

std::optional<std::size_t> label_count(const Name &name) noexcept {
  Name checked;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, checked);
  if (!consumed || *consumed != name.octets)
    return std::nullopt;
  std::size_t count{};
  for (std::size_t offset{}; offset < name.octets;) {
    const auto length = name.wire[offset++];
    if (length == 0U)
      return count;
    offset += length;
    ++count;
  }
  return std::nullopt;
}

bool same_rrset(const Record &left, const Record &right) noexcept {
  return left.type == right.type &&
         left.record_class == right.record_class &&
         same_name(left.owner, right.owner);
}

bool signature_covers(const Record &signature, const Record &rrset) noexcept {
  if (signature.type != packet::dns::type_rrsig ||
      signature.record_class != rrset.record_class ||
      !same_name(signature.owner, rrset.owner))
    return false;
  const auto decoded = decode_rrsig(signature.rdata);
  return decoded && decoded->type_covered == rrset.type;
}

struct ValidatedSet {
  ValidationResult validation;
  std::vector<Record> records;
};

std::optional<ValidatedSet> validate_set(
    const Record &first, std::span<const Record> answers,
    std::span<const Record> authorities, std::span<const Record> dnskeys,
    std::uint32_t now, const CryptoVerifier &crypto) {
  ValidatedSet result;
  std::vector<Record> signatures;
  const auto collect = [&](std::span<const Record> section) {
    for (const auto &record : section) {
      if (same_rrset(record, first))
        result.records.push_back(record);
      else if (signature_covers(record, first))
        signatures.push_back(record);
    }
  };
  collect(answers);
  collect(authorities);
  if (result.records.empty() || signatures.empty())
    return std::nullopt;
  result.validation =
      validate_rrset(result.records, signatures, dnskeys, now, crypto);
  return result;
}

void clamp_validated_ttl(const Record &first, std::span<Record> answers,
                         std::span<Record> authorities,
                         const ValidationResult &validation,
                         std::uint32_t now) noexcept {
  // RFC 4035 section 5.3.3 limits a validated RRset by received TTL,
  // RRSIG Original TTL and signature lifetime. Unsigned referral NS is never
  // passed here, so its parent-provided TTL remains independent.
  const auto limit = std::min(validation.original_ttl,
                              validation.valid_until - now);
  const auto clamp = [&](std::span<Record> section) {
    for (auto &record : section)
      if (same_rrset(record, first) || signature_covers(record, first))
        record.ttl = std::min(record.ttl, limit);
  };
  clamp(answers);
  clamp(authorities);
}

bool already_seen(const Record &record,
                  std::span<const Record> seen) noexcept {
  return std::ranges::any_of(seen, [&](const auto &entry) {
    return same_rrset(entry, record);
  });
}

ResponseValidationResult failed_set(const ValidationResult &validation) {
  return {.security = validation.state == ValidationState::indeterminate
                          ? ResponseSecurity::indeterminate
                          : ResponseSecurity::bogus,
          .failure = ResponseValidationFailure::invalid_rrset,
          .rrset_failure = validation.failure};
}

std::optional<Name> cname_terminal(const packet::dns::Question &question,
                                   std::span<const Record> answers) noexcept {
  try {
    Name current = question.name;
    // A CNAME query asks for the alias RRset itself. Following its target here
    // would incorrectly demand a second CNAME RRset at the canonical name.
    if (question.type == packet::dns::type_cname)
      return current;
    std::vector<Name> visited{current};
    for (;;) {
      const auto alias = std::ranges::find_if(answers, [&](const auto &record) {
        return record.type == packet::dns::type_cname &&
               same_name(record.owner, current);
      });
      if (alias == answers.end())
        return current;
      Name target;
      const auto consumed =
          packet::dns::parse_name(alias->rdata, 0U, target);
      if (!consumed || *consumed != alias->rdata.size() ||
          std::ranges::any_of(visited, [&](const auto &seen) {
            return same_name(seen, target);
          }))
        return std::nullopt;
      visited.push_back(target);
      current = target;
      // A response contains a finite number of CNAME RRsets. Crossing more
      // aliases than it carries proves a cycle or duplicate-owner conflict,
      // so no independent arbitrary hop ceiling is needed here.
      if (visited.size() > answers.size() + 1U)
        return std::nullopt;
    }
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Name> referral_owner(const Name &qname, const Name &zone,
                                   std::span<const Record> authorities) noexcept {
  std::optional<Name> selected;
  std::size_t selected_labels{};
  for (const auto &record : authorities) {
    if (record.type != packet::dns::type_ns || same_name(record.owner, zone) ||
        !dns::is_subdomain(qname, record.owner))
      continue;
    const auto count = label_count(record.owner);
    if (!count)
      return std::nullopt;
    if (!selected || *count > selected_labels) {
      selected = record.owner;
      selected_labels = *count;
    }
  }
  return selected;
}

bool nsec3_proved(Nsec3ProofState state) noexcept {
  return state == Nsec3ProofState::proved;
}

} // namespace

ResponseValidationResult validate_secure_zone_response(
    const packet::dns::Question &question, packet::dns::Rcode rcode,
    std::span<Record> answers, std::span<Record> authorities,
    const Name &zone, std::span<const Record> dnskeys, std::uint32_t now,
    const CryptoVerifier &crypto, const DigestCalculator &digests,
    Nsec3IterationPolicy nsec3_policy) noexcept {
  if (dnskeys.empty() ||
      (rcode != packet::dns::Rcode::no_error &&
       rcode != packet::dns::Rcode::name_error))
    return {.security = ResponseSecurity::indeterminate,
            .failure = ResponseValidationFailure::malformed_response};
  try {
    std::vector<Record> seen;
    std::vector<AuthenticatedNsec> nsecs;
    std::vector<AuthenticatedNsec3> nsec3s;
    bool wildcard{};

    // Validate every answer RRset. A single valid signature authenticates the
    // complete RRset, including all records, never just one convenient value.
    for (const auto &record : answers) {
      if (record.type == packet::dns::type_rrsig ||
          already_seen(record, seen))
        continue;
      const auto set = validate_set(record, answers, authorities, dnskeys, now,
                                    crypto);
      if (!set)
        return {.security = ResponseSecurity::bogus,
                .failure = ResponseValidationFailure::missing_signature};
      if (set->validation.state != ValidationState::secure)
        return failed_set(set->validation);
      clamp_validated_ttl(record, answers, authorities, set->validation, now);
      const auto owner_labels = label_count(record.owner);
      if (!owner_labels || set->validation.labels > *owner_labels)
        return {.security = ResponseSecurity::bogus,
                .failure = ResponseValidationFailure::malformed_response};
      wildcard = wildcard || set->validation.labels < *owner_labels;
      seen.push_back(record);
    }

    // Authority NS at a zone cut and glue are deliberately unsigned. Every
    // other authority RRset is parent-authoritative and must validate.
    const auto cut = referral_owner(question.name, zone, authorities);
    for (const auto &record : authorities) {
      if (record.type == packet::dns::type_rrsig ||
          (cut && record.type == packet::dns::type_ns &&
           same_name(record.owner, *cut)) ||
          already_seen(record, seen))
        continue;
      const auto set = validate_set(record, answers, authorities, dnskeys, now,
                                    crypto);
      if (!set)
        return {.security = ResponseSecurity::bogus,
                .failure = ResponseValidationFailure::missing_signature};
      if (set->validation.state != ValidationState::secure)
        return failed_set(set->validation);
      clamp_validated_ttl(record, answers, authorities, set->validation, now);
      if (record.type == packet::dns::type_nsec)
        for (const auto &member : set->records) {
          auto authenticated = authenticate_nsec(member, set->validation);
          if (!authenticated)
            return {.security = ResponseSecurity::bogus,
                    .failure =
                        ResponseValidationFailure::malformed_response};
          nsecs.push_back(std::move(*authenticated));
        }
      if (record.type == packet::dns::type_nsec3)
        for (const auto &member : set->records) {
          auto authenticated = authenticate_nsec3(member, set->validation);
          if (!authenticated)
            return {.security = ResponseSecurity::bogus,
                    .failure =
                        ResponseValidationFailure::malformed_response};
          nsec3s.push_back(std::move(*authenticated));
        }
      seen.push_back(record);
    }

    if (cut) {
      const bool has_ds = std::ranges::any_of(authorities, [&](const auto &rr) {
        return rr.type == packet::dns::type_ds && same_name(rr.owner, *cut);
      });
      if (has_ds)
        return {.security = ResponseSecurity::secure,
                .failure = ResponseValidationFailure::none};
      const auto nsec_proof = prove_nsec_no_ds(*cut, nsecs);
      const auto nsec3_proof = prove_nsec3_no_ds(
          *cut, zone, nsec3s, nsec3_policy, digests);
      if (nsec_proof || nsec3_proved(nsec3_proof))
        return {.security = ResponseSecurity::insecure_delegation,
                .failure = ResponseValidationFailure::none};
      return {.security = ResponseSecurity::bogus,
              .failure = ResponseValidationFailure::missing_denial};
    }

    const auto terminal = cname_terminal(question, answers);
    if (!terminal)
      return {.security = ResponseSecurity::bogus,
              .failure = ResponseValidationFailure::malformed_response};

    if (rcode == packet::dns::Rcode::name_error) {
      const auto proved = prove_nsec_name_error(*terminal, nsecs) ||
                          nsec3_proved(prove_nsec3_name_error(
                              *terminal, zone, nsec3s, nsec3_policy, digests));
      return proved
                 ? ResponseValidationResult{
                       .security = ResponseSecurity::secure,
                       .failure = ResponseValidationFailure::none}
                 : ResponseValidationResult{
                       .security = ResponseSecurity::bogus,
                       .failure = ResponseValidationFailure::missing_denial};
    }

    const bool has_terminal_answer =
        std::ranges::any_of(answers, [&](const auto &record) {
          return record.type == question.type &&
                 same_name(record.owner, *terminal);
        });
    if (!has_terminal_answer) {
      const auto proved =
          prove_nsec_nodata(*terminal, question.type, nsecs) ||
          prove_nsec_wildcard_nodata(*terminal, question.type, nsecs) ||
          nsec3_proved(prove_nsec3_nodata(*terminal, question.type, zone,
                                          nsec3s, nsec3_policy, digests)) ||
          nsec3_proved(prove_nsec3_wildcard_nodata(
              *terminal, question.type, zone, nsec3s, nsec3_policy, digests));
      return proved
                 ? ResponseValidationResult{
                       .security = ResponseSecurity::secure,
                       .failure = ResponseValidationFailure::none}
                 : ResponseValidationResult{
                       .security = ResponseSecurity::bogus,
                       .failure = ResponseValidationFailure::missing_denial};
    }

    if (wildcard) {
      // Each verified answer carries its own Labels value. All wildcard
      // answer RRsets must receive a proof, not merely the first one found.
      for (const auto &record : answers) {
        if (record.type == packet::dns::type_rrsig)
          continue;
        const auto set = validate_set(record, answers, authorities, dnskeys,
                                      now, crypto);
        const auto count = label_count(record.owner);
        if (!set || !count || set->validation.labels >= *count)
          continue;
        if (!prove_nsec_wildcard_expansion(record.owner,
                                           set->validation.labels, nsecs) &&
            !nsec3_proved(prove_nsec3_wildcard_expansion(
                record.owner, set->validation.labels, zone, nsec3s,
                nsec3_policy, digests)))
          return {.security = ResponseSecurity::bogus,
                  .failure = ResponseValidationFailure::missing_denial,
                  .wildcard_expansion = true};
      }
    }
    return {.security = ResponseSecurity::secure,
            .failure = ResponseValidationFailure::none,
            .wildcard_expansion = wildcard};
  } catch (...) {
    return {.security = ResponseSecurity::indeterminate,
            .failure = ResponseValidationFailure::resource_exhausted};
  }
}

} // namespace router::dnssec
