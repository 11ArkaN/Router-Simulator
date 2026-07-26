// RFC 4035 sections 3.1.1 through 3.1.4 signed authoritative response rules.
// Selection happens after ordinary DNS semantics so DNSSEC cannot change the
// underlying existence, wildcard, delegation or alias decision.
// Source: ietf.dnssec.validation.rfc4035

#include "router/dnssec_authoritative_response.hpp"

#include "router/dnssec_denial.hpp"
#include "router/dnssec_record.hpp"

#include <algorithm>
#include <array>

namespace router::dnssec {
namespace {

using packet::dns::Name;
using packet::dns::RecordData;

bool same_name(const Name &left, const Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

RecordData view(const dns::ZoneRecord &record, const Name &response_owner) {
  return {.owner = response_owner,
          .type = record.type,
          .record_class = record.record_class,
          .ttl = record.ttl,
          .rdata = record.rdata};
}

bool same_view(const RecordData &left, const RecordData &right) noexcept {
  return left.type == right.type && left.record_class == right.record_class &&
         same_name(left.owner, right.owner) &&
         std::ranges::equal(left.rdata, right.rdata);
}

void append_unique(std::vector<RecordData> &section, RecordData record) {
  if (std::ranges::none_of(section, [&](const auto &existing) {
        return same_view(existing, record);
      }))
    section.push_back(record);
}

bool append_signatures(const dns::Zone &zone, const Name &source_owner,
                       const Name &response_owner, std::uint16_t covered_type,
                       std::vector<RecordData> &section) {
  for (const auto &candidate : zone.records()) {
    if (candidate.type != packet::dns::type_rrsig ||
        !same_name(candidate.owner, source_owner))
      continue;
    const auto signature = decode_rrsig(candidate.rdata);
    if (!signature)
      return false;
    if (signature->type_covered == covered_type)
      append_unique(section, view(candidate, response_owner));
  }
  return true;
}

const dns::ZoneRecord *exact_nsec(const dns::Zone &zone,
                                  const Name &owner) noexcept {
  const auto found = std::ranges::find_if(zone.records(), [&](const auto &record) {
    return record.type == packet::dns::type_nsec &&
           same_name(record.owner, owner);
  });
  return found == zone.records().end() ? nullptr : &*found;
}

bool interval_covers(const dns::ZoneRecord &record, const Nsec &nsec,
                     const Name &name) noexcept {
  const auto owner_to_name = canonical_name_compare(record.owner, name);
  const auto name_to_next = canonical_name_compare(name, nsec.next_domain);
  const auto owner_to_next =
      canonical_name_compare(record.owner, nsec.next_domain);
  if (!owner_to_name || !name_to_next || !owner_to_next || *owner_to_name == 0)
    return false;
  if (*owner_to_next < 0)
    return *owner_to_name < 0 && *name_to_next < 0;
  if (*owner_to_next > 0)
    return *owner_to_name < 0 || *name_to_next < 0;
  return true;
}

const dns::ZoneRecord *covering_nsec(const dns::Zone &zone,
                                     const Name &name) noexcept {
  for (const auto &record : zone.records()) {
    if (record.type != packet::dns::type_nsec)
      continue;
    const auto nsec = decode_nsec(record.rdata);
    if (nsec && interval_covers(record, *nsec, name))
      return &record;
  }
  return nullptr;
}

bool append_nsec(const dns::Zone &zone, const dns::ZoneRecord &nsec,
                 std::vector<RecordData> &authorities) {
  append_unique(authorities, view(nsec, nsec.owner));
  return append_signatures(zone, nsec.owner, nsec.owner,
                           packet::dns::type_nsec, authorities);
}

std::optional<std::vector<std::uint8_t>> decode_base32hex(
    std::span<const std::uint8_t> text) noexcept {
  try {
    std::vector<std::uint8_t> output;
    output.reserve((text.size() * 5U) / 8U);
    std::uint32_t bits{};
    unsigned count{};
    for (const auto octet : text) {
      const auto upper = octet >= 'a' && octet <= 'v'
                             ? static_cast<std::uint8_t>(octet - ('a' - 'A'))
                             : octet;
      const auto value =
          octet >= '0' && octet <= '9'
              ? std::optional<std::uint8_t>{
                    static_cast<std::uint8_t>(octet - '0')}
              : upper >= 'A' && upper <= 'V'
                    ? std::optional<std::uint8_t>{static_cast<std::uint8_t>(
                          10U + upper - 'A')}
                    : std::nullopt;
      if (!value)
        return std::nullopt;
      bits = (bits << 5U) | *value;
      count += 5U;
      if (count >= 8U) {
        count -= 8U;
        output.push_back(static_cast<std::uint8_t>(bits >> count));
        bits &= count == 0U ? 0U : (1U << count) - 1U;
      }
    }
    if (count != 0U && bits != 0U)
      return std::nullopt;
    return output;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::vector<std::uint8_t>> nsec3_owner_hash(
    const dns::ZoneRecord &record, const Name &origin) noexcept {
  const auto label_length = record.owner.wire[0];
  if (record.type != packet::dns::type_nsec3 || label_length == 0U ||
      1U + label_length >= record.owner.octets)
    return std::nullopt;
  Name suffix;
  suffix.octets = static_cast<std::uint16_t>(
      record.owner.octets - 1U - label_length);
  std::copy_n(record.owner.wire.begin() + 1U + label_length, suffix.octets,
              suffix.wire.begin());
  if (!same_name(suffix, origin))
    return std::nullopt;
  return decode_base32hex(std::span<const std::uint8_t>{record.owner.wire}
                              .subspan(1U, label_length));
}

bool hash_covers(std::span<const std::uint8_t> owner,
                 std::span<const std::uint8_t> next,
                 std::span<const std::uint8_t> value) noexcept {
  if (std::ranges::equal(owner, value))
    return false;
  const auto owner_next = std::lexicographical_compare_three_way(
      owner.begin(), owner.end(), next.begin(), next.end());
  const auto owner_value = std::lexicographical_compare_three_way(
      owner.begin(), owner.end(), value.begin(), value.end());
  const auto value_next = std::lexicographical_compare_three_way(
      value.begin(), value.end(), next.begin(), next.end());
  if (owner_next < 0)
    return owner_value < 0 && value_next < 0;
  if (owner_next > 0)
    return owner_value < 0 || value_next < 0;
  return true;
}

std::optional<Nsec3param> nsec3_parameter(const dns::Zone &zone) noexcept {
  for (const auto &record : zone.records())
    if (record.type == packet::dns::type_nsec3param &&
        same_name(record.owner, zone.origin()))
      return decode_nsec3param(record.rdata);
  return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> hash_name(
    const Name &name, const Nsec3param &parameter,
    const DigestCalculator &digests) noexcept {
  Nsec3 value{.hash_algorithm = parameter.hash_algorithm,
              .flags = 0U,
              .iterations = parameter.iterations,
              .salt = parameter.salt,
              .next_hashed_owner = std::vector<std::uint8_t>(20U),
              .types = {}};
  std::vector<std::uint8_t> hash;
  return nsec3_hash(name, value,
                    {.maximum = parameter.iterations}, digests, hash) ==
                 Nsec3ProofState::proved
             ? std::optional{std::move(hash)}
             : std::nullopt;
}

const dns::ZoneRecord *exact_nsec3(
    const dns::Zone &zone, std::span<const std::uint8_t> hash) noexcept {
  for (const auto &record : zone.records()) {
    const auto owner = nsec3_owner_hash(record, zone.origin());
    if (owner && std::ranges::equal(*owner, hash))
      return &record;
  }
  return nullptr;
}

const dns::ZoneRecord *covering_nsec3(
    const dns::Zone &zone, std::span<const std::uint8_t> hash) noexcept {
  for (const auto &record : zone.records()) {
    const auto owner = nsec3_owner_hash(record, zone.origin());
    const auto value = decode_nsec3(record.rdata);
    if (owner && value &&
        hash_covers(*owner, value->next_hashed_owner, hash))
      return &record;
  }
  return nullptr;
}

bool append_nsec3(const dns::Zone &zone, const dns::ZoneRecord &nsec3,
                  std::vector<RecordData> &authorities) {
  append_unique(authorities, view(nsec3, nsec3.owner));
  return append_signatures(zone, nsec3.owner, nsec3.owner,
                           packet::dns::type_nsec3, authorities);
}

std::optional<std::size_t> labels(const Name &name) noexcept {
  Name checked;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, checked);
  if (!consumed || *consumed != name.octets)
    return std::nullopt;
  std::size_t count{};
  for (std::size_t offset{}; offset < name.octets && name.wire[offset] != 0U;
       offset += 1U + name.wire[offset])
    ++count;
  return count;
}

std::optional<Name> suffix_name(const Name &name,
                                std::size_t labels_to_keep) noexcept {
  const auto total = labels(name);
  if (!total || labels_to_keep > *total)
    return std::nullopt;
  std::size_t offset{};
  for (std::size_t skipped = *total; skipped > labels_to_keep; --skipped)
    offset += 1U + name.wire[offset];
  Name suffix;
  suffix.octets = static_cast<std::uint16_t>(name.octets - offset);
  std::copy_n(name.wire.begin() + static_cast<std::ptrdiff_t>(offset),
              suffix.octets, suffix.wire.begin());
  return suffix;
}

std::optional<Name> next_closer(const Name &qname,
                                const Name &closest) noexcept {
  const auto closest_labels = labels(closest);
  const auto qname_labels = labels(qname);
  if (!closest_labels || !qname_labels || *closest_labels >= *qname_labels)
    return std::nullopt;
  return suffix_name(qname, *closest_labels + 1U);
}

std::optional<Name> closest_nsec3_encloser(
    const dns::Zone &zone, const Name &name, const Nsec3param &parameter,
    const DigestCalculator &digests) noexcept {
  const auto count = labels(name);
  if (!count)
    return std::nullopt;
  for (std::size_t keep = *count;; --keep) {
    const auto candidate = suffix_name(name, keep);
    const auto hash = candidate ? hash_name(*candidate, parameter, digests)
                                : std::nullopt;
    if (candidate && hash && exact_nsec3(zone, *hash))
      return candidate;
    if (keep == 0U)
      break;
  }
  return std::nullopt;
}

std::optional<Name> wildcard_name(const Name &closest) noexcept {
  if (closest.octets + 2U > packet::dns::maximum_name_octets)
    return std::nullopt;
  Name wildcard;
  wildcard.wire[0] = 1U;
  wildcard.wire[1] = '*';
  std::copy_n(closest.wire.begin(), closest.octets, wildcard.wire.begin() + 2);
  wildcard.octets = static_cast<std::uint16_t>(closest.octets + 2U);
  return wildcard;
}

std::optional<Name> closest_encloser(const dns::Zone &zone,
                                     const Name &qname) noexcept {
  for (std::size_t offset{}; offset < qname.octets;) {
    Name suffix;
    suffix.octets = static_cast<std::uint16_t>(qname.octets - offset);
    std::copy_n(qname.wire.begin() + static_cast<std::ptrdiff_t>(offset),
                suffix.octets, suffix.wire.begin());
    const bool exists = std::ranges::any_of(zone.records(), [&](const auto &record) {
      return same_name(record.owner, suffix) ||
             dns::is_subdomain(record.owner, suffix);
    });
    if (exists)
      return suffix;
    if (qname.wire[offset] == 0U)
      break;
    offset += 1U + qname.wire[offset];
  }
  return std::nullopt;
}

const dns::ZoneRecord *wildcard_source(const dns::Zone &zone,
                                       const RecordData &answer) noexcept {
  for (const auto &record : zone.records()) {
    if (record.type != answer.type || record.record_class != answer.record_class ||
        !std::ranges::equal(record.rdata, answer.rdata) ||
        record.owner.octets < 3U || record.owner.wire[0] != 1U ||
        record.owner.wire[1] != static_cast<std::uint8_t>('*'))
      continue;
    Name suffix;
    suffix.octets = static_cast<std::uint16_t>(record.owner.octets - 2U);
    std::copy_n(record.owner.wire.begin() + 2, suffix.octets,
                suffix.wire.begin());
    if (dns::is_subdomain(answer.owner, suffix) &&
        !same_name(answer.owner, suffix))
      return &record;
  }
  return nullptr;
}

} // namespace

bool augment_authoritative_answer(const dns::Zone &zone,
                                  const packet::dns::Question &question,
                                  dns::AuthoritativeAnswer &answer,
                                  const DigestCalculator *digests) noexcept {
  try {
    // DO requests available DNSSEC data; it does not require an unsigned zone
    // to synthesize signatures or fail. Apex DNSKEY is the signed-zone signal
    // because ordinary data may legally contain opaque DNSSEC-like types only
    // within a delegated child namespace.
    const bool signed_zone = std::ranges::any_of(
        zone.records(), [&](const auto &record) {
          return record.type == packet::dns::type_dnskey &&
                 same_name(record.owner, zone.origin());
        });
    if (!signed_zone)
      return true;
    const auto nsec3 = nsec3_parameter(zone);
    if (nsec3 && !digests)
      return false;
    if (answer.referral) {
      if (answer.authorities.empty())
        return false;
      const auto cut = answer.authorities.front().owner;
      const auto original_count = answer.authorities.size();
      for (std::size_t index{}; index < original_count; ++index)
        if (!append_signatures(zone, answer.authorities[index].owner,
                               answer.authorities[index].owner,
                               answer.authorities[index].type,
                               answer.authorities))
          return false;
      bool has_ds{};
      for (const auto &record : zone.records())
        if (record.type == packet::dns::type_ds && same_name(record.owner, cut)) {
          has_ds = true;
          append_unique(answer.authorities, view(record, record.owner));
        }
      if (has_ds) {
        if (!append_signatures(zone, cut, cut, packet::dns::type_ds,
                               answer.authorities))
          return false;
      } else {
        if (nsec3) {
          const auto cut_hash = hash_name(cut, *nsec3, *digests);
          const auto closest =
              closest_nsec3_encloser(zone, cut, *nsec3, *digests);
          const auto next = closest ? next_closer(cut, *closest) : std::nullopt;
          const auto closest_hash =
              closest ? hash_name(*closest, *nsec3, *digests) : std::nullopt;
          const auto next_hash =
              next ? hash_name(*next, *nsec3, *digests) : std::nullopt;
          const auto *exact = cut_hash ? exact_nsec3(zone, *cut_hash) : nullptr;
          if (exact) {
            if (!append_nsec3(zone, *exact, answer.authorities))
              return false;
          } else {
            const auto *closest_record =
                closest_hash ? exact_nsec3(zone, *closest_hash) : nullptr;
            const auto *cover =
                next_hash ? covering_nsec3(zone, *next_hash) : nullptr;
            const auto cover_value = cover ? decode_nsec3(cover->rdata)
                                           : std::nullopt;
            if (!closest_record || !cover || !cover_value ||
                (cover_value->flags & 1U) == 0U ||
                !append_nsec3(zone, *closest_record, answer.authorities) ||
                !append_nsec3(zone, *cover, answer.authorities))
              return false;
          }
        } else {
          const auto *denial = exact_nsec(zone, cut);
          if (!denial || !append_nsec(zone, *denial, answer.authorities))
            return false;
        }
      }
      return true;
    }

    const auto original_answer_count = answer.answers.size();
    bool wildcard_expansion{};
    std::optional<Name> wildcard_closest;
    for (std::size_t index{}; index < original_answer_count; ++index) {
      const auto record = answer.answers[index];
      if (record.type == packet::dns::type_rrsig)
        continue;
      const auto *wildcard = wildcard_source(zone, record);
      wildcard_expansion = wildcard_expansion || wildcard != nullptr;
      if (wildcard) {
        Name closest;
        closest.octets = static_cast<std::uint16_t>(wildcard->owner.octets - 2U);
        std::copy_n(wildcard->owner.wire.begin() + 2, closest.octets,
                    closest.wire.begin());
        wildcard_closest = closest;
      }
      const auto &source_owner = wildcard ? wildcard->owner : record.owner;
      if (!append_signatures(zone, source_owner, record.owner, record.type,
                             answer.answers))
        return false;
    }

    const auto original_authority_count = answer.authorities.size();
    for (std::size_t index{}; index < original_authority_count; ++index) {
      const auto record = answer.authorities[index];
      if (record.type != packet::dns::type_rrsig &&
          !append_signatures(zone, record.owner, record.owner, record.type,
                             answer.authorities))
        return false;
    }

    if (wildcard_expansion) {
      const auto next = wildcard_closest
                            ? next_closer(question.name, *wildcard_closest)
                            : std::nullopt;
      if (!next)
        return false;
      if (nsec3) {
        const auto hash = hash_name(*next, *nsec3, *digests);
        const auto *denial = hash ? covering_nsec3(zone, *hash) : nullptr;
        if (!denial || !append_nsec3(zone, *denial, answer.authorities))
          return false;
      } else {
        const auto *denial = covering_nsec(zone, *next);
        if (!denial || !append_nsec(zone, *denial, answer.authorities))
          return false;
      }
      return true;
    }
    if (!answer.answers.empty())
      return true;

    if (answer.rcode == packet::dns::Rcode::name_error) {
      const auto closest = closest_encloser(zone, question.name);
      const auto next = closest ? next_closer(question.name, *closest)
                                : std::nullopt;
      const auto wildcard = closest ? wildcard_name(*closest) : std::nullopt;
      if (nsec3) {
        const auto closest_hash =
            closest ? hash_name(*closest, *nsec3, *digests) : std::nullopt;
        const auto next_hash =
            next ? hash_name(*next, *nsec3, *digests) : std::nullopt;
        const auto wildcard_hash =
            wildcard ? hash_name(*wildcard, *nsec3, *digests) : std::nullopt;
        const auto *closest_record =
            closest_hash ? exact_nsec3(zone, *closest_hash) : nullptr;
        const auto *name_denial =
            next_hash ? covering_nsec3(zone, *next_hash) : nullptr;
        const auto *wildcard_denial =
            wildcard_hash ? covering_nsec3(zone, *wildcard_hash) : nullptr;
        if (!closest_record || !name_denial || !wildcard_denial ||
            !append_nsec3(zone, *closest_record, answer.authorities) ||
            !append_nsec3(zone, *name_denial, answer.authorities) ||
            !append_nsec3(zone, *wildcard_denial, answer.authorities))
          return false;
      } else {
        const auto *name_denial = next ? covering_nsec(zone, *next) : nullptr;
        const auto *wildcard_denial =
            wildcard ? covering_nsec(zone, *wildcard) : nullptr;
        if (!name_denial || !wildcard_denial ||
            !append_nsec(zone, *name_denial, answer.authorities) ||
            !append_nsec(zone, *wildcard_denial, answer.authorities))
          return false;
      }
      return true;
    }

    // NOERROR with no answer is NODATA. An exact NSEC is sufficient for an
    // existing owner. Empty non-terminals are proven by the surrounding NSEC
    // interval together with ordinary name existence semantics.
    if (answer.rcode == packet::dns::Rcode::no_error) {
      if (nsec3) {
        const auto qhash = hash_name(question.name, *nsec3, *digests);
        const auto *denial = qhash ? exact_nsec3(zone, *qhash) : nullptr;
        if (denial)
          return append_nsec3(zone, *denial, answer.authorities);

        // A wildcard NODATA response has no answer record from which to retain
        // the wildcard source. Recompute the closest encloser and require the
        // RFC 5155 closest proof plus the exact wildcard hash.
        const auto closest = closest_encloser(zone, question.name);
        const auto next = closest ? next_closer(question.name, *closest)
                                  : std::nullopt;
        const auto wildcard = closest ? wildcard_name(*closest) : std::nullopt;
        const auto closest_hash =
            closest ? hash_name(*closest, *nsec3, *digests) : std::nullopt;
        const auto next_hash =
            next ? hash_name(*next, *nsec3, *digests) : std::nullopt;
        const auto wildcard_hash =
            wildcard ? hash_name(*wildcard, *nsec3, *digests) : std::nullopt;
        const auto *closest_record =
            closest_hash ? exact_nsec3(zone, *closest_hash) : nullptr;
        const auto *next_record =
            next_hash ? covering_nsec3(zone, *next_hash) : nullptr;
        const auto *wildcard_record =
            wildcard_hash ? exact_nsec3(zone, *wildcard_hash) : nullptr;
        return closest_record && next_record && wildcard_record &&
               append_nsec3(zone, *closest_record, answer.authorities) &&
               append_nsec3(zone, *next_record, answer.authorities) &&
               append_nsec3(zone, *wildcard_record, answer.authorities);
      }
      const auto *denial = exact_nsec(zone, question.name);
      if (!denial)
        denial = covering_nsec(zone, question.name);
      return denial && append_nsec(zone, *denial, answer.authorities);
    }
    return true;
  } catch (...) {
    return false;
  }
}

} // namespace router::dnssec
