// RFC 1034, RFC 1035 and RFC 2308 authoritative answer selection. Delegation
// and glue are derived only from zone records. No global topology or peer DNS
// state is visible to this repository.

#include "router/dns_authoritative.hpp"

#include <algorithm>
#include <limits>
#include <new>

namespace router::dns {
namespace {

using packet::dns::Name;
using packet::dns::RecordData;

bool canonical_name_rdata(std::span<const std::uint8_t> rdata) noexcept {
  packet::dns::Name decoded;
  const auto consumed = packet::dns::parse_name(rdata, 0U, decoded);
  return consumed && *consumed == rdata.size();
}

bool valid_name(const Name &name) noexcept {
  Name decoded;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, decoded);
  return consumed && *consumed == name.octets;
}

bool canonical_soa_rdata(std::span<const std::uint8_t> rdata) noexcept {
  packet::dns::Name name;
  const auto first = packet::dns::parse_name(rdata, 0U, name);
  if (!first)
    return false;
  const auto second = packet::dns::parse_name(rdata, *first, name);
  return second && *first + *second + 20U == rdata.size();
}

bool canonical_two_names(std::span<const std::uint8_t> rdata) noexcept {
  packet::dns::Name name;
  const auto first = packet::dns::parse_name(rdata, 0U, name);
  if (!first)
    return false;
  const auto second = packet::dns::parse_name(rdata, *first, name);
  return second && *first + *second == rdata.size();
}

bool character_strings(std::span<const std::uint8_t> rdata,
                       std::size_t required_count = 0U) noexcept {
  std::size_t offset{};
  std::size_t count{};
  while (offset < rdata.size()) {
    const auto length = rdata[offset++];
    if (length > rdata.size() - offset)
      return false;
    offset += length;
    ++count;
  }
  return offset == rdata.size() &&
         (required_count == 0U ? count != 0U : count == required_count);
}

bool valid_rdata(const ZoneRecord &record) noexcept {
  using namespace packet::dns;
  switch (record.type) {
  case type_a:
    return record.rdata.size() == 4U;
  case type_aaaa:
    return record.rdata.size() == 16U;
  case type_ns:
  case type_md:
  case type_mf:
  case type_cname:
  case type_mb:
  case type_mg:
  case type_mr:
  case type_ptr:
  case type_dname:
    return canonical_name_rdata(record.rdata);
  case type_minfo:
    return canonical_two_names(record.rdata);
  case type_hinfo:
    return character_strings(record.rdata, 2U);
  case type_txt:
    return character_strings(record.rdata);
  case type_wks:
    // Four address octets and one protocol octet precede an optional bitmap.
    return record.rdata.size() >= 5U;
  case type_soa:
    return canonical_soa_rdata(record.rdata);
  case type_mx:
    return record.rdata.size() >= 3U &&
           canonical_name_rdata(
               std::span<const std::uint8_t>{record.rdata}.subspan(2U));
  case type_srv:
    return record.rdata.size() >= 7U &&
           canonical_name_rdata(
               std::span<const std::uint8_t>{record.rdata}.subspan(6U));
  default:
    // Unknown types are opaque by design. Their class, TTL and exact bytes are
    // still served and can later gain a typed editor without schema migration.
    return record.rdata.size() <= std::numeric_limits<std::uint16_t>::max();
  }
}

std::optional<Name> rdata_name(const ZoneRecord &record) noexcept {
  Name value;
  const auto parsed = packet::dns::parse_name(record.rdata, 0U, value);
  return parsed && *parsed == record.rdata.size() ? std::optional{Name{value}}
                                                  : std::nullopt;
}

std::uint32_t soa_minimum(const ZoneRecord &soa) noexcept {
  if (soa.rdata.size() < 4U)
    return 0U;
  const auto offset = soa.rdata.size() - 4U;
  return (static_cast<std::uint32_t>(soa.rdata[offset]) << 24U) |
         (static_cast<std::uint32_t>(soa.rdata[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(soa.rdata[offset + 2U]) << 8U) |
         soa.rdata[offset + 3U];
}

} // namespace

bool is_subdomain(const packet::dns::Name &name,
                  const packet::dns::Name &ancestor) noexcept {
  std::size_t offset{};
  while (offset < name.octets) {
    Name suffix;
    suffix.octets = static_cast<std::uint16_t>(name.octets - offset);
    std::copy_n(name.wire.begin() + static_cast<std::ptrdiff_t>(offset),
                suffix.octets, suffix.wire.begin());
    if (packet::dns::equal_case_insensitive(suffix, ancestor))
      return true;
    if (name.wire[offset] == 0U)
      break;
    offset += 1U + name.wire[offset];
  }
  return false;
}

Zone::Zone(packet::dns::Name origin) noexcept : origin_(origin) {}

bool Zone::replace(std::vector<ZoneRecord> records) noexcept {
  try {
    Name validated_origin;
    const auto origin_octets =
        packet::dns::parse_name(origin_.view(), 0U, validated_origin);
    if (!origin_octets || *origin_octets != origin_.octets)
      return false;
    std::size_t apex_soa{};
    std::size_t apex_ns{};
    for (std::size_t index = 0U; index < records.size(); ++index) {
      const auto &record = records[index];
      if (!valid_name(record.owner) || !is_subdomain(record.owner, origin_) ||
          record.record_class != packet::dns::internet_class ||
          !valid_rdata(record))
        return false;
      const bool apex =
          packet::dns::equal_case_insensitive(record.owner, origin_);
      apex_soa += apex && record.type == packet::dns::type_soa;
      apex_ns += apex && record.type == packet::dns::type_ns;

      // CNAME owns an alias node and cannot coexist with ordinary data. DNSSEC
      // denial and signature records are the standardized exceptions.
      for (std::size_t previous = 0U; previous < index; ++previous) {
        const auto &other = records[previous];
        if (!packet::dns::equal_case_insensitive(record.owner, other.owner))
          continue;
        const bool cname_conflict = (record.type == packet::dns::type_cname ||
                                     other.type == packet::dns::type_cname) &&
                                    record.type != other.type &&
                                    record.type != packet::dns::type_rrsig &&
                                    other.type != packet::dns::type_rrsig &&
                                    record.type != packet::dns::type_nsec &&
                                    other.type != packet::dns::type_nsec;
        if (cname_conflict ||
            (record.type == other.type && record.rdata == other.rdata))
          return false;
      }
    }
    if (apex_soa != 1U || apex_ns == 0U)
      return false;
    records_ = std::move(records);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

packet::dns::RecordData Zone::view(const ZoneRecord &record) const noexcept {
  return {.owner = record.owner,
          .type = record.type,
          .record_class = record.record_class,
          .ttl = record.ttl,
          .rdata = record.rdata};
}

void Zone::negative_soa(AuthoritativeAnswer &answer) const {
  const auto soa =
      std::find_if(records_.begin(), records_.end(), [&](const auto &record) {
        return record.type == packet::dns::type_soa &&
               packet::dns::equal_case_insensitive(record.owner, origin_);
      });
  if (soa == records_.end())
    return;
  auto negative = view(*soa);
  negative.ttl = std::min(soa->ttl, soa_minimum(*soa));
  answer.authorities.push_back(negative);
}

AuthoritativeAnswer Zone::answer(const packet::dns::Question &question) const {
  AuthoritativeAnswer result{.rcode = packet::dns::Rcode::no_error,
                             .answers = {},
                             .authorities = {},
                             .additionals = {},
                             .synthesized_rdata = {},
                             .authoritative = true,
                             .referral = false};
  if (question.record_class != packet::dns::internet_class ||
      !is_subdomain(question.name, origin_)) {
    result.rcode = packet::dns::Rcode::refused;
    result.authoritative = false;
    return result;
  }

  // The closest non-apex NS owner is a zone cut. Parent-side DS queries remain
  // authoritative at the cut; all other types receive a referral and only
  // in-bailiwick address records are added as glue.
  const ZoneRecord *cut{};
  for (const auto &record : records_) {
    if (record.type != packet::dns::type_ns ||
        packet::dns::equal_case_insensitive(record.owner, origin_) ||
        !is_subdomain(question.name, record.owner))
      continue;
    if (!cut || record.owner.octets > cut->owner.octets)
      cut = &record;
  }
  const bool parent_ds =
      cut && question.type == packet::dns::type_ds &&
      packet::dns::equal_case_insensitive(question.name, cut->owner);
  if (cut && !parent_ds) {
    result.authoritative = false;
    result.referral = true;
    for (const auto &record : records_) {
      if (record.type != packet::dns::type_ns ||
          !packet::dns::equal_case_insensitive(record.owner, cut->owner))
        continue;
      result.authorities.push_back(view(record));
      const auto target = rdata_name(record);
      if (!target || !is_subdomain(*target, cut->owner))
        continue;
      for (const auto &address : records_)
        if ((address.type == packet::dns::type_a ||
             address.type == packet::dns::type_aaaa) &&
            packet::dns::equal_case_insensitive(address.owner, *target))
          result.additionals.push_back(view(address));
    }
    return result;
  }

  bool owner_exists{};
  for (const auto &record : records_) {
    if (!packet::dns::equal_case_insensitive(record.owner, question.name))
      continue;
    owner_exists = true;
    if (question.type == 255U || record.type == question.type)
      result.answers.push_back(view(record));
  }
  if (result.answers.empty() && owner_exists &&
      question.type != packet::dns::type_cname) {
    for (const auto &record : records_)
      if (record.type == packet::dns::type_cname &&
          packet::dns::equal_case_insensitive(record.owner, question.name))
        result.answers.push_back(view(record));
  }
  if (!result.answers.empty())
    return result;

  // A name with descendants is an empty non-terminal and therefore exists
  // even though it owns no RRset. Returning NXDOMAIN here would incorrectly
  // deny the entire subtree and break RFC 8020-aware recursive caches.
  if (!owner_exists) {
    owner_exists =
        std::any_of(records_.begin(), records_.end(), [&](const auto &record) {
          return is_subdomain(record.owner, question.name) &&
                 !packet::dns::equal_case_insensitive(record.owner,
                                                      question.name);
        });
  }

  if (!owner_exists) {
    // Find the closest existing ancestor. Existence includes empty
    // non-terminals induced by deeper records, not only explicit owners.
    std::size_t suffix_offset{};
    Name closest = question.name;
    bool found_closest{};
    while (suffix_offset < question.name.octets) {
      closest = {};
      closest.octets =
          static_cast<std::uint16_t>(question.name.octets - suffix_offset);
      std::copy_n(question.name.wire.begin() +
                      static_cast<std::ptrdiff_t>(suffix_offset),
                  closest.octets, closest.wire.begin());
      const bool exists = std::any_of(
          records_.begin(), records_.end(), [&](const auto &record) {
            return packet::dns::equal_case_insensitive(record.owner, closest) ||
                   is_subdomain(record.owner, closest);
          });
      if (exists) {
        found_closest = true;
        break;
      }
      if (question.name.wire[suffix_offset] == 0U)
        break;
      suffix_offset += 1U + question.name.wire[suffix_offset];
    }

    if (found_closest) {
      // DNAME takes precedence when the matching walk falls below its owner.
      // The synthesized CNAME retains QNAME as owner and replaces only the
      // matched suffix. The target is never compressed in RDATA.
      const ZoneRecord *dname{};
      for (const auto &record : records_)
        if (record.type == packet::dns::type_dname &&
            packet::dns::equal_case_insensitive(record.owner, closest) &&
            !packet::dns::equal_case_insensitive(question.name, record.owner) &&
            !dname)
          dname = &record;
      if (dname) {
        result.answers.push_back(view(*dname));
        const auto prefix_octets = static_cast<std::size_t>(
            question.name.octets - dname->owner.octets);
        if (prefix_octets + dname->rdata.size() >
            packet::dns::maximum_name_octets) {
          result.rcode = packet::dns::Rcode::yx_domain;
          return result;
        }
        result.synthesized_rdata.emplace_back();
        auto &target = result.synthesized_rdata.back();
        target.reserve(prefix_octets + dname->rdata.size());
        target.insert(target.end(), question.name.wire.begin(),
                      question.name.wire.begin() +
                          static_cast<std::ptrdiff_t>(prefix_octets));
        target.insert(target.end(), dname->rdata.begin(), dname->rdata.end());
        result.answers.push_back({.owner = question.name,
                                  .type = packet::dns::type_cname,
                                  .record_class = dname->record_class,
                                  .ttl = dname->ttl,
                                  .rdata = target});
        return result;
      }

      // RFC 4592 permits exactly one synthesis source: an asterisk label
      // immediately below the closest encloser. If that node exists but lacks
      // QTYPE, the answer is NODATA and no less-specific wildcard is tried.
      if (closest.octets + 2U <= packet::dns::maximum_name_octets) {
        Name wildcard;
        wildcard.octets = static_cast<std::uint16_t>(closest.octets + 2U);
        wildcard.wire[0] = 1U;
        wildcard.wire[1] = static_cast<std::uint8_t>('*');
        std::copy_n(closest.wire.begin(), closest.octets,
                    wildcard.wire.begin() + 2U);
        bool wildcard_exists{};
        for (const auto &record : records_) {
          if (!packet::dns::equal_case_insensitive(record.owner, wildcard))
            continue;
          wildcard_exists = true;
          if (question.type == 255U || record.type == question.type ||
              (record.type == packet::dns::type_cname &&
               question.type != packet::dns::type_cname)) {
            auto synthesized = view(record);
            synthesized.owner = question.name;
            result.answers.push_back(synthesized);
          }
        }
        if (wildcard_exists) {
          if (result.answers.empty())
            negative_soa(result);
          return result;
        }
      }
    }
  }

  if (!owner_exists)
    result.rcode = packet::dns::Rcode::name_error;
  negative_soa(result);
  return result;
}

} // namespace router::dns
