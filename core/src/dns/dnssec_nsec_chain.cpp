// RFC 4034 section 4 NSEC chain generation. The ordinary complete chain is
// used, not online epsilon records. Delegation cuts follow RFC 4035 section
// 2.3, so parent-side NS and DS remain authoritative while child glue does not.
// Source: ietf.dnssec.records.rfc4034
// Source: ietf.dnssec.validation.rfc4035

#include "router/dnssec_nsec_chain.hpp"

#include "router/dnssec_denial.hpp"
#include "router/dnssec_record.hpp"

#include <algorithm>

namespace router::dnssec {
namespace {

bool same_name(const packet::dns::Name &left,
               const packet::dns::Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

bool valid_name(const packet::dns::Name &name) noexcept {
  packet::dns::Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  return consumed && *consumed == name.octets;
}

bool below_cut(const packet::dns::Name &owner,
               std::span<const packet::dns::Name> cuts) noexcept {
  return std::ranges::any_of(cuts, [&](const auto &cut) {
    return !same_name(owner, cut) && dns::is_subdomain(owner, cut);
  });
}

} // namespace

std::optional<std::vector<dns::ZoneRecord>>
build_nsec_chain(const packet::dns::Name &origin,
                 std::span<const dns::ZoneRecord> records,
                 std::uint32_t denial_ttl) noexcept {
  if (!valid_name(origin) || records.empty())
    return std::nullopt;
  try {
    std::vector<packet::dns::Name> cuts;
    for (const auto &record : records)
      if (record.type == packet::dns::type_ns &&
          !same_name(record.owner, origin) &&
          dns::is_subdomain(record.owner, origin) &&
          std::ranges::none_of(cuts, [&](const auto &cut) {
            return same_name(cut, record.owner);
          }))
        cuts.push_back(record.owner);

    std::vector<packet::dns::Name> owners;
    for (const auto &record : records) {
      if (!valid_name(record.owner) ||
          !dns::is_subdomain(record.owner, origin) ||
          below_cut(record.owner, cuts))
        continue;
      // Existing generated denial and signature records cannot introduce a
      // new owner into the unsigned zone's authoritative name set.
      if (record.type == packet::dns::type_rrsig ||
          record.type == packet::dns::type_nsec ||
          record.type == packet::dns::type_nsec3)
        continue;
      if (std::ranges::none_of(owners, [&](const auto &owner) {
            return same_name(owner, record.owner);
          }))
        owners.push_back(record.owner);
    }
    if (std::ranges::none_of(owners,
                             [&](const auto &owner) {
                               return same_name(owner, origin);
                             }))
      return std::nullopt;
    std::ranges::sort(owners, [](const auto &left, const auto &right) {
      const auto order = canonical_name_compare(left, right);
      return order && *order < 0;
    });

    std::vector<dns::ZoneRecord> chain;
    chain.reserve(owners.size());
    for (std::size_t index{}; index < owners.size(); ++index) {
      const auto &owner = owners[index];
      const auto &next = owners[(index + 1U) % owners.size()];
      std::vector<std::uint16_t> types;
      for (const auto &record : records) {
        if (!same_name(record.owner, owner) ||
            record.type == packet::dns::type_rrsig ||
            record.type == packet::dns::type_nsec ||
            record.type == packet::dns::type_nsec3)
          continue;
        const bool at_cut = std::ranges::any_of(cuts, [&](const auto &cut) {
          return same_name(cut, owner);
        });
        if (at_cut && record.type != packet::dns::type_ns &&
            record.type != packet::dns::type_ds)
          continue;
        types.push_back(record.type);
      }
      types.push_back(packet::dns::type_nsec);
      types.push_back(packet::dns::type_rrsig);
      std::ranges::sort(types);
      types.erase(std::unique(types.begin(), types.end()), types.end());
      std::vector<std::uint8_t> rdata;
      if (!encode_nsec({.next_domain = next, .types = std::move(types)}, rdata))
        return std::nullopt;
      chain.push_back({.owner = owner,
                       .type = packet::dns::type_nsec,
                       .record_class = packet::dns::internet_class,
                       .ttl = denial_ttl,
                       .rdata = std::move(rdata)});
    }
    return chain;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace router::dnssec
