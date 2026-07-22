// RFC 5155 section 7.1 NSEC3 generation with RFC 9276 publisher parameters.
// Source: ietf.dnssec.nsec3.rfc5155
// Source: ietf.dnssec.nsec3_parameters.rfc9276

#include "router/dnssec_nsec3_chain.hpp"

#include "router/dnssec_record.hpp"

#include <algorithm>
#include <string>

namespace router::dnssec {
namespace {

using Name = packet::dns::Name;
using Record = dns::ZoneRecord;

bool same_name(const Name &left, const Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

bool valid_name(const Name &name) noexcept {
  Name checked;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, checked);
  return consumed && *consumed == name.octets;
}

bool below_cut(const Name &owner, std::span<const Name> cuts) noexcept {
  return std::ranges::any_of(cuts, [&](const auto &cut) {
    return !same_name(owner, cut) && dns::is_subdomain(owner, cut);
  });
}

std::vector<Name> delegation_cuts(const Name &origin,
                                  std::span<const Record> records) {
  std::vector<Name> cuts;
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

bool has_ds(const Name &cut, std::span<const Record> records) noexcept {
  return std::ranges::any_of(records, [&](const auto &record) {
    return record.type == packet::dns::type_ds &&
           same_name(record.owner, cut);
  });
}

void append_unique(std::vector<Name> &names, const Name &candidate) {
  if (std::ranges::none_of(names, [&](const auto &existing) {
        return same_name(existing, candidate);
      }))
    names.push_back(candidate);
}

void append_empty_non_terminals(const Name &owner, const Name &origin,
                                std::vector<Name> &names) {
  if (same_name(owner, origin))
    return;
  // Remove one leftmost label at a time. Stop before origin because the apex
  // already exists. Every intermediate suffix is an empty non-terminal unless
  // an explicit owner later merges with it.
  std::size_t offset{};
  while (offset < owner.octets && owner.wire[offset] != 0U) {
    offset += 1U + owner.wire[offset];
    Name suffix;
    suffix.octets = static_cast<std::uint16_t>(owner.octets - offset);
    std::copy_n(owner.wire.begin() + static_cast<std::ptrdiff_t>(offset),
                suffix.octets, suffix.wire.begin());
    if (same_name(suffix, origin))
      break;
    append_unique(names, suffix);
  }
}

std::string base32hex(std::span<const std::uint8_t> input) {
  static constexpr char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  std::string output;
  output.reserve((input.size() * 8U + 4U) / 5U);
  std::uint32_t bits{};
  unsigned count{};
  for (const auto byte : input) {
    bits = (bits << 8U) | byte;
    count += 8U;
    while (count >= 5U) {
      count -= 5U;
      output.push_back(alphabet[(bits >> count) & 0x1fU]);
      bits &= count == 0U ? 0U : (1U << count) - 1U;
    }
  }
  if (count != 0U)
    output.push_back(alphabet[(bits << (5U - count)) & 0x1fU]);
  return output;
}

std::optional<Name> hashed_owner(std::span<const std::uint8_t> hash,
                                 const Name &origin) noexcept {
  try {
    const auto label = base32hex(hash);
    if (label.empty() || label.size() > packet::dns::maximum_label_octets ||
        1U + label.size() + origin.octets > packet::dns::maximum_name_octets)
      return std::nullopt;
    Name owner;
    owner.wire[0] = static_cast<std::uint8_t>(label.size());
    std::copy(label.begin(), label.end(), owner.wire.begin() + 1);
    std::copy_n(origin.wire.begin(), origin.octets,
                owner.wire.begin() + 1 +
                    static_cast<std::ptrdiff_t>(label.size()));
    owner.octets = static_cast<std::uint16_t>(
        1U + label.size() + origin.octets);
    return owner;
  } catch (...) {
    return std::nullopt;
  }
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

struct HashedName {
  Name original;
  std::vector<std::uint8_t> hash;
  std::vector<std::uint16_t> types;
};

} // namespace

std::optional<Nsec3Chain> build_nsec3_chain(
    const Name &origin, std::span<const Record> records,
    std::uint32_t denial_ttl, Nsec3PublisherPolicy policy,
    const DigestCalculator &digests) noexcept {
  if (!valid_name(origin) || records.empty() || !digests.supports_digest(1U))
    return std::nullopt;
  try {
    const auto cuts = delegation_cuts(origin, records);
    std::vector<Name> owners;
    std::vector<Name> omitted_unsigned_cuts;
    for (const auto &record : records) {
      if (!valid_name(record.owner) ||
          !dns::is_subdomain(record.owner, origin) ||
          below_cut(record.owner, cuts) ||
          record.type == packet::dns::type_rrsig ||
          record.type == packet::dns::type_nsec ||
          record.type == packet::dns::type_nsec3 ||
          record.type == packet::dns::type_nsec3param)
        continue;
      const bool cut = std::ranges::any_of(cuts, [&](const auto &candidate) {
        return same_name(candidate, record.owner);
      });
      if (policy.opt_out && cut && !has_ds(record.owner, records)) {
        append_unique(omitted_unsigned_cuts, record.owner);
        continue;
      }
      append_unique(owners, record.owner);
    }
    if (std::ranges::none_of(owners, [&](const auto &owner) {
          return same_name(owner, origin);
        }))
      return std::nullopt;
    const auto explicit_owners = owners;
    for (const auto &owner : explicit_owners)
      append_empty_non_terminals(owner, origin, owners);

    const Nsec3 parameters{.hash_algorithm = 1U,
                           .flags = 0U,
                           .iterations = 0U,
                           .salt = {},
                           .next_hashed_owner = std::vector<std::uint8_t>(20U),
                           .types = {}};
    std::vector<HashedName> hashed;
    hashed.reserve(owners.size());
    for (const auto &owner : owners) {
      std::vector<std::uint8_t> hash;
      if (nsec3_hash(owner, parameters, {}, digests, hash) !=
              Nsec3ProofState::proved ||
          hash.size() != 20U)
        return std::nullopt;
      std::vector<std::uint16_t> types;
      const bool at_cut = std::ranges::any_of(cuts, [&](const auto &cut) {
        return same_name(cut, owner);
      });
      bool signed_original_rrset{};
      for (const auto &record : records) {
        if (!same_name(record.owner, owner) ||
            record.type == packet::dns::type_rrsig ||
            record.type == packet::dns::type_nsec ||
            record.type == packet::dns::type_nsec3 ||
            record.type == packet::dns::type_nsec3param)
          continue;
        if (at_cut && record.type != packet::dns::type_ns &&
            record.type != packet::dns::type_ds)
          continue;
        types.push_back(record.type);
        signed_original_rrset = signed_original_rrset ||
                                !at_cut || record.type == packet::dns::type_ds;
      }
      if (same_name(owner, origin)) {
        types.push_back(packet::dns::type_nsec3param);
        signed_original_rrset = true;
      }
      if (signed_original_rrset)
        types.push_back(packet::dns::type_rrsig);
      std::ranges::sort(types);
      types.erase(std::unique(types.begin(), types.end()), types.end());
      hashed.push_back(
          {.original = owner, .hash = std::move(hash), .types = std::move(types)});
    }
    std::ranges::sort(hashed, {}, &HashedName::hash);
    for (std::size_t index = 1U; index < hashed.size(); ++index)
      if (hashed[index - 1U].hash == hashed[index].hash &&
          !same_name(hashed[index - 1U].original, hashed[index].original))
        return std::nullopt;

    std::vector<std::vector<std::uint8_t>> omitted_hashes;
    omitted_hashes.reserve(omitted_unsigned_cuts.size());
    for (const auto &owner : omitted_unsigned_cuts) {
      std::vector<std::uint8_t> hash;
      if (nsec3_hash(owner, parameters, {}, digests, hash) !=
          Nsec3ProofState::proved)
        return std::nullopt;
      omitted_hashes.push_back(std::move(hash));
    }

    Nsec3Chain result;
    Nsec3param parameter{.hash_algorithm = 1U,
                         .flags = 0U,
                         .iterations = 0U,
                         .salt = {}};
    if (!encode_nsec3param(parameter, result.parameter.rdata))
      return std::nullopt;
    result.parameter.owner = origin;
    result.parameter.type = packet::dns::type_nsec3param;
    result.parameter.record_class = packet::dns::internet_class;
    result.parameter.ttl = denial_ttl;
    result.records.reserve(hashed.size());
    for (std::size_t index{}; index < hashed.size(); ++index) {
      const auto &entry = hashed[index];
      const auto &next = hashed[(index + 1U) % hashed.size()].hash;
      const bool covers_omitted = policy.opt_out &&
          std::ranges::any_of(omitted_hashes, [&](const auto &omitted) {
            return hash_covers(entry.hash, next, omitted);
          });
      Nsec3 value{.hash_algorithm = 1U,
                  .flags = static_cast<std::uint8_t>(covers_omitted ? 1U : 0U),
                  .iterations = 0U,
                  .salt = {},
                  .next_hashed_owner = next,
                  .types = entry.types};
      std::vector<std::uint8_t> rdata;
      const auto owner = hashed_owner(entry.hash, origin);
      if (!owner || !encode_nsec3(value, rdata))
        return std::nullopt;
      result.records.push_back({.owner = *owner,
                                .type = packet::dns::type_nsec3,
                                .record_class = packet::dns::internet_class,
                                .ttl = denial_ttl,
                                .rdata = std::move(rdata)});
    }
    return result;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace router::dnssec
