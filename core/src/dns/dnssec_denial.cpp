// RFC 4034 canonical name ordering and RFC 4035 authenticated denial using
// NSEC. This module deliberately does not treat arbitrary absence as proof.
// Source: ietf.dnssec.nsec_denial.rfc4035

#include "router/dnssec_denial.hpp"

#include <algorithm>
#include <array>

namespace router::dnssec {
namespace {

using Name = packet::dns::Name;

struct Labels {
  std::array<std::span<const std::uint8_t>, 127U> values{};
  std::size_t count{};
};

std::optional<Labels> labels(const Name &name) noexcept {
  Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  if (!consumed || *consumed != name.octets)
    return std::nullopt;
  Labels result;
  // parse_name above proves that input is one complete uncompressed Name.
  // Store views into the caller-owned input, not parsed, because parsed is a
  // local validation copy whose lifetime ends when this function returns.
  for (std::size_t offset{}; offset < name.octets;) {
    const auto length = name.wire[offset++];
    if (length == 0U)
      return result;
    if (result.count == result.values.size() || offset + length > name.octets)
      return std::nullopt;
    result.values[result.count++] =
        std::span<const std::uint8_t>{name.wire}.subspan(offset, length);
    offset += length;
  }
  return std::nullopt;
}

std::uint8_t folded(std::uint8_t value) noexcept {
  return value >= 'A' && value <= 'Z'
             ? static_cast<std::uint8_t>(value + ('a' - 'A'))
             : value;
}

int compare_label(std::span<const std::uint8_t> left,
                  std::span<const std::uint8_t> right) noexcept {
  const auto common = std::min(left.size(), right.size());
  for (std::size_t index{}; index < common; ++index) {
    const auto l = folded(left[index]);
    const auto r = folded(right[index]);
    if (l < r)
      return -1;
    if (l > r)
      return 1;
  }
  return left.size() < right.size() ? -1 : left.size() > right.size() ? 1 : 0;
}

bool same_name(const Name &left, const Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

bool covers(const AuthenticatedNsec &nsec, const Name &name) noexcept {
  const auto owner_order = canonical_name_compare(nsec.record().owner, name);
  const auto next_order = canonical_name_compare(name, nsec.value().next_domain);
  const auto interval_order =
      canonical_name_compare(nsec.record().owner, nsec.value().next_domain);
  if (!owner_order || !next_order || !interval_order || *owner_order == 0)
    return false;
  if (*interval_order < 0)
    return *owner_order < 0 && *next_order < 0;
  if (*interval_order > 0)
    return *owner_order < 0 || *next_order < 0;
  // An owner equal to next represents the wrap-around interval in a zone with
  // one NSEC owner, covering every other canonical name.
  return true;
}

bool contains_type(const Nsec &nsec, std::uint16_t type) noexcept {
  return std::ranges::binary_search(nsec.types, type);
}

bool contains_type(const Nsec3 &nsec, std::uint16_t type) noexcept {
  return std::ranges::binary_search(nsec.types, type);
}

bool valid_nsec3_closest_encloser(const Nsec3 &nsec) noexcept {
  // RFC 5155 section 8.3 prevents an attacker from presenting delegation or
  // DNAME data as proof that a name is an authoritative closest encloser.
  return !contains_type(nsec, packet::dns::type_dname) &&
         (!contains_type(nsec, packet::dns::type_ns) ||
          contains_type(nsec, packet::dns::type_soa));
}

std::optional<Name> suffix_name(const Name &input,
                                std::size_t labels_to_keep) noexcept {
  const auto decoded = labels(input);
  if (!decoded || labels_to_keep > decoded->count)
    return std::nullopt;
  Name output;
  std::size_t offset{};
  const auto first = decoded->count - labels_to_keep;
  for (std::size_t index = first; index < decoded->count; ++index) {
    const auto label = decoded->values[index];
    if (offset + 1U + label.size() >= output.wire.size())
      return std::nullopt;
    output.wire[offset++] = static_cast<std::uint8_t>(label.size());
    std::copy(label.begin(), label.end(), output.wire.begin() +
                                               static_cast<std::ptrdiff_t>(offset));
    offset += label.size();
  }
  output.wire[offset++] = 0U;
  output.octets = static_cast<std::uint16_t>(offset);
  return output;
}

std::optional<Name> wildcard_name(const Name &encloser) noexcept {
  Name wildcard;
  if (encloser.octets + 2U > wildcard.wire.size())
    return std::nullopt;
  wildcard.wire[0] = 1U;
  wildcard.wire[1] = '*';
  std::copy_n(encloser.wire.begin(), encloser.octets,
              wildcard.wire.begin() + 2);
  wildcard.octets = static_cast<std::uint16_t>(encloser.octets + 2U);
  return wildcard;
}

} // namespace

std::optional<AuthenticatedNsec>
authenticate_nsec(const dns::ZoneRecord &record,
                  const ValidationResult &validation) noexcept {
  if (validation.state != ValidationState::secure ||
      record.type != packet::dns::type_nsec)
    return std::nullopt;
  auto decoded = decode_nsec(record.rdata);
  if (!decoded)
    return std::nullopt;
  try {
    return AuthenticatedNsec{record, std::move(*decoded)};
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<int> canonical_name_compare(const Name &left,
                                          const Name &right) noexcept {
  const auto left_labels = labels(left);
  const auto right_labels = labels(right);
  if (!left_labels || !right_labels)
    return std::nullopt;
  const auto common = std::min(left_labels->count, right_labels->count);
  for (std::size_t depth{}; depth < common; ++depth) {
    const auto left_index = left_labels->count - 1U - depth;
    const auto right_index = right_labels->count - 1U - depth;
    const auto order = compare_label(left_labels->values[left_index],
                                     right_labels->values[right_index]);
    if (order != 0)
      return order;
  }
  return left_labels->count < right_labels->count
             ? -1
             : left_labels->count > right_labels->count ? 1 : 0;
}

bool prove_nsec_nodata(const Name &name, std::uint16_t qtype,
                       std::span<const AuthenticatedNsec> nsecs) noexcept {
  for (const auto &nsec : nsecs)
    if (same_name(nsec.record().owner, name))
      return !contains_type(nsec.value(), qtype) &&
             !contains_type(nsec.value(), packet::dns::type_cname);
  return false;
}

bool prove_nsec_name_error(const Name &name,
                           std::span<const AuthenticatedNsec> nsecs) noexcept {
  const auto query_labels = labels(name);
  if (!query_labels || query_labels->count == 0U)
    return false;
  for (const auto &nsec : nsecs)
    if (same_name(nsec.record().owner, name))
      return false;

  std::optional<Name> closest;
  std::size_t closest_labels{};
  for (std::size_t count = query_labels->count; count > 0U; --count) {
    const auto candidate = suffix_name(name, count);
    if (!candidate)
      return false;
    if (std::ranges::any_of(nsecs, [&](const auto &nsec) {
          return same_name(nsec.record().owner, *candidate);
        })) {
      closest = candidate;
      closest_labels = count;
      break;
    }
  }
  if (!closest || closest_labels >= query_labels->count)
    return false;
  const auto next_closer = suffix_name(name, closest_labels + 1U);
  const auto wildcard = wildcard_name(*closest);
  if (!next_closer || !wildcard)
    return false;
  const auto covered = [&](const Name &candidate) {
    return std::ranges::any_of(nsecs,
                               [&](const auto &nsec) { return covers(nsec, candidate); });
  };
  return covered(*next_closer) && covered(*wildcard);
}

bool prove_nsec_wildcard_nodata(
    const Name &name, std::uint16_t qtype,
    std::span<const AuthenticatedNsec> nsecs) noexcept {
  const auto query_labels = labels(name);
  if (!query_labels || query_labels->count == 0U)
    return false;
  std::optional<Name> closest;
  std::size_t closest_labels{};
  for (std::size_t count = query_labels->count; count > 0U; --count) {
    const auto candidate = suffix_name(name, count);
    if (!candidate)
      return false;
    if (std::ranges::any_of(nsecs, [&](const auto &nsec) {
          return same_name(nsec.record().owner, *candidate);
        })) {
      closest = candidate;
      closest_labels = count;
      break;
    }
  }
  if (!closest || closest_labels >= query_labels->count)
    return false;
  const auto next_closer = suffix_name(name, closest_labels + 1U);
  const auto wildcard = wildcard_name(*closest);
  if (!next_closer || !wildcard ||
      !std::ranges::any_of(nsecs, [&](const auto &nsec) {
        return covers(nsec, *next_closer);
      }))
    return false;
  for (const auto &nsec : nsecs)
    if (same_name(nsec.record().owner, *wildcard))
      return !contains_type(nsec.value(), qtype) &&
             !contains_type(nsec.value(), packet::dns::type_cname);
  return false;
}

bool prove_nsec_wildcard_expansion(
    const Name &name, std::uint8_t wildcard_labels,
    std::span<const AuthenticatedNsec> nsecs) noexcept {
  const auto query_labels = labels(name);
  if (!query_labels || wildcard_labels >= query_labels->count)
    return false;

  // RRSIG Labels counts the labels below the wildcard. Keeping one additional
  // label constructs the next-closer name regardless of how many QNAME labels
  // the wildcard expansion replaced.
  const auto next_closer = suffix_name(name, wildcard_labels + 1U);
  return next_closer && std::ranges::any_of(nsecs, [&](const auto &nsec) {
           return covers(nsec, *next_closer);
         });
}

bool prove_nsec_no_ds(const Name &delegation,
                      std::span<const AuthenticatedNsec> nsecs) noexcept {
  for (const auto &nsec : nsecs)
    if (same_name(nsec.record().owner, delegation))
      return contains_type(nsec.value(), packet::dns::type_ns) &&
             !contains_type(nsec.value(), packet::dns::type_ds) &&
             !contains_type(nsec.value(), packet::dns::type_soa);
  return false;
}

std::optional<AuthenticatedNsec3>
authenticate_nsec3(const dns::ZoneRecord &record,
                   const ValidationResult &validation) noexcept {
  if (validation.state != ValidationState::secure ||
      record.type != packet::dns::type_nsec3)
    return std::nullopt;
  auto decoded = decode_nsec3(record.rdata);
  if (!decoded)
    return std::nullopt;
  try {
    return AuthenticatedNsec3{record, std::move(*decoded)};
  } catch (...) {
    return std::nullopt;
  }
}

Nsec3ProofState nsec3_hash(const Name &name, const Nsec3 &parameters,
                           Nsec3IterationPolicy policy,
                           const DigestCalculator &digests,
                           std::vector<std::uint8_t> &output) noexcept {
  if (parameters.hash_algorithm != 1U || !digests.supports_digest(1U))
    return Nsec3ProofState::malformed;
  if (parameters.iterations > policy.maximum)
    return Nsec3ProofState::unsupported_iterations;
  Name canonical;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, canonical);
  if (!consumed || *consumed != name.octets)
    return Nsec3ProofState::malformed;
  for (std::size_t offset{}; offset < canonical.octets &&
                              canonical.wire[offset] != 0U;) {
    const auto length = canonical.wire[offset++];
    for (std::size_t index{}; index < length; ++index)
      canonical.wire[offset + index] = folded(canonical.wire[offset + index]);
    offset += length;
  }
  try {
    std::vector<std::uint8_t> input(canonical.wire.begin(),
                                    canonical.wire.begin() + canonical.octets);
    input.insert(input.end(), parameters.salt.begin(), parameters.salt.end());
    std::vector<std::uint8_t> digest;
    if (!digests.calculate_digest(1U, input, digest) || digest.size() != 20U)
      return Nsec3ProofState::malformed;
    for (std::uint16_t iteration{}; iteration < parameters.iterations;
         ++iteration) {
      input.assign(digest.begin(), digest.end());
      input.insert(input.end(), parameters.salt.begin(), parameters.salt.end());
      if (!digests.calculate_digest(1U, input, digest) || digest.size() != 20U)
        return Nsec3ProofState::malformed;
    }
    output = std::move(digest);
    return Nsec3ProofState::proved;
  } catch (...) {
    return Nsec3ProofState::resource_exhausted;
  }
}

namespace {

std::optional<std::vector<std::uint8_t>> decode_base32hex(
    std::span<const std::uint8_t> text) noexcept {
  try {
    std::vector<std::uint8_t> output;
    output.reserve((text.size() * 5U) / 8U);
    std::uint32_t bits{};
    unsigned count{};
    for (const auto octet : text) {
      const auto value = [&]() -> std::optional<std::uint8_t> {
        if (octet >= '0' && octet <= '9')
          return static_cast<std::uint8_t>(octet - '0');
        const auto upper = octet >= 'a' && octet <= 'v'
                               ? static_cast<std::uint8_t>(octet - ('a' - 'A'))
                               : octet;
        if (upper >= 'A' && upper <= 'V')
          return static_cast<std::uint8_t>(10U + upper - 'A');
        return std::nullopt;
      }();
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

std::optional<std::vector<std::uint8_t>> owner_hash(
    const AuthenticatedNsec3 &record, const Name &zone) noexcept {
  const auto &owner = record.record().owner;
  if (owner.octets < 2U || owner.wire[0] == 0U ||
      1U + owner.wire[0] >= owner.octets)
    return std::nullopt;
  const auto suffix_offset = 1U + owner.wire[0];
  Name suffix;
  const auto suffix_octets = owner.octets - suffix_offset;
  std::copy_n(owner.wire.begin() + static_cast<std::ptrdiff_t>(suffix_offset),
              suffix_octets, suffix.wire.begin());
  suffix.octets = static_cast<std::uint16_t>(suffix_octets);
  if (!same_name(suffix, zone))
    return std::nullopt;
  return decode_base32hex(
      std::span<const std::uint8_t>{owner.wire}.subspan(1U, owner.wire[0]));
}

bool compatible_parameters(const Nsec3 &left, const Nsec3 &right) noexcept {
  return left.hash_algorithm == right.hash_algorithm &&
         left.iterations == right.iterations && left.salt == right.salt;
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

struct Nsec3SetView {
  const Nsec3 *parameters{};
  std::vector<std::vector<std::uint8_t>> owners;
};

Nsec3ProofState prepare_nsec3_set(
    std::span<const AuthenticatedNsec3> nsecs, const Name &zone,
    Nsec3IterationPolicy policy, Nsec3SetView &view) noexcept {
  if (nsecs.empty())
    return Nsec3ProofState::not_proved;
  if (nsecs.front().value().hash_algorithm != 1U ||
      nsecs.front().value().iterations > policy.maximum)
    return nsecs.front().value().iterations > policy.maximum
               ? Nsec3ProofState::unsupported_iterations
               : Nsec3ProofState::malformed;
  try {
    view.parameters = &nsecs.front().value();
    view.owners.reserve(nsecs.size());
    for (const auto &record : nsecs) {
      if (!compatible_parameters(*view.parameters, record.value()) ||
          (record.value().flags & ~1U) != 0U ||
          record.value().next_hashed_owner.size() != 20U)
        return Nsec3ProofState::malformed;
      auto decoded_owner = owner_hash(record, zone);
      if (!decoded_owner || decoded_owner->size() != 20U)
        return Nsec3ProofState::malformed;
      view.owners.push_back(std::move(*decoded_owner));
    }
    return Nsec3ProofState::proved;
  } catch (...) {
    return Nsec3ProofState::resource_exhausted;
  }
}

std::optional<std::size_t> exact_hash(
    std::span<const std::uint8_t> hash,
    const Nsec3SetView &view) noexcept {
  for (std::size_t index{}; index < view.owners.size(); ++index)
    if (std::ranges::equal(hash, view.owners[index]))
      return index;
  return std::nullopt;
}

std::optional<std::size_t> covering_hash(
    std::span<const std::uint8_t> hash,
    const Nsec3SetView &view,
    std::span<const AuthenticatedNsec3> nsecs) noexcept {
  for (std::size_t index{}; index < view.owners.size(); ++index)
    if (hash_covers(view.owners[index],
                    nsecs[index].value().next_hashed_owner, hash))
      return index;
  return std::nullopt;
}

} // namespace

Nsec3ProofState prove_nsec3_nodata(
    const Name &name, std::uint16_t qtype, const Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept {
  Nsec3SetView view;
  const auto prepared = prepare_nsec3_set(nsecs, zone, policy, view);
  if (prepared != Nsec3ProofState::proved)
    return prepared;
  std::vector<std::uint8_t> hash;
  const auto hashed = nsec3_hash(name, *view.parameters, policy, digests, hash);
  if (hashed != Nsec3ProofState::proved)
    return hashed;
  const auto match = exact_hash(hash, view);
  if (!match)
    return Nsec3ProofState::not_proved;
  const auto &nsec = nsecs[*match].value();
  return !contains_type(nsec, qtype) &&
                 !contains_type(nsec, packet::dns::type_cname)
             ? Nsec3ProofState::proved
             : Nsec3ProofState::not_proved;
}

Nsec3ProofState prove_nsec3_name_error(
    const Name &name, const Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept {
  Nsec3SetView view;
  const auto prepared = prepare_nsec3_set(nsecs, zone, policy, view);
  if (prepared != Nsec3ProofState::proved)
    return prepared;
  const auto query_labels = labels(name);
  const auto zone_labels = labels(zone);
  if (!query_labels || !zone_labels || query_labels->count <= zone_labels->count)
    return Nsec3ProofState::malformed;
  const auto query_zone = suffix_name(name, zone_labels->count);
  if (!query_zone || !same_name(*query_zone, zone))
    return Nsec3ProofState::malformed;

  std::optional<Name> closest;
  std::size_t closest_count{};
  std::optional<std::size_t> closest_record;
  for (std::size_t count = query_labels->count; count >= zone_labels->count;
       --count) {
    const auto candidate = suffix_name(name, count);
    std::vector<std::uint8_t> hash;
    if (!candidate || nsec3_hash(*candidate, *view.parameters, policy, digests,
                                 hash) != Nsec3ProofState::proved)
      return Nsec3ProofState::malformed;
    if (const auto exact = exact_hash(hash, view)) {
      closest = candidate;
      closest_count = count;
      closest_record = exact;
      break;
    }
    if (count == zone_labels->count)
      break;
  }
  if (!closest || !closest_record ||
      !valid_nsec3_closest_encloser(nsecs[*closest_record].value()) ||
      closest_count >= query_labels->count)
    return Nsec3ProofState::not_proved;
  const auto next_closer = suffix_name(name, closest_count + 1U);
  const auto wildcard = wildcard_name(*closest);
  if (!next_closer || !wildcard)
    return Nsec3ProofState::malformed;
  std::vector<std::uint8_t> next_hash;
  std::vector<std::uint8_t> wildcard_hash;
  if (nsec3_hash(*next_closer, *view.parameters, policy, digests, next_hash) !=
          Nsec3ProofState::proved ||
      nsec3_hash(*wildcard, *view.parameters, policy, digests,
                 wildcard_hash) != Nsec3ProofState::proved)
    return Nsec3ProofState::malformed;
  return covering_hash(next_hash, view, nsecs) &&
                 covering_hash(wildcard_hash, view, nsecs)
             ? Nsec3ProofState::proved
             : Nsec3ProofState::not_proved;
}

Nsec3ProofState prove_nsec3_wildcard_nodata(
    const Name &name, std::uint16_t qtype, const Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept {
  Nsec3SetView view;
  const auto prepared = prepare_nsec3_set(nsecs, zone, policy, view);
  if (prepared != Nsec3ProofState::proved)
    return prepared;
  const auto query_labels = labels(name);
  const auto zone_labels = labels(zone);
  if (!query_labels || !zone_labels || query_labels->count <= zone_labels->count)
    return Nsec3ProofState::malformed;
  const auto query_zone = suffix_name(name, zone_labels->count);
  if (!query_zone || !same_name(*query_zone, zone))
    return Nsec3ProofState::malformed;

  std::optional<Name> closest;
  std::size_t closest_count{};
  std::optional<std::size_t> closest_record;
  for (std::size_t count = query_labels->count; count >= zone_labels->count;
       --count) {
    const auto candidate = suffix_name(name, count);
    std::vector<std::uint8_t> hash;
    if (!candidate || nsec3_hash(*candidate, *view.parameters, policy, digests,
                                 hash) != Nsec3ProofState::proved)
      return Nsec3ProofState::malformed;
    if (const auto exact = exact_hash(hash, view)) {
      closest = candidate;
      closest_count = count;
      closest_record = exact;
      break;
    }
    if (count == zone_labels->count)
      break;
  }
  if (!closest || !closest_record ||
      !valid_nsec3_closest_encloser(nsecs[*closest_record].value()) ||
      closest_count >= query_labels->count)
    return Nsec3ProofState::not_proved;
  const auto next_closer = suffix_name(name, closest_count + 1U);
  const auto wildcard = wildcard_name(*closest);
  if (!next_closer || !wildcard)
    return Nsec3ProofState::malformed;
  std::vector<std::uint8_t> next_hash;
  std::vector<std::uint8_t> wildcard_hash;
  if (nsec3_hash(*next_closer, *view.parameters, policy, digests, next_hash) !=
          Nsec3ProofState::proved ||
      nsec3_hash(*wildcard, *view.parameters, policy, digests,
                 wildcard_hash) != Nsec3ProofState::proved)
    return Nsec3ProofState::malformed;
  if (!covering_hash(next_hash, view, nsecs))
    return Nsec3ProofState::not_proved;
  const auto wildcard_record = exact_hash(wildcard_hash, view);
  if (!wildcard_record)
    return Nsec3ProofState::not_proved;
  const auto &nsec = nsecs[*wildcard_record].value();
  return !contains_type(nsec, qtype) &&
                 !contains_type(nsec, packet::dns::type_cname)
             ? Nsec3ProofState::proved
             : Nsec3ProofState::not_proved;
}

Nsec3ProofState prove_nsec3_wildcard_expansion(
    const Name &name, std::uint8_t wildcard_labels, const Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept {
  Nsec3SetView view;
  const auto prepared = prepare_nsec3_set(nsecs, zone, policy, view);
  if (prepared != Nsec3ProofState::proved)
    return prepared;
  const auto query_labels = labels(name);
  const auto zone_labels = labels(zone);
  if (!query_labels || !zone_labels ||
      wildcard_labels < zone_labels->count ||
      wildcard_labels >= query_labels->count)
    return Nsec3ProofState::malformed;
  const auto query_zone = suffix_name(name, zone_labels->count);
  const auto next_closer = suffix_name(name, wildcard_labels + 1U);
  if (!query_zone || !same_name(*query_zone, zone) || !next_closer)
    return Nsec3ProofState::malformed;

  // RFC 5155 section 7.2.6 needs only coverage of the next-closer hash. The
  // expanded wildcard RRSIG itself proves that its immediate ancestor exists,
  // so demanding a second exact closest-encloser NSEC3 would reject valid
  // minimal authoritative responses.
  std::vector<std::uint8_t> next_hash;
  const auto next_state =
      nsec3_hash(*next_closer, *view.parameters, policy, digests, next_hash);
  if (next_state != Nsec3ProofState::proved)
    return next_state;
  return covering_hash(next_hash, view, nsecs)
             ? Nsec3ProofState::proved
             : Nsec3ProofState::not_proved;
}

Nsec3ProofState prove_nsec3_no_ds(
    const Name &delegation, const Name &zone,
    std::span<const AuthenticatedNsec3> nsecs, Nsec3IterationPolicy policy,
    const DigestCalculator &digests) noexcept {
  Nsec3SetView view;
  const auto prepared = prepare_nsec3_set(nsecs, zone, policy, view);
  if (prepared != Nsec3ProofState::proved)
    return prepared;
  std::vector<std::uint8_t> delegation_hash;
  const auto hashed = nsec3_hash(delegation, *view.parameters, policy, digests,
                                 delegation_hash);
  if (hashed != Nsec3ProofState::proved)
    return hashed;
  if (const auto exact = exact_hash(delegation_hash, view)) {
    const auto &nsec = nsecs[*exact].value();
    return contains_type(nsec, packet::dns::type_ns) &&
                   !contains_type(nsec, packet::dns::type_ds) &&
                   !contains_type(nsec, packet::dns::type_soa)
               ? Nsec3ProofState::proved
               : Nsec3ProofState::not_proved;
  }
  const auto covering = covering_hash(delegation_hash, view, nsecs);
  if (!covering || (nsecs[*covering].value().flags & 1U) == 0U)
    return Nsec3ProofState::not_proved;

  // Opt-Out alone is insufficient. An exact closest-encloser hash must bind
  // the covered delegation to this authenticated NSEC3 chain.
  const auto delegation_labels = labels(delegation);
  const auto zone_labels = labels(zone);
  if (!delegation_labels || !zone_labels ||
      delegation_labels->count <= zone_labels->count)
    return Nsec3ProofState::malformed;
  const auto delegation_zone = suffix_name(delegation, zone_labels->count);
  if (!delegation_zone || !same_name(*delegation_zone, zone))
    return Nsec3ProofState::malformed;
  for (std::size_t count = delegation_labels->count - 1U;
       count >= zone_labels->count; --count) {
    const auto candidate = suffix_name(delegation, count);
    std::vector<std::uint8_t> candidate_hash;
    if (!candidate || nsec3_hash(*candidate, *view.parameters, policy, digests,
                                 candidate_hash) != Nsec3ProofState::proved)
      return Nsec3ProofState::malformed;
    if (const auto exact = exact_hash(candidate_hash, view))
      return valid_nsec3_closest_encloser(nsecs[*exact].value())
                 ? Nsec3ProofState::proved
                 : Nsec3ProofState::not_proved;
    if (count == zone_labels->count)
      break;
  }
  return Nsec3ProofState::not_proved;
}

} // namespace router::dnssec
