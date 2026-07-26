// RFC 4034 canonical RR ordering and RFC 4035 signature checks. Names are
// lowercased only where DNSSEC canonical form requires it. Opaque RDATA is
// preserved exactly, preventing unknown record types from being rewritten.
// Source: ietf.dnssec.records.rfc4034
// Source: ietf.dnssec.validation.rfc4035

#include "router/dnssec_validation.hpp"

#include "router/generated_dnssec_policy.hpp"

#include <algorithm>
#include <limits>
#include <optional>

namespace router::dnssec {
namespace {

using packet::dns::Name;

void append_u16(std::vector<std::uint8_t> &output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t> &output, std::uint32_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 24U));
  output.push_back(static_cast<std::uint8_t>(value >> 16U));
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

std::optional<Name> canonical_name(Name name) noexcept {
  Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  if (!consumed || *consumed != name.octets)
    return std::nullopt;
  std::size_t offset{};
  while (offset < name.octets && name.wire[offset] != 0U) {
    const auto length = name.wire[offset++];
    for (std::size_t index{}; index < length; ++index) {
      auto &octet = name.wire[offset + index];
      if (octet >= 'A' && octet <= 'Z')
        octet = static_cast<std::uint8_t>(octet + ('a' - 'A'));
    }
    offset += length;
  }
  return name;
}

std::size_t label_count(const Name &name) noexcept {
  std::size_t count{};
  for (std::size_t offset{}; offset < name.octets && name.wire[offset] != 0U;
       offset += 1U + name.wire[offset])
    ++count;
  return count;
}

std::optional<Name> signed_owner(const Name &owner, std::uint8_t labels) noexcept {
  const auto canonical = canonical_name(owner);
  if (!canonical)
    return std::nullopt;
  const auto count = label_count(*canonical);
  if (labels > count)
    return std::nullopt;
  if (labels == count)
    return canonical;

  // A smaller Labels field means the signer expanded a wildcard. The signed
  // owner is one '*' label followed by exactly the rightmost Labels labels.
  std::size_t suffix{};
  for (std::size_t skip = count; skip > labels; --skip)
    suffix += 1U + canonical->wire[suffix];
  Name wildcard;
  wildcard.wire[0] = 1U;
  wildcard.wire[1] = '*';
  const auto suffix_octets = canonical->octets - suffix;
  if (2U + suffix_octets > wildcard.wire.size())
    return std::nullopt;
  std::copy_n(canonical->wire.begin() + static_cast<std::ptrdiff_t>(suffix),
              suffix_octets, wildcard.wire.begin() + 2);
  wildcard.octets = static_cast<std::uint16_t>(2U + suffix_octets);
  return wildcard;
}

bool append_canonical_name(std::span<const std::uint8_t> rdata,
                           std::size_t &offset,
                           std::vector<std::uint8_t> &output) {
  Name decoded;
  const auto consumed = packet::dns::parse_name(rdata, offset, decoded);
  if (!consumed)
    return false;
  const auto canonical = canonical_name(decoded);
  if (!canonical)
    return false;
  output.insert(output.end(), canonical->wire.begin(),
                canonical->wire.begin() + canonical->octets);
  offset += *consumed;
  return true;
}

bool canonical_rdata(const dns::ZoneRecord &record,
                     std::vector<std::uint8_t> &output) {
  const auto input = std::span<const std::uint8_t>{record.rdata};
  std::size_t offset{};
  using namespace packet::dns;
  switch (record.type) {
  case type_ns:
  case type_cname:
  case type_ptr:
  case type_dname:
    if (!append_canonical_name(input, offset, output))
      return false;
    break;
  case type_soa:
    if (!append_canonical_name(input, offset, output) ||
        !append_canonical_name(input, offset, output))
      return false;
    output.insert(output.end(), input.begin() + static_cast<std::ptrdiff_t>(offset),
                  input.end());
    offset = input.size();
    break;
  case type_mx:
    if (input.size() < 3U)
      return false;
    output.insert(output.end(), input.begin(), input.begin() + 2);
    offset = 2U;
    if (!append_canonical_name(input, offset, output))
      return false;
    break;
  case type_srv:
    if (input.size() < 7U)
      return false;
    output.insert(output.end(), input.begin(), input.begin() + 6);
    offset = 6U;
    if (!append_canonical_name(input, offset, output))
      return false;
    break;
  case type_svcb:
  case type_https:
    if (input.size() < 3U)
      return false;
    output.insert(output.end(), input.begin(), input.begin() + 2);
    offset = 2U;
    if (!append_canonical_name(input, offset, output))
      return false;
    // SvcParams are an ordered sequence of numeric keys and opaque values.
    // Their value syntax is key-specific but does not apply DNS name folding.
    output.insert(output.end(),
                  input.begin() + static_cast<std::ptrdiff_t>(offset),
                  input.end());
    offset = input.size();
    break;
  case type_rrsig: {
    const auto decoded = decode_rrsig(input);
    std::vector<std::uint8_t> canonical;
    if (!decoded || !encode_rrsig(*decoded, canonical))
      return false;
    output.insert(output.end(), canonical.begin(), canonical.end());
    offset = input.size();
    break;
  }
  case type_nsec: {
    const auto decoded = decode_nsec(input);
    std::vector<std::uint8_t> canonical;
    if (!decoded || !encode_nsec(*decoded, canonical))
      return false;
    output.insert(output.end(), canonical.begin(), canonical.end());
    offset = input.size();
    break;
  }
  default:
    output.insert(output.end(), input.begin(), input.end());
    offset = input.size();
    break;
  }
  return offset == input.size();
}

bool same_rrset(const dns::ZoneRecord &record, const dns::ZoneRecord &first,
                std::uint16_t covered_type) noexcept {
  return record.type == covered_type && record.type == first.type &&
         record.record_class == first.record_class &&
         packet::dns::equal_case_insensitive(record.owner, first.owner);
}

bool serial_before(std::uint32_t left, std::uint32_t right) noexcept {
  return left != right && static_cast<std::uint32_t>(right - left) < 0x80000000U;
}

int failure_priority(ValidationFailure failure) noexcept {
  // A stable priority makes the diagnostic independent of RRSIG wire order.
  // Unsupported algorithms are deliberately lowest: they can explain an
  // indeterminate result only when no locally supported signature was usable.
  switch (failure) {
  case ValidationFailure::resource_exhausted:
    return 7;
  case ValidationFailure::malformed_rrset:
    return 6;
  case ValidationFailure::invalid_signature:
    return 5;
  case ValidationFailure::signature_expired:
    return 4;
  case ValidationFailure::signature_not_yet_valid:
    return 3;
  case ValidationFailure::no_matching_key:
    return 2;
  case ValidationFailure::unsupported_algorithm:
    return 1;
  case ValidationFailure::none:
    return 0;
  }
  return 0;
}

void retain_stronger_failure(ValidationFailure candidate,
                             ValidationFailure &retained) noexcept {
  if (failure_priority(candidate) > failure_priority(retained))
    retained = candidate;
}

} // namespace

bool canonical_signed_data(const Rrsig &signature,
                           std::span<const dns::ZoneRecord> records,
                           std::vector<std::uint8_t> &output) noexcept {
  if (records.empty() || signature.type_covered != records.front().type)
    return false;
  const auto owner = signed_owner(records.front().owner, signature.labels);
  const auto signer = canonical_name(signature.signer_name);
  if (!owner || !signer)
    return false;
  try {
    std::vector<std::uint8_t> staged;
    append_u16(staged, signature.type_covered);
    staged.push_back(signature.algorithm);
    staged.push_back(signature.labels);
    append_u32(staged, signature.original_ttl);
    append_u32(staged, signature.signature_expiration);
    append_u32(staged, signature.signature_inception);
    append_u16(staged, signature.key_tag);
    staged.insert(staged.end(), signer->wire.begin(),
                  signer->wire.begin() + signer->octets);

    std::vector<std::vector<std::uint8_t>> canonical_records;
    canonical_records.reserve(records.size());
    for (const auto &record : records) {
      if (!same_rrset(record, records.front(), signature.type_covered))
        return false;
      std::vector<std::uint8_t> canonical;
      canonical.insert(canonical.end(), owner->wire.begin(),
                       owner->wire.begin() + owner->octets);
      append_u16(canonical, record.type);
      append_u16(canonical, record.record_class);
      append_u32(canonical, signature.original_ttl);
      const auto length_offset = canonical.size();
      canonical.resize(canonical.size() + 2U);
      const auto rdata_offset = canonical.size();
      if (!canonical_rdata(record, canonical) ||
          canonical.size() - rdata_offset >
              std::numeric_limits<std::uint16_t>::max())
        return false;
      const auto length = static_cast<std::uint16_t>(canonical.size() - rdata_offset);
      canonical[length_offset] = static_cast<std::uint8_t>(length >> 8U);
      canonical[length_offset + 1U] = static_cast<std::uint8_t>(length);
      canonical_records.push_back(std::move(canonical));
    }
    std::sort(canonical_records.begin(), canonical_records.end());
    for (const auto &record : canonical_records)
      staged.insert(staged.end(), record.begin(), record.end());
    output = std::move(staged);
    return true;
  } catch (...) {
    return false;
  }
}

ValidationResult validate_rrset(
    std::span<const dns::ZoneRecord> records,
    std::span<const dns::ZoneRecord> signatures,
    std::span<const dns::ZoneRecord> dnskeys, std::uint32_t now,
    const CryptoVerifier &crypto) noexcept {
  if (records.empty())
    return {.state = ValidationState::bogus,
            .failure = ValidationFailure::malformed_rrset};
  ValidationFailure strongest_failure = ValidationFailure::none;
  bool saw_supported_signature{};
  bool saw_unsupported_signature{};
  for (const auto &signature_record : signatures) {
    const auto signature = decode_rrsig(signature_record.rdata);
    if (!signature || signature->type_covered != records.front().type ||
        !packet::dns::equal_case_insensitive(signature_record.owner,
                                             records.front().owner)) {
      retain_stronger_failure(ValidationFailure::malformed_rrset,
                              strongest_failure);
      continue;
    }
    // Algorithm support is checked before the time window. An implementation
    // cannot make a security claim about the validity period of a signature
    // whose cryptographic algorithm it cannot process.
    if (!policy::algorithm(signature->algorithm) ||
        !crypto.supports(signature->algorithm)) {
      saw_unsupported_signature = true;
      retain_stronger_failure(ValidationFailure::unsupported_algorithm,
                              strongest_failure);
      continue;
    }
    saw_supported_signature = true;
    if (serial_before(now, signature->signature_inception)) {
      retain_stronger_failure(ValidationFailure::signature_not_yet_valid,
                              strongest_failure);
      continue;
    }
    if (serial_before(signature->signature_expiration, now)) {
      retain_stronger_failure(ValidationFailure::signature_expired,
                              strongest_failure);
      continue;
    }
    std::vector<std::uint8_t> signed_data;
    if (!canonical_signed_data(*signature, records, signed_data)) {
      retain_stronger_failure(ValidationFailure::malformed_rrset,
                              strongest_failure);
      continue;
    }
    bool matching_key{};
    for (const auto &key_record : dnskeys) {
      if (key_record.type != packet::dns::type_dnskey ||
          !packet::dns::equal_case_insensitive(key_record.owner,
                                               signature->signer_name))
        continue;
      const auto key = decode_dnskey(key_record.rdata);
      if (!key || key->algorithm != signature->algorithm ||
          key_tag(key_record.rdata) != signature->key_tag ||
          (key->flags & dnskey_zone_flag) == 0U)
        continue;
      matching_key = true;
      if (crypto.verify(key->algorithm, key->public_key, signed_data,
                        signature->signature))
        return {.state = ValidationState::secure,
                .failure = ValidationFailure::none,
                .key_tag = signature->key_tag,
                .algorithm = signature->algorithm,
                .labels = signature->labels,
                .original_ttl = signature->original_ttl,
                .valid_until = signature->signature_expiration};
      retain_stronger_failure(ValidationFailure::invalid_signature,
                              strongest_failure);
    }
    if (!matching_key)
      retain_stronger_failure(ValidationFailure::no_matching_key,
                              strongest_failure);
  }
  if (!saw_supported_signature && saw_unsupported_signature &&
      strongest_failure == ValidationFailure::unsupported_algorithm)
    return {.state = ValidationState::indeterminate,
            .failure = ValidationFailure::unsupported_algorithm};
  return {.state = ValidationState::bogus,
          .failure = strongest_failure == ValidationFailure::none
                         ? ValidationFailure::no_matching_key
                         : strongest_failure};
}

} // namespace router::dnssec
