// DNSKEY construction and RRSIG generation according to RFC 4034 and RFC
// 4035. No default lifetime is hidden here because operational timing belongs
// to the zone key policy described by RFC 6781 and RFC 7583.
// Source: ietf.dnssec.records.rfc4034
// Source: ietf.dnssec.validation.rfc4035

#include "router/dnssec_zone_signer.hpp"

#include "router/dnssec_record.hpp"
#include "router/dnssec_validation.hpp"

#include <algorithm>

namespace router::dnssec {
namespace {

bool valid_name(const packet::dns::Name &name) noexcept {
  packet::dns::Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  return consumed && *consumed == name.octets;
}

std::uint8_t labels_without_root(const packet::dns::Name &name) noexcept {
  std::uint8_t labels{};
  for (std::size_t offset{};
       offset < name.octets && name.wire[offset] != 0U;
       offset += 1U + name.wire[offset])
    ++labels;
  // RFC 4034 section 3.1.3 excludes the initial asterisk label from Labels.
  // Validators use the smaller value to reconstruct the wildcard owner from
  // the expanded response owner.
  const bool wildcard = name.octets >= 3U && name.wire[0] == 1U &&
                        name.wire[1] == static_cast<std::uint8_t>('*');
  return static_cast<std::uint8_t>(labels - (wildcard ? 1U : 0U));
}

} // namespace

std::optional<dns::ZoneRecord>
make_dnskey_record(const packet::dns::Name &zone, std::uint32_t ttl,
                   const SigningKey &key, KeyRole role) noexcept {
  if (!valid_name(zone) || key.public_key().empty())
    return std::nullopt;
  try {
    Dnskey value{.flags = static_cast<std::uint16_t>(
                     dnskey_zone_flag |
                     (role == KeyRole::key_signing
                          ? dnskey_secure_entry_point_flag
                          : 0U)),
                 .protocol = dnskey_protocol,
                 .algorithm = key.algorithm(),
                 .public_key = {key.public_key().begin(), key.public_key().end()}};
    std::vector<std::uint8_t> rdata;
    if (!encode_dnskey(value, rdata))
      return std::nullopt;
    return dns::ZoneRecord{.owner = zone,
                           .type = packet::dns::type_dnskey,
                           .record_class = packet::dns::internet_class,
                           .ttl = ttl,
                           .rdata = std::move(rdata)};
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<dns::ZoneRecord>
sign_rrset(std::span<const dns::ZoneRecord> records,
           const dns::ZoneRecord &key_record, const SigningKey &key,
           std::uint32_t inception, std::uint32_t expiration) noexcept {
  if (records.empty() || key_record.type != packet::dns::type_dnskey ||
      (records.front().type == packet::dns::type_dnskey &&
       !packet::dns::equal_case_insensitive(key_record.owner,
                                            records.front().owner)))
    return std::nullopt;
  const auto decoded_key = decode_dnskey(key_record.rdata);
  if (!decoded_key || decoded_key->algorithm != key.algorithm() ||
      !std::ranges::equal(decoded_key->public_key, key.public_key()) ||
      inception == expiration)
    return std::nullopt;

  try {
    Rrsig signature{.type_covered = records.front().type,
                    .algorithm = key.algorithm(),
                    .labels = labels_without_root(records.front().owner),
                    .original_ttl = records.front().ttl,
                    .signature_expiration = expiration,
                    .signature_inception = inception,
                    .key_tag = key_tag(key_record.rdata),
                    .signer_name = key_record.owner,
                    .signature = {}};
    std::vector<std::uint8_t> signed_data;
    if (!canonical_signed_data(signature, records, signed_data) ||
        !key.sign(signed_data, signature.signature))
      return std::nullopt;
    std::vector<std::uint8_t> rdata;
    if (!encode_rrsig(signature, rdata))
      return std::nullopt;
    return dns::ZoneRecord{.owner = records.front().owner,
                           .type = packet::dns::type_rrsig,
                           .record_class = records.front().record_class,
                           .ttl = records.front().ttl,
                           .rdata = std::move(rdata)};
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace router::dnssec
