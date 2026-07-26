// Signed snapshot tests ensure KSK/ZSK separation, multi-record RRset signing
// and omission of signatures for glue below a delegation cut.

#include "router/dnssec_signed_zone.hpp"

#include "router/dnssec_record.hpp"
#include "router/dnssec_openssl.hpp"
#include "router/dnssec_authoritative_response.hpp"

#include <algorithm>
#include <stdexcept>

namespace {

router::packet::dns::Name signed_zone_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("signed zone fixture name is malformed");
  return *parsed;
}

std::vector<std::uint8_t> signed_zone_name_wire(const char *text) {
  const auto value = signed_zone_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

} // namespace

void dnssec_signed_zone_tests() {
  using namespace router;
  using namespace router::dnssec;

  const KeySchedule schedule{.publish_at = 100U,
                             .ready_at = 100U,
                             .activate_at = 100U,
                             .retire_at = 1000U,
                             .dead_at = 1100U,
                             .remove_at = 1200U};
  ZoneKeyStore keys;
  auto ksk = ManagedKey::create(KeyRole::key_signing, schedule,
                                generate_signing_key(15U));
  auto zsk = ManagedKey::create(KeyRole::zone_signing, schedule,
                                generate_signing_key(15U));
  if (!ksk || !zsk || keys.add(std::move(*ksk)).first != ZoneKeyMutation::applied ||
      keys.add(std::move(*zsk)).first != ZoneKeyMutation::applied)
    throw std::runtime_error("signed zone keys were not admitted");

  const auto origin = signed_zone_name("example.");
  std::vector<std::uint8_t> soa = signed_zone_name_wire("ns.example.");
  const auto mailbox = signed_zone_name_wire("hostmaster.example.");
  soa.insert(soa.end(), mailbox.begin(), mailbox.end());
  soa.resize(soa.size() + 20U, 0U);
  const std::vector<dns::ZoneRecord> records{
      {.owner = origin,
       .type = packet::dns::type_soa,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = soa},
      {.owner = origin,
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = signed_zone_name_wire("ns.example.")},
      {.owner = signed_zone_name("www.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 1U)},
      {.owner = signed_zone_name("www.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 2U)},
      {.owner = signed_zone_name("child.example."),
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = signed_zone_name_wire("ns.child.example.")},
      {.owner = signed_zone_name("ns.child.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 3U)}};
  const auto signed_records = sign_zone_snapshot(
      origin, records, keys, 200U,
      {.dnskey_ttl = 3600U,
       .denial_ttl = 600U,
       .signature_inception = 100U,
       .signature_expiration = 900U});
  if (!signed_records)
    throw std::runtime_error("signed zone snapshot failed");

  std::size_t aaaa_signatures{};
  bool glue_signature{};
  bool delegation_ns_signature{};
  bool dnskey_signature{};
  for (const auto &record : *signed_records) {
    if (record.type != packet::dns::type_rrsig)
      continue;
    const auto signature = decode_rrsig(record.rdata);
    if (!signature)
      throw std::runtime_error("signed zone emitted malformed RRSIG");
    aaaa_signatures += signature->type_covered == packet::dns::type_aaaa &&
                       packet::dns::equal_case_insensitive(
                           record.owner, signed_zone_name("www.example."));
    glue_signature = glue_signature ||
                     packet::dns::equal_case_insensitive(
                         record.owner, signed_zone_name("ns.child.example."));
    delegation_ns_signature = delegation_ns_signature ||
        (signature->type_covered == packet::dns::type_ns &&
         packet::dns::equal_case_insensitive(
             record.owner, signed_zone_name("child.example.")));
    dnskey_signature = dnskey_signature ||
                       signature->type_covered == packet::dns::type_dnskey;
  }
  if (aaaa_signatures != 1U || glue_signature || delegation_ns_signature ||
      !dnskey_signature)
    throw std::runtime_error("signed zone RRset or glue signing policy is wrong");

  OpenSslCryptoVerifier crypto;
  const auto nsec3_signed = sign_zone_snapshot(
      origin, records, keys, 200U,
      {.dnskey_ttl = 3600U,
       .denial_ttl = 600U,
       .signature_inception = 100U,
       .signature_expiration = 900U,
       .denial_mode = DenialMode::nsec3},
      &crypto);
  if (!nsec3_signed)
    throw std::runtime_error("NSEC3 signed zone snapshot failed");
  bool has_nsec3{};
  bool has_nsec3param{};
  bool signs_nsec3{};
  bool signs_parameter{};
  for (const auto &record : *nsec3_signed) {
    has_nsec3 = has_nsec3 || record.type == packet::dns::type_nsec3;
    has_nsec3param = has_nsec3param ||
                     record.type == packet::dns::type_nsec3param;
    if (record.type != packet::dns::type_rrsig)
      continue;
    const auto signature = decode_rrsig(record.rdata);
    signs_nsec3 = signs_nsec3 ||
                  (signature &&
                   signature->type_covered == packet::dns::type_nsec3);
    signs_parameter = signs_parameter ||
                      (signature && signature->type_covered ==
                                        packet::dns::type_nsec3param);
  }
  if (!has_nsec3 || !has_nsec3param || !signs_nsec3 || !signs_parameter ||
      std::ranges::any_of(*nsec3_signed, [](const auto &record) {
        return record.type == packet::dns::type_nsec;
      }))
    throw std::runtime_error("NSEC3 signed material is incomplete");

  dns::Zone nsec3_zone{origin};
  if (!nsec3_zone.replace(*nsec3_signed))
    throw std::runtime_error("NSEC3 signed zone was not loadable");
  const packet::dns::Question missing{
      .name = signed_zone_name("missing.deep.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class};
  auto negative = nsec3_zone.answer(missing);
  if (!augment_authoritative_answer(nsec3_zone, missing, negative, &crypto) ||
      !std::ranges::any_of(negative.authorities, [](const auto &record) {
        return record.type == packet::dns::type_nsec3;
      }) ||
      std::ranges::any_of(negative.authorities, [](const auto &record) {
        return record.type == packet::dns::type_nsec;
      }))
    throw std::runtime_error("NSEC3 NXDOMAIN proof was not served");
}
