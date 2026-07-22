// End-to-end response validation uses independently verified signatures from
// the pinned crypto provider. It covers positive wildcard data, authenticated
// NXDOMAIN, insecure delegation, tampering and a missing-signature failure.

#include "router/dnssec_response_validation.hpp"

#include "router/dnssec_authoritative_response.hpp"
#include "router/dnssec_nsec_chain.hpp"
#include "router/dnssec_openssl.hpp"
#include "router/dnssec_zone_signer.hpp"

#include <algorithm>
#include <ranges>
#include <stdexcept>

namespace {

router::packet::dns::Name response_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("response-validation fixture name is malformed");
  return *parsed;
}

std::vector<std::uint8_t> response_name_wire(const char *text) {
  const auto value = response_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

void append_u32(std::vector<std::uint8_t> &wire, std::uint32_t value) {
  wire.push_back(static_cast<std::uint8_t>(value >> 24U));
  wire.push_back(static_cast<std::uint8_t>(value >> 16U));
  wire.push_back(static_cast<std::uint8_t>(value >> 8U));
  wire.push_back(static_cast<std::uint8_t>(value));
}

std::vector<std::uint8_t> response_soa() {
  auto wire = response_name_wire("ns.example.");
  const auto mailbox = response_name_wire("hostmaster.example.");
  wire.insert(wire.end(), mailbox.begin(), mailbox.end());
  append_u32(wire, 1U);
  append_u32(wire, 3600U);
  append_u32(wire, 600U);
  append_u32(wire, 86400U);
  append_u32(wire, 600U);
  return wire;
}

std::vector<router::dns::ZoneRecord>
own(std::span<const router::packet::dns::RecordData> records) {
  std::vector<router::dns::ZoneRecord> result;
  result.reserve(records.size());
  for (const auto &record : records)
    result.push_back({.owner = record.owner,
                      .type = record.type,
                      .record_class = record.record_class,
                      .ttl = record.ttl,
                      .rdata = {record.rdata.begin(), record.rdata.end()}});
  return result;
}

} // namespace

void dnssec_response_validation_tests() {
  using namespace router;

  const auto origin = response_name("example.");
  std::vector<dns::ZoneRecord> records{
      {.owner = origin,
       .type = packet::dns::type_soa,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = response_soa()},
      {.owner = origin,
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = response_name_wire("ns.example.")},
      {.owner = response_name("*.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 0x20U)},
      {.owner = response_name("child.example."),
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = response_name_wire("ns.child.example.")},
      {.owner = response_name("ns.child.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 0x30U)}};
  const auto key = dnssec::generate_signing_key(15U);
  const auto dnskey = key ? dnssec::make_dnskey_record(
                                origin, 3600U, *key,
                                dnssec::KeyRole::key_signing)
                          : std::nullopt;
  if (!key || !dnskey)
    throw std::runtime_error("response-validation key generation failed");
  records.push_back(*dnskey);
  const auto nsecs = dnssec::build_nsec_chain(origin, records, 600U);
  if (!nsecs)
    throw std::runtime_error("response-validation NSEC chain failed");
  records.insert(records.end(), nsecs->begin(), nsecs->end());

  const auto unsigned_count = records.size();
  for (std::size_t index{}; index < unsigned_count; ++index) {
    const auto &record = records[index];
    // Delegation NS and its glue are non-authoritative parent data and RFC
    // 4035 explicitly forbids signing them in the parent zone.
    if (packet::dns::equal_case_insensitive(
            record.owner, response_name("child.example.")) &&
        record.type == packet::dns::type_ns)
      continue;
    if (packet::dns::equal_case_insensitive(
            record.owner, response_name("ns.child.example.")))
      continue;
    const auto signature = dnssec::sign_rrset(
        std::span{&record, 1U}, *dnskey, *key, 1000U, 2000U);
    if (!signature)
      throw std::runtime_error("response-validation signing failed");
    records.push_back(*signature);
  }

  dns::Zone zone{origin};
  if (!zone.replace(records))
    throw std::runtime_error("response-validation signed zone was rejected");
  const std::vector<dns::ZoneRecord> zone_keys{*dnskey};
  dnssec::OpenSslCryptoVerifier crypto;

  const packet::dns::Question wildcard_question{
      .name = response_name("host.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class};
  auto wildcard = zone.answer(wildcard_question);
  if (!dnssec::augment_authoritative_answer(zone, wildcard_question,
                                             wildcard))
    throw std::runtime_error("wildcard response augmentation failed");
  auto wildcard_answers = own(wildcard.answers);
  auto wildcard_authorities = own(wildcard.authorities);
  const auto wildcard_validation = dnssec::validate_secure_zone_response(
      wildcard_question, wildcard.rcode, wildcard_answers,
      wildcard_authorities, origin, zone_keys, 1500U, crypto, crypto);
  if (wildcard_validation.security != dnssec::ResponseSecurity::secure ||
      !wildcard_validation.wildcard_expansion)
    throw std::runtime_error("secure wildcard response did not validate");

  auto tampered = wildcard_answers;
  const auto address = std::ranges::find(tampered, packet::dns::type_aaaa,
                                         &dns::ZoneRecord::type);
  if (address == tampered.end())
    throw std::runtime_error("wildcard response omitted AAAA fixture");
  address->rdata[0] ^= 1U;
  if (dnssec::validate_secure_zone_response(
          wildcard_question, wildcard.rcode, tampered, wildcard_authorities,
          origin, zone_keys, 1500U, crypto, crypto)
          .security != dnssec::ResponseSecurity::bogus)
    throw std::runtime_error("tampered wildcard response was accepted");

  const packet::dns::Question missing_question{
      .name = response_name("absent.deep.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class};
  auto missing = zone.answer(missing_question);
  if (!dnssec::augment_authoritative_answer(zone, missing_question, missing))
    throw std::runtime_error("NXDOMAIN response augmentation failed");
  auto missing_answers = own(missing.answers);
  auto missing_authorities = own(missing.authorities);
  const auto missing_validation = dnssec::validate_secure_zone_response(
      missing_question, missing.rcode, missing_answers, missing_authorities,
      origin, zone_keys, 1500U, crypto, crypto);
  if (missing_validation.security != dnssec::ResponseSecurity::secure ||
      std::ranges::any_of(missing_authorities, [](const auto &record) {
        return record.ttl > 500U;
      }))
    throw std::runtime_error("authenticated NXDOMAIN did not validate");

  const packet::dns::Question referral_question{
      .name = response_name("host.child.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class};
  auto referral = zone.answer(referral_question);
  if (!dnssec::augment_authoritative_answer(zone, referral_question,
                                             referral))
    throw std::runtime_error("referral response augmentation failed");
  auto referral_answers = own(referral.answers);
  auto referral_authorities = own(referral.authorities);
  const auto referral_validation = dnssec::validate_secure_zone_response(
      referral_question, referral.rcode, referral_answers,
      referral_authorities, origin, zone_keys, 1500U, crypto, crypto);
  if (referral_validation.security !=
      dnssec::ResponseSecurity::insecure_delegation)
    throw std::runtime_error("authenticated no-DS referral was not insecure");

  wildcard_answers.erase(
      std::remove_if(wildcard_answers.begin(), wildcard_answers.end(),
                     [](const auto &record) {
                       return record.type == packet::dns::type_rrsig;
                     }),
      wildcard_answers.end());
  if (dnssec::validate_secure_zone_response(
          wildcard_question, wildcard.rcode, wildcard_answers,
          wildcard_authorities, origin, zone_keys, 1500U, crypto, crypto)
          .failure != dnssec::ResponseValidationFailure::missing_signature)
    throw std::runtime_error("unsigned secure-zone RRset was accepted");
}
