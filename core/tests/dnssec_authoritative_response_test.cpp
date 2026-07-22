// Signed authoritative response tests construct a complete in-memory signed
// zone and verify positive, NXDOMAIN and insecure-delegation record selection.

#include "router/dnssec_authoritative_response.hpp"

#include "router/dnssec_nsec_chain.hpp"
#include "router/dnssec_zone_signer.hpp"

#include <algorithm>
#include <stdexcept>

namespace {

router::packet::dns::Name authoritative_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("signed authoritative fixture name is malformed");
  return *parsed;
}

std::vector<std::uint8_t> authoritative_name_wire(const char *text) {
  const auto value = authoritative_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

void append_u32(std::vector<std::uint8_t> &wire, std::uint32_t value) {
  wire.push_back(static_cast<std::uint8_t>(value >> 24U));
  wire.push_back(static_cast<std::uint8_t>(value >> 16U));
  wire.push_back(static_cast<std::uint8_t>(value >> 8U));
  wire.push_back(static_cast<std::uint8_t>(value));
}

std::vector<std::uint8_t> soa_wire() {
  auto wire = authoritative_name_wire("ns.example.");
  const auto mailbox = authoritative_name_wire("hostmaster.example.");
  wire.insert(wire.end(), mailbox.begin(), mailbox.end());
  append_u32(wire, 1U);
  append_u32(wire, 3600U);
  append_u32(wire, 600U);
  append_u32(wire, 86400U);
  append_u32(wire, 600U);
  return wire;
}

bool has_type(std::span<const router::packet::dns::RecordData> records,
              std::uint16_t type) {
  return std::ranges::any_of(records,
                             [&](const auto &record) {
                               return record.type == type;
                             });
}

} // namespace

void dnssec_authoritative_response_tests() {
  using namespace router;

  const auto origin = authoritative_name("example.");
  std::vector<dns::ZoneRecord> unsigned_records{
      {.owner = origin,
       .type = packet::dns::type_soa,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = soa_wire()},
      {.owner = origin,
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = authoritative_name_wire("ns.example.")},
      {.owner = authoritative_name("www.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 1U)},
      {.owner = authoritative_name("child.example."),
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = authoritative_name_wire("ns.child.example.")},
      {.owner = authoritative_name("ns.child.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 2U)}};
  const auto key = dnssec::generate_signing_key(15U);
  const auto dnskey = key ? dnssec::make_dnskey_record(
                                origin, 3600U, *key,
                                dnssec::KeyRole::key_signing)
                          : std::nullopt;
  if (!key || !dnskey)
    throw std::runtime_error("signed authoritative fixture key failed");
  unsigned_records.push_back(*dnskey);
  const auto nsecs = dnssec::build_nsec_chain(origin, unsigned_records, 600U);
  if (!nsecs)
    throw std::runtime_error("signed authoritative NSEC chain failed");

  std::vector<dns::ZoneRecord> signed_records = unsigned_records;
  signed_records.insert(signed_records.end(), nsecs->begin(), nsecs->end());
  const auto records_to_sign = signed_records.size();
  for (std::size_t index{}; index < records_to_sign; ++index) {
    const auto &record = signed_records[index];
    // Glue below child.example is outside the parent authoritative data and
    // intentionally remains unsigned.
    if (packet::dns::equal_case_insensitive(
            record.owner, authoritative_name("ns.child.example.")))
      continue;
    const auto signature = dnssec::sign_rrset(
        std::span{&record, 1U}, *dnskey, *key, 1000U, 2000U);
    if (!signature)
      throw std::runtime_error("signed authoritative RRset signing failed");
    signed_records.push_back(*signature);
  }

  dns::Zone zone{origin};
  if (!zone.replace(std::move(signed_records)))
    throw std::runtime_error("signed authoritative zone was rejected");

  const packet::dns::Question positive{
      .name = authoritative_name("www.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class};
  auto positive_answer = zone.answer(positive);
  if (!dnssec::augment_authoritative_answer(zone, positive, positive_answer) ||
      !has_type(positive_answer.answers, packet::dns::type_aaaa) ||
      !has_type(positive_answer.answers, packet::dns::type_rrsig))
    throw std::runtime_error("signed positive answer omitted RRSIG");

  const packet::dns::Question missing{
      .name = authoritative_name("absent.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class};
  auto negative_answer = zone.answer(missing);
  if (!dnssec::augment_authoritative_answer(zone, missing, negative_answer) ||
      negative_answer.rcode != packet::dns::Rcode::name_error ||
      !has_type(negative_answer.authorities, packet::dns::type_soa) ||
      !has_type(negative_answer.authorities, packet::dns::type_nsec) ||
      !has_type(negative_answer.authorities, packet::dns::type_rrsig))
    throw std::runtime_error("signed NXDOMAIN answer omitted its proof");

  const packet::dns::Question referral{
      .name = authoritative_name("host.child.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class};
  auto referral_answer = zone.answer(referral);
  if (!dnssec::augment_authoritative_answer(zone, referral, referral_answer) ||
      !referral_answer.referral ||
      !has_type(referral_answer.authorities, packet::dns::type_ns) ||
      !has_type(referral_answer.authorities, packet::dns::type_nsec) ||
      !has_type(referral_answer.authorities, packet::dns::type_rrsig))
    throw std::runtime_error("signed insecure referral omitted no-DS proof");
}
