// Authoritative DNS tests exercise positive, negative and delegated answers
// from one immutable zone generation. Returned records are then encoded and
// parsed as a complete DNS response to keep repository and wire contracts tied.

#include "router/dns_authoritative.hpp"

#include <array>
#include <stdexcept>

namespace {

router::packet::dns::Name name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("authoritative DNS fixture name is invalid");
  return *parsed;
}

std::vector<std::uint8_t> name_data(const char *text) {
  const auto value = name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

void append_u32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

} // namespace

void dns_authoritative_tests() {
  using namespace router;
  using namespace router::packet::dns;

  const auto origin = name("example.test.");
  auto soa = name_data("ns.example.test.");
  const auto mailbox = name_data("hostmaster.example.test.");
  soa.insert(soa.end(), mailbox.begin(), mailbox.end());
  append_u32(soa, 2026071701U);
  append_u32(soa, 3600U);
  append_u32(soa, 600U);
  append_u32(soa, 86400U);
  append_u32(soa, 120U);

  dns::Zone zone{origin};
  std::vector<dns::ZoneRecord> records{
      {.owner = origin, .type = type_soa, .ttl = 600U, .rdata = soa},
      {.owner = origin,
       .type = type_ns,
       .ttl = 300U,
       .rdata = name_data("ns.example.test.")},
      {.owner = name("ns.example.test."),
       .type = type_a,
       .ttl = 300U,
       .rdata = {192U, 0U, 2U, 53U}},
      {.owner = name("www.example.test."),
       .type = type_a,
       .ttl = 60U,
       .rdata = {192U, 0U, 2U, 80U}},
      {.owner = name("alias.example.test."),
       .type = type_cname,
       .ttl = 60U,
       .rdata = name_data("www.example.test.")},
      {.owner = name("child.example.test."),
       .type = type_ns,
       .ttl = 300U,
       .rdata = name_data("ns.child.example.test.")},
      {.owner = name("ns.child.example.test."),
       .type = type_a,
       .ttl = 300U,
       .rdata = {198U, 51U, 100U, 53U}},
      {.owner = name("leaf.empty.example.test."),
       .type = type_a,
       .ttl = 60U,
       .rdata = {192U, 0U, 2U, 81U}},
      {.owner = name("*.wild.example.test."),
       .type = type_a,
       .ttl = 60U,
       .rdata = {192U, 0U, 2U, 82U}},
      {.owner = name("tree.example.test."),
       .type = type_dname,
       .ttl = 60U,
       .rdata = name_data("replacement.example.net.")}};
  if (!zone.replace(std::move(records)))
    throw std::runtime_error("authoritative DNS zone import was rejected");

  const Question positive_question{.name = name("www.example.test."),
                                   .type = type_a,
                                   .record_class = internet_class};
  const auto positive = zone.answer(positive_question);
  if (!positive.authoritative || positive.rcode != Rcode::no_error ||
      positive.answers.size() != 1U ||
      positive.answers.front().rdata.size() != 4U)
    throw std::runtime_error("authoritative DNS positive lookup failed");

  const auto missing = zone.answer(
      {.name = name("missing.example.test."),
       .type = type_a,
       .record_class = internet_class});
  if (!missing.authoritative || missing.rcode != Rcode::name_error ||
      missing.authorities.size() != 1U ||
      missing.authorities.front().type != type_soa ||
      missing.authorities.front().ttl != 120U)
    throw std::runtime_error("authoritative DNS NXDOMAIN omitted negative SOA");

  const auto nodata = zone.answer(
      {.name = positive_question.name,
       .type = type_aaaa,
       .record_class = internet_class});
  if (nodata.rcode != Rcode::no_error || !nodata.answers.empty() ||
      nodata.authorities.size() != 1U)
    throw std::runtime_error("authoritative DNS NODATA was not distinguishable");

  const auto empty_non_terminal = zone.answer(
      {.name = name("empty.example.test."),
       .type = type_aaaa,
       .record_class = internet_class});
  if (empty_non_terminal.rcode != Rcode::no_error ||
      !empty_non_terminal.answers.empty() ||
      empty_non_terminal.authorities.size() != 1U)
    throw std::runtime_error("empty non-terminal was incorrectly NXDOMAIN");

  const auto wildcard = zone.answer(
      {.name = name("host.wild.example.test."),
       .type = type_a,
       .record_class = internet_class});
  if (wildcard.answers.size() != 1U ||
      !equal_case_insensitive(wildcard.answers.front().owner,
                              name("host.wild.example.test.")) ||
      wildcard.answers.front().rdata.back() != 82U)
    throw std::runtime_error("wildcard answer did not synthesize QNAME owner");

  const auto dname = zone.answer(
      {.name = name("host.tree.example.test."),
       .type = type_a,
       .record_class = internet_class});
  const auto dname_target = name_data("host.replacement.example.net.");
  if (dname.answers.size() != 2U || dname.answers[0].type != type_dname ||
      dname.answers[1].type != type_cname ||
      !std::equal(dname.answers[1].rdata.begin(), dname.answers[1].rdata.end(),
                  dname_target.begin(), dname_target.end()))
    throw std::runtime_error("DNAME did not synthesize the required CNAME");

  const auto referral = zone.answer(
      {.name = name("host.child.example.test."),
       .type = type_a,
       .record_class = internet_class});
  if (referral.authoritative || !referral.referral ||
      referral.authorities.size() != 1U ||
      referral.additionals.size() != 1U ||
      referral.additionals.front().type != type_a)
    throw std::runtime_error("authoritative DNS delegation or glue failed");

  // DS is parent-side data at the cut and must not be answered as a referral.
  const auto absent_ds = zone.answer(
      {.name = name("child.example.test."),
       .type = type_ds,
       .record_class = internet_class});
  if (!absent_ds.authoritative || absent_ds.referral ||
      absent_ds.authorities.size() != 1U)
    throw std::runtime_error("authoritative DNS mishandled DS at a zone cut");

  std::array<std::uint8_t, 512U> wire{};
  const auto encoded = encode_response(
      wire, 0x4444U, positive_question, positive.answers,
      positive.authorities, positive.additionals,
      {.rcode = positive.rcode,
       .authoritative = positive.authoritative,
       .edns_udp_payload_size = std::nullopt,
       .edns_extended_rcode = 0U,
       .edns_version = 0U,
       .dnssec_ok = false});
  std::array<Question, 1U> questions{};
  std::array<ResourceRecord, 1U> answers{};
  const auto parsed =
      encoded ? parse(std::span<const std::uint8_t>{wire}.first(*encoded),
                      {.questions = questions,
                       .answers = answers,
                       .authorities = {},
                       .additionals = {}})
              : std::nullopt;
  if (!parsed || !parsed->header.authoritative ||
      parsed->answers.size() != 1U ||
      parsed->answers.front().rdata[3U] != 80U)
    throw std::runtime_error("authoritative DNS answer failed wire round trip");
}
