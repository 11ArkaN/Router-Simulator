// DNS wire tests cover ordinary and compressed names, EDNS, unknown RDATA and
// hostile pointer shapes. Every fixture is a complete message image, matching
// what UDP or TCP delivers to the DNS service owner.

#include "router/dns_packet.hpp"
#include "router/dns_svcb.hpp"

#include <array>
#include <stdexcept>
#include <string>
#include <vector>

void dns_packet_tests() {
  using namespace router::packet::dns;

  const auto name = name_from_text("www.example.com.");
  if (!name ||
      !equal_case_insensitive(*name, *name_from_text("WWW.Example.COM")) ||
      name_from_text("bad..example") || name_from_text(std::string(64U, 'x')))
    throw std::runtime_error("DNS presentation name validation failed");

  Name uncompressed{};
  uncompressed.wire[0U] = 99U;
  constexpr std::array<std::uint8_t, 5U> one_name{3U, 'w', 'w', 'w', 0U};
  constexpr std::array<std::uint8_t, 2U> pointer{0xc0U, 0U};
  const auto plain_octets = parse_uncompressed_name(one_name, uncompressed);
  const auto before_rejection = uncompressed;
  if (!plain_octets || *plain_octets != one_name.size() ||
      uncompressed.octets != one_name.size() ||
      parse_uncompressed_name(pointer, uncompressed) ||
      uncompressed.wire != before_rejection.wire ||
      uncompressed.octets != before_rejection.octets)
    throw std::runtime_error(
        "DNS uncompressed-name boundary published invalid state");

  Question question{
      .name = *name, .type = type_a, .record_class = internet_class};
  std::array<std::uint8_t, 512U> query_bytes{};
  const auto query_octets = encode_query(
      query_bytes, 0x1234U, question, true,
      std::optional<std::uint16_t>{std::uint16_t{128U}}, true, true, true);
  std::array<Question, 1U> query_questions{};
  std::array<ResourceRecord, 1U> query_additionals{};
  const auto query =
      query_octets ? parse(std::span<const std::uint8_t>{query_bytes}.first(
                               *query_octets),
                           {.questions = query_questions,
                            .answers = {},
                            .authorities = {},
                            .additionals = query_additionals})
                   : std::nullopt;
  if (!query || query->header.id != 0x1234U ||
      !query->header.recursion_desired || !query->header.authentic_data ||
      !query->header.checking_disabled || query->questions.size() != 1U ||
      query->additionals.size() != 1U ||
      query->additionals.front().type != type_opt ||
      query->additionals.front().record_class != 512U ||
      query->additionals.front().ttl != 0x00008000U)
    throw std::runtime_error("DNS query or EDNS OPT encoding changed fields");

  // The answer owner name points to QNAME at offset 12. Unknown type 65280 is
  // preserved as four opaque RDATA octets rather than rejected or fabricated.
  std::vector<std::uint8_t> response(query_bytes.begin(),
                                     query_bytes.begin() + 33U);
  response[2U] = 0x84U;
  response[3U] = 0x00U;
  response[6U] = 0U;
  response[7U] = 1U;
  response[10U] = 0U;
  response[11U] = 0U;
  const std::array<std::uint8_t, 16U> answer{
      0xc0U, 0x0cU, 0xffU, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U,
      0x00U, 0x3cU, 0x00U, 0x04U, 0xdeU, 0xadU, 0xbeU, 0xefU};
  response.insert(response.end(), answer.begin(), answer.end());
  std::array<Question, 1U> response_questions{};
  std::array<ResourceRecord, 1U> response_answers{};
  const auto parsed_response = parse(response, {.questions = response_questions,
                                                .answers = response_answers,
                                                .authorities = {},
                                                .additionals = {}});
  if (!parsed_response || !parsed_response->header.authoritative ||
      parsed_response->answers.front().type != 0xff00U ||
      parsed_response->answers.front().ttl != 60U ||
      !equal_case_insensitive(parsed_response->answers.front().owner, *name) ||
      !std::equal(parsed_response->answers.front().rdata.begin(),
                  parsed_response->answers.front().rdata.end(),
                  answer.end() - 4))
    throw std::runtime_error("DNS compressed owner or unknown RDATA was lost");

  std::vector<std::uint8_t> cname_response(query_bytes.begin(),
                                           query_bytes.begin() + 33U);
  cname_response[2U] = 0x84U;
  cname_response[3U] = 0U;
  cname_response[6U] = 0U;
  cname_response[7U] = 1U;
  cname_response[10U] = 0U;
  cname_response[11U] = 0U;
  const std::array<std::uint8_t, 14U> cname_answer{
      0xc0U, 0x0cU, 0x00U, 0x05U, 0x00U, 0x01U, 0x00U,
      0x00U, 0x00U, 0x3cU, 0x00U, 0x02U, 0xc0U, 0x0cU};
  cname_response.insert(cname_response.end(), cname_answer.begin(),
                        cname_answer.end());
  std::array<ResourceRecord, 1U> cname_answers{};
  const auto parsed_cname =
      parse(cname_response, {.questions = response_questions,
                             .answers = cname_answers,
                             .authorities = {},
                             .additionals = {}});
  std::vector<std::uint8_t> canonical{0xffU};
  if (!parsed_cname ||
      !canonicalize_rdata(cname_response, parsed_cname->answers.front(),
                          canonical) ||
      !std::equal(canonical.begin(), canonical.end(), name->view().begin(),
                  name->view().end()))
    throw std::runtime_error("compressed DNS RDATA was not canonicalized");

  // MINFO carries two independently compressible names. Expanding both is
  // necessary before cache or checkpoint storage because message pointers are
  // invalid as soon as the receive buffer is released.
  auto minfo_response = cname_response;
  minfo_response[minfo_response.size() - 4U] = 0x00U;
  minfo_response[minfo_response.size() - 3U] = 0x04U;
  minfo_response[minfo_response.size() - 2U] = 0xc0U;
  minfo_response[minfo_response.size() - 1U] = 0x0cU;
  minfo_response.insert(minfo_response.end(), {0xc0U, 0x0cU});
  minfo_response[minfo_response.size() - 14U] = 0x00U;
  minfo_response[minfo_response.size() - 13U] =
      static_cast<std::uint8_t>(type_minfo);
  std::array<ResourceRecord, 1U> minfo_answers{};
  const auto parsed_minfo =
      parse(minfo_response, {.questions = response_questions,
                             .answers = minfo_answers,
                             .authorities = {},
                             .additionals = {}});
  std::vector<std::uint8_t> canonical_minfo;
  if (!parsed_minfo ||
      !canonicalize_rdata(minfo_response, parsed_minfo->answers.front(),
                          canonical_minfo) ||
      canonical_minfo.size() != name->octets * 2U ||
      !std::equal(canonical_minfo.begin(),
                  canonical_minfo.begin() + name->octets, name->view().begin(),
                  name->view().end()) ||
      !std::equal(canonical_minfo.begin() + name->octets, canonical_minfo.end(),
                  name->view().begin(), name->view().end()))
    throw std::runtime_error(
        "compressed DNS MINFO names were not canonicalized");

  // RFC 9460 uses an uncompressed TargetName followed by strictly increasing
  // parameters. This fixture advertises h2 and h3, a non-default port and the
  // DNS mapping's relative URI template while marking ALPN and dohpath as
  // mandatory.
  const std::array<std::uint8_t, 64U> svcb_rdata{
      0x00U, 0x01U, 0x08U, 'r',   'e',   's',   'o',   'l',   'v',   'e',
      'r',   0x07U, 'e',   'x',   'a',   'm',   'p',   'l',   'e',   0x00U,
      0x00U, 0x00U, 0x00U, 0x04U, 0x00U, 0x01U, 0x00U, 0x07U, 0x00U, 0x01U,
      0x00U, 0x06U, 0x02U, 'h',   '2',   0x02U, 'h',   '3',   0x00U, 0x03U,
      0x00U, 0x02U, 0x03U, 0x55U, 0x00U, 0x07U, 0x00U, 0x10U, '/',   'd',
      'n',   's',   '-',   'q',   'u',   'e',   'r',   'y',   '{',   '?',
      'd',   'n',   's',   '}'};
  std::array<svcb::Parameter, 8U> svcb_parameters{};
  const auto binding = svcb::parse(svcb_rdata, svcb_parameters);
  std::size_t alpn_count{};
  const auto *alpn = binding ? svcb::find(*binding, svcb::key_alpn) : nullptr;
  if (!binding || binding->alias_mode() || binding->priority != 1U || !alpn ||
      !svcb::find(*binding, svcb::key_port) ||
      !svcb::find(*binding, svcb::key_dohpath) ||
      !svcb::visit_alpn(alpn->value,
                        [&](std::span<const std::uint8_t>) {
                          ++alpn_count;
                          return true;
                        }) ||
      alpn_count != 2U)
    throw std::runtime_error("SVCB service record decoding failed");
  auto malformed_svcb = svcb_rdata;
  // Repeating key 1 where key 3 belongs violates the strictly increasing key
  // order and must reject the whole RR instead of accepting ambiguous policy.
  malformed_svcb[38U] = 0x00U;
  malformed_svcb[39U] = 0x01U;
  if (svcb::parse(malformed_svcb, svcb_parameters))
    throw std::runtime_error("SVCB accepted duplicate parameter keys");

  std::array<std::uint8_t, 514U> stream{};
  const auto stream_octets = encode_stream_message(
      stream, std::span<const std::uint8_t>{query_bytes}.first(*query_octets));
  const auto stream_message =
      stream_octets
          ? decode_stream_message(
                std::span<const std::uint8_t>{stream}.first(*stream_octets))
          : std::nullopt;
  if (!stream_message || stream_message->consumed_octets != *stream_octets ||
      stream_message->message.size() != *query_octets ||
      decode_stream_message(std::span<const std::uint8_t>{stream}.first(1U)))
    throw std::runtime_error("DNS TCP length framing failed");

  // Self and forward pointers violate the prior-occurrence compression rule.
  // They must fail without recursion, allocation or partial output mutation.
  std::array<std::uint8_t, 2U> self_pointer{0xc0U, 0x00U};
  std::array<std::uint8_t, 4U> forward_pointer{0xc0U, 0x02U, 0U, 0U};
  Name rejected;
  if (parse_name(self_pointer, 0U, rejected) ||
      parse_name(forward_pointer, 0U, rejected))
    throw std::runtime_error("DNS compression accepted a looping pointer");

  // Caller-provided section capacity is a hard admission boundary. The parser
  // never truncates an answer count or allocates hidden replacement storage.
  if (parse(response, {.questions = response_questions,
                       .answers = {},
                       .authorities = {},
                       .additionals = {}}))
    throw std::runtime_error("DNS parser ignored section storage exhaustion");

  // Truncation occurs before an entire consecutive RRset. A buffer that can
  // hold one of two A records must therefore advertise zero answers and TC,
  // allowing the requester to retry the complete query over TCP.
  const std::array<std::uint8_t, 4U> address_one{192U, 0U, 2U, 1U};
  const std::array<std::uint8_t, 4U> address_two{192U, 0U, 2U, 2U};
  const std::array<RecordData, 2U> rrset{
      RecordData{.owner = *name,
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 300U,
                 .rdata = address_one},
      RecordData{.owner = *name,
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 300U,
                 .rdata = address_two}};
  std::array<std::uint8_t, 60U> truncated_bytes{};
  const auto truncated_octets =
      encode_response(truncated_bytes, 0x1234U, question, rrset, {}, {},
                      {.authoritative = true,
                       .recursion_desired = true,
                       .edns_udp_payload_size = std::nullopt,
                       .edns_extended_rcode = 0U,
                       .edns_version = 0U,
                       .dnssec_ok = false});
  std::array<Question, 1U> truncated_questions{};
  const auto truncated_message =
      truncated_octets
          ? parse(std::span<const std::uint8_t>{truncated_bytes}.first(
                      *truncated_octets),
                  {.questions = truncated_questions,
                   .answers = {},
                   .authorities = {},
                   .additionals = {}})
          : std::nullopt;
  if (!truncated_message || !truncated_message->header.truncated ||
      truncated_message->header.answer_count != 0U)
    throw std::runtime_error("DNS encoder split an RRset during truncation");

  std::array<std::uint8_t, 512U> edns_response_bytes{};
  const auto edns_response_octets =
      encode_response(edns_response_bytes, 0x1234U, question, {}, {}, {},
                      {.authoritative = true,
                       .edns_udp_payload_size = std::uint16_t{1232U},
                       .edns_extended_rcode = 0U,
                       .edns_version = 0U,
                       .dnssec_ok = true});
  std::array<Question, 1U> edns_response_questions{};
  std::array<ResourceRecord, 1U> edns_response_additionals{};
  const auto edns_response =
      edns_response_octets
          ? parse(std::span<const std::uint8_t>{edns_response_bytes}.first(
                      *edns_response_octets),
                  {.questions = edns_response_questions,
                   .answers = {},
                   .authorities = {},
                   .additionals = edns_response_additionals})
          : std::nullopt;
  if (!edns_response || edns_response->additionals.size() != 1U ||
      edns_response->additionals.front().type != type_opt ||
      edns_response->additionals.front().record_class != 1232U ||
      (edns_response->additionals.front().ttl & 0x8000U) == 0U)
    throw std::runtime_error("DNS response omitted negotiated EDNS OPT data");

  // When a malformed request leaves no trustworthy question, RFC 1035 uses a
  // header-only FORMERR. Opcode, RD and CD remain visible to the requester,
  // while every section count is zero rather than echoing unparsed bytes.
  std::array<std::uint8_t, header_octets> error_bytes{};
  const auto error_octets = encode_error_response(
      error_bytes, 0xbeefU, 2U, Rcode::format_error, true, true);
  const auto error_message =
      error_octets ? parse(std::span<const std::uint8_t>{error_bytes}.first(
                               *error_octets),
                           {.questions = {},
                            .answers = {},
                            .authorities = {},
                            .additionals = {}})
                   : std::nullopt;
  if (!error_message || !error_message->header.response ||
      error_message->header.id != 0xbeefU ||
      error_message->header.opcode != 2U ||
      error_message->header.rcode != Rcode::format_error ||
      !error_message->header.recursion_desired ||
      !error_message->header.checking_disabled ||
      error_message->header.question_count != 0U)
    throw std::runtime_error("DNS header-only error response changed fields");
}
