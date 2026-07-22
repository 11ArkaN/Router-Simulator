// DNS master-file tests verify presentation syntax and exact wire-data
// preservation together. A successful parse is also admitted through Zone so
// the test cannot pass with records the authoritative implementation rejects.

#include "router/dns_master_file.hpp"

#include <algorithm>
#include <stdexcept>

namespace {

router::packet::dns::Name name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("master-file fixture name is invalid");
  return *parsed;
}

bool same_record(const router::dns::ZoneRecord &left,
                 const router::dns::ZoneRecord &right) {
  // ZoneRecord intentionally has no broad equality operator. Comparing every
  // persisted field here ensures a later field addition must update this test.
  return router::packet::dns::equal_case_insensitive(left.owner, right.owner) &&
         left.type == right.type && left.record_class == right.record_class &&
         left.ttl == right.ttl && left.rdata == right.rdata;
}

} // namespace

void dns_master_file_tests() {
  using namespace router;

  static constexpr auto fixture = R"ZONE($ORIGIN example.test.
$TTL 300
@ IN SOA ns hostmaster ( 2026071701 3600 600 86400 60 )
  IN NS ns
ns A 192.0.2.53
www 60 AAAA 2001:db8::1
alias CNAME www
service SRV 10 20 443 www
escaped\046label TXT "hello world" "\059"
opaque TYPE65280 \# 4 DEADBEEF
)ZONE";

  const auto imported = dns::import_master_file(fixture);
  if (!imported || imported.records.size() != 8U)
    throw std::runtime_error("valid DNS master file was rejected");

  // Zone::replace is the publication boundary. Import remains detached until
  // all authoritative invariants, including owner containment, succeed.
  dns::Zone zone{name("example.test.")};
  if (!zone.replace(imported.records))
    throw std::runtime_error("imported DNS records failed zone validation");

  const auto exported =
      dns::export_master_file(name("example.test."), imported.records);
  if (!exported ||
      exported->find("TYPE65280 \\# 4 DEADBEEF") == std::string::npos)
    throw std::runtime_error("generic DNS master-file export failed");

  // RFC 3597 generic RDATA is deliberately used for every exported RR. A
  // re-import must therefore reproduce unknown and known RDATA byte-for-byte.
  const auto round_trip = dns::import_master_file(*exported);
  if (!round_trip || round_trip.records.size() != imported.records.size() ||
      !std::equal(imported.records.begin(), imported.records.end(),
                  round_trip.records.begin(), same_record))
    throw std::runtime_error("DNS master-file round trip changed records");

  const auto malformed = dns::import_master_file(
      "$ORIGIN example.test.\n$TTL 60\nbad TYPE65280 \\# 4 DEAD\n");
  if (malformed || !malformed.records.empty() ||
      malformed.error.code != dns::MasterFileErrorCode::invalid_rdata)
    throw std::runtime_error("partial malformed DNS zone escaped import");

  const auto unavailable_include =
      dns::import_master_file("$ORIGIN example.test.\n$INCLUDE child.zone\n");
  if (unavailable_include || unavailable_include.error.code !=
                                 dns::MasterFileErrorCode::include_unavailable)
    throw std::runtime_error(
        "DNS include without an owner resolver was accepted");

  // RFC 1035 defines INCLUDE as textual insertion except that the child
  // origin cannot escape back into the parent. The resolver supplies detached
  // bytes and canonical names; the parser itself never opens a host file.
  const dns::MasterFileIncludeResolver include_resolver =
      [](std::string_view referring,
         std::string_view requested) -> std::optional<dns::MasterFileInclude> {
    if (referring == "root.zone" && requested == "child.zone")
      return dns::MasterFileInclude{.canonical_name = "child.zone",
                                    .contents =
                                        R"ZONE(@ HINFO "router-cpu" "sros"
mail MB gateway
obsolete-md MD gateway
obsolete-mf MF gateway
renamed MR replacement
list MINFO owner errors
services WKS 192.0.2.1 TCP SMTP DOMAIN
$ORIGIN nested
$INCLUDE nested.zone
)ZONE"};
    if (referring == "child.zone" && requested == "nested.zone")
      return dns::MasterFileInclude{.canonical_name = "nested.zone",
                                    .contents = "member MG person\n"};
    return std::nullopt;
  };
  const auto included = dns::import_master_file(
      "$ORIGIN example.test.\n$TTL 60\n"
      "$INCLUDE child.zone child.example.test.\n"
      "after A 192.0.2.9\n",
      std::nullopt, std::nullopt, &include_resolver, "root.zone");
  if (!included || included.records.size() != 9U ||
      !packet::dns::equal_case_insensitive(included.records.front().owner,
                                           name("child.example.test.")) ||
      included.records.front().type != packet::dns::type_hinfo ||
      !packet::dns::equal_case_insensitive(
          included.records[7U].owner,
          name("member.nested.child.example.test.")) ||
      !packet::dns::equal_case_insensitive(included.records.back().owner,
                                           name("after.example.test.")))
    throw std::runtime_error(
        "DNS INCLUDE origin scoping or typed records failed");
  const auto &wks = included.records[6U].rdata;
  if (wks.size() != 12U || wks[4U] != 6U ||
      (wks[5U + 25U / 8U] & (0x80U >> (25U % 8U))) == 0U ||
      (wks[5U + 53U / 8U] & (0x80U >> (53U % 8U))) == 0U)
    throw std::runtime_error("DNS WKS mnemonic bitmap encoding failed");

  const dns::MasterFileIncludeResolver cyclic_resolver =
      [](std::string_view,
         std::string_view requested) -> std::optional<dns::MasterFileInclude> {
    if (requested == "child.zone")
      return dns::MasterFileInclude{.canonical_name = "child.zone",
                                    .contents = "$INCLUDE root.zone\n"};
    if (requested == "root.zone")
      return dns::MasterFileInclude{.canonical_name = "root.zone",
                                    .contents = {}};
    return std::nullopt;
  };
  const auto cycle = dns::import_master_file(
      "$ORIGIN example.test.\n$TTL 60\n$INCLUDE child.zone\n", std::nullopt,
      std::nullopt, &cyclic_resolver, "root.zone");
  if (cycle || cycle.error.code != dns::MasterFileErrorCode::include_cycle ||
      cycle.error.source != "child.zone")
    throw std::runtime_error("DNS active INCLUDE cycle was not rejected");

  const auto null_mnemonic = dns::import_master_file(
      "$ORIGIN example.test.\n$TTL 60\nnull NULL data\n");
  if (null_mnemonic ||
      null_mnemonic.error.code != dns::MasterFileErrorCode::invalid_rdata)
    throw std::runtime_error(
        "RFC 1035 NULL mnemonic escaped master-file rejection");

  // Export performs the same name validation as import. A malformed owner is
  // rejected before any partial text can reach persistence or a download.
  auto corrupt = imported.records.front();
  corrupt.owner.wire[0] = 64U;
  if (dns::export_master_file(name("example.test."),
                              std::span<const dns::ZoneRecord>{&corrupt, 1U}))
    throw std::runtime_error("invalid DNS owner escaped export validation");
}
