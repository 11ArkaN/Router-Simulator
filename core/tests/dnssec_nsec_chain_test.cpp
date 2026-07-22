// NSEC chain tests cover canonical ordering, circular closure, type bitmaps and
// exclusion of in-bailiwick glue below an unsigned child delegation.

#include "router/dnssec_nsec_chain.hpp"

#include "router/dnssec_record.hpp"

#include <stdexcept>

namespace {

router::packet::dns::Name nsec_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("NSEC chain fixture name is malformed");
  return *parsed;
}

std::vector<std::uint8_t> nsec_name_wire(const char *text) {
  const auto value = nsec_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

} // namespace

void dnssec_nsec_chain_tests() {
  using namespace router;

  const auto origin = nsec_name("example.");
  const std::vector<dns::ZoneRecord> records{
      {.owner = origin,
       .type = packet::dns::type_soa,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = {}},
      {.owner = origin,
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = nsec_name_wire("ns.example.")},
      {.owner = nsec_name("A.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 1U)},
      {.owner = nsec_name("child.example."),
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = nsec_name_wire("ns.child.example.")},
      {.owner = nsec_name("ns.child.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 2U)}};
  const auto chain = dnssec::build_nsec_chain(origin, records, 600U);
  if (!chain || chain->size() != 3U)
    throw std::runtime_error("NSEC chain included glue or omitted an owner");
  if (!packet::dns::equal_case_insensitive((*chain)[0].owner, origin) ||
      !packet::dns::equal_case_insensitive((*chain)[1].owner,
                                           nsec_name("A.example.")) ||
      !packet::dns::equal_case_insensitive((*chain)[2].owner,
                                           nsec_name("child.example.")))
    throw std::runtime_error("NSEC chain canonical order is wrong");
  const auto apex_nsec = dnssec::decode_nsec((*chain)[0].rdata);
  const auto cut_nsec = dnssec::decode_nsec((*chain)[2].rdata);
  if (!apex_nsec || !cut_nsec ||
      !packet::dns::equal_case_insensitive(cut_nsec->next_domain, origin) ||
      !std::ranges::binary_search(cut_nsec->types, packet::dns::type_ns) ||
      std::ranges::binary_search(cut_nsec->types, packet::dns::type_aaaa) ||
      !std::ranges::binary_search(cut_nsec->types, packet::dns::type_nsec) ||
      !std::ranges::binary_search(cut_nsec->types, packet::dns::type_rrsig))
    throw std::runtime_error("NSEC chain closure or bitmap is wrong");
}
