// NSEC3 publisher tests cover empty non-terminals, apex bitmap content,
// circular links and precise Opt-Out omission of one unsigned delegation.

#include "router/dnssec_nsec3_chain.hpp"

#include "router/dnssec_openssl.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>

namespace {

router::packet::dns::Name nsec3_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("NSEC3-chain fixture name is malformed");
  return *parsed;
}

std::string base32hex(std::span<const std::uint8_t> input) {
  static constexpr char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  std::string output;
  std::uint32_t bits{};
  unsigned count{};
  for (const auto byte : input) {
    bits = (bits << 8U) | byte;
    count += 8U;
    while (count >= 5U) {
      count -= 5U;
      output.push_back(alphabet[(bits >> count) & 0x1fU]);
      bits &= count == 0U ? 0U : (1U << count) - 1U;
    }
  }
  if (count != 0U)
    output.push_back(alphabet[(bits << (5U - count)) & 0x1fU]);
  return output;
}

std::string owner_label(const router::dns::ZoneRecord &record) {
  return std::string{
      record.owner.wire.begin() + 1,
      record.owner.wire.begin() + 1 + record.owner.wire[0]};
}

std::string hash_label(const router::packet::dns::Name &name,
                       const router::dnssec::DigestCalculator &digests) {
  router::dnssec::Nsec3 parameters{
      .hash_algorithm = 1U,
      .flags = 0U,
      .iterations = 0U,
      .salt = {},
      .next_hashed_owner = std::vector<std::uint8_t>(20U),
      .types = {}};
  std::vector<std::uint8_t> hash;
  if (router::dnssec::nsec3_hash(name, parameters, {}, digests, hash) !=
      router::dnssec::Nsec3ProofState::proved)
    throw std::runtime_error("NSEC3-chain fixture hashing failed");
  return base32hex(hash);
}

} // namespace

void dnssec_nsec3_chain_tests() {
  using namespace router;

  const auto origin = nsec3_name("example.");
  const std::vector<dns::ZoneRecord> unsigned_records{
      {.owner = origin,
       .type = packet::dns::type_soa,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = std::vector<std::uint8_t>(22U)},
      {.owner = origin,
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = {0U}},
      {.owner = nsec3_name("a.b.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 1U)},
      {.owner = nsec3_name("child.example."),
       .type = packet::dns::type_ns,
       .record_class = packet::dns::internet_class,
       .ttl = 3600U,
       .rdata = {0U}},
      {.owner = nsec3_name("ns.child.example."),
       .type = packet::dns::type_aaaa,
       .record_class = packet::dns::internet_class,
       .ttl = 300U,
       .rdata = std::vector<std::uint8_t>(16U, 2U)}};
  dnssec::OpenSslCryptoVerifier crypto;
  const auto complete = dnssec::build_nsec3_chain(
      origin, unsigned_records, 600U, {.opt_out = false}, crypto);
  if (!complete)
    throw std::runtime_error("complete NSEC3 chain construction failed");
  if (complete->records.size() != 4U)
    throw std::runtime_error("complete NSEC3 owner count is " +
                             std::to_string(complete->records.size()));
  const auto parameter = dnssec::decode_nsec3param(complete->parameter.rdata);
  if (!parameter || parameter->hash_algorithm != 1U ||
      parameter->iterations != 0U || !parameter->salt.empty() ||
      parameter->flags != 0U)
    throw std::runtime_error("RFC 9276 NSEC3PARAM values are wrong");

  const auto apex_hash = hash_label(origin, crypto);
  const auto empty_hash = hash_label(nsec3_name("b.example."), crypto);
  const auto child_hash = hash_label(nsec3_name("child.example."), crypto);
  bool found_apex{};
  bool found_empty{};
  bool found_child{};
  for (const auto &record : complete->records) {
    const auto decoded = dnssec::decode_nsec3(record.rdata);
    if (!decoded || decoded->next_hashed_owner.size() != 20U ||
        decoded->flags != 0U)
      throw std::runtime_error("complete NSEC3 record is malformed");
    const auto label = owner_label(record);
    if (label == apex_hash) {
      found_apex = std::ranges::binary_search(
                       decoded->types, packet::dns::type_soa) &&
                   std::ranges::binary_search(
                       decoded->types, packet::dns::type_nsec3param) &&
                   std::ranges::binary_search(
                       decoded->types, packet::dns::type_rrsig);
    }
    if (label == empty_hash)
      found_empty = decoded->types.empty();
    if (label == child_hash)
      found_child =
          std::ranges::binary_search(decoded->types, packet::dns::type_ns) &&
          !std::ranges::binary_search(decoded->types,
                                      packet::dns::type_rrsig);
  }
  if (!found_apex || !found_empty || !found_child)
    throw std::runtime_error("NSEC3 type bitmap or empty owner is wrong");

  const auto optout = dnssec::build_nsec3_chain(
      origin, unsigned_records, 600U, {.opt_out = true}, crypto);
  if (!optout || optout->records.size() != 3U)
    throw std::runtime_error("Opt-Out did not omit unsigned delegation");
  bool marked_cover{};
  for (const auto &record : optout->records) {
    if (owner_label(record) == child_hash)
      throw std::runtime_error("Opt-Out retained unsigned delegation owner");
    const auto decoded = dnssec::decode_nsec3(record.rdata);
    if (!decoded)
      throw std::runtime_error("Opt-Out NSEC3 record is malformed");
    marked_cover = marked_cover || decoded->flags == 1U;
  }
  if (!marked_cover)
    throw std::runtime_error("Opt-Out covering interval was not marked");
}
