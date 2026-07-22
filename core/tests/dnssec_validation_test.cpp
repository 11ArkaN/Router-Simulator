// RRset validation tests exercise canonical name folding, canonical record
// ordering, key selection, signature time windows and unsupported algorithms.
// A deterministic verifier inspects bytes but performs no production crypto.

#include "router/dnssec_validation.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

router::packet::dns::Name name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("DNSSEC validation fixture name is invalid");
  return *parsed;
}

class InspectingVerifier final : public router::dnssec::CryptoVerifier {
public:
  std::vector<std::uint8_t> expected_data;
  std::vector<std::uint8_t> expected_key;
  std::vector<std::uint8_t> expected_signature;
  bool enabled{true};

  bool supports(std::uint8_t algorithm) const noexcept override {
    return enabled && algorithm == 13U;
  }

  bool verify(std::uint8_t algorithm,
              std::span<const std::uint8_t> public_key,
              std::span<const std::uint8_t> signed_data,
              std::span<const std::uint8_t> signature) const noexcept override {
    return algorithm == 13U &&
           std::ranges::equal(public_key, expected_key) &&
           std::ranges::equal(signed_data, expected_data) &&
           std::ranges::equal(signature, expected_signature);
  }
};

} // namespace

void dnssec_validation_tests() {
  using namespace router;

  const dns::ZoneRecord high{.owner = name("WWW.Example.COM."),
                             .type = packet::dns::type_a,
                             .record_class = packet::dns::internet_class,
                             .ttl = 300U,
                             .rdata = {192U, 0U, 2U, 2U}};
  const dns::ZoneRecord low{.owner = name("www.example.com."),
                            .type = packet::dns::type_a,
                            .record_class = packet::dns::internet_class,
                            .ttl = 60U,
                            .rdata = {192U, 0U, 2U, 1U}};
  const std::array records{high, low};

  dnssec::Dnskey key{.flags = dnssec::dnskey_zone_flag,
                     .protocol = dnssec::dnskey_protocol,
                     .algorithm = 13U,
                     .public_key = {1U, 2U, 3U, 4U}};
  std::vector<std::uint8_t> key_wire;
  if (!dnssec::encode_dnskey(key, key_wire))
    throw std::runtime_error("DNSSEC validation key encoding failed");

  dnssec::Rrsig rrsig{.type_covered = packet::dns::type_a,
                       .algorithm = 13U,
                       .labels = 3U,
                       .original_ttl = 300U,
                       .signature_expiration = 2000U,
                       .signature_inception = 1000U,
                       .key_tag = dnssec::key_tag(key_wire),
                       .signer_name = name("EXAMPLE.com."),
                       .signature = {0xaaU, 0xbbU}};
  std::vector<std::uint8_t> signed_data;
  if (!dnssec::canonical_signed_data(rrsig, records, signed_data))
    throw std::runtime_error("DNSSEC canonical signed data failed");

  // RRSIG fixed fields and signer consume 31 octets. The first sorted RR must
  // contain the lower address even though it was second in repository order.
  constexpr std::size_t first_rdata_offset = 31U + 17U + 2U + 2U + 4U + 2U;
  if (signed_data.size() != 93U ||
      signed_data[first_rdata_offset + 3U] != 1U ||
      signed_data[31U + 1U] != 'w' || signed_data[31U + 5U] != 'e')
    throw std::runtime_error("DNSSEC canonical RR ordering or case failed");
  const std::array reversed{low, high};
  std::vector<std::uint8_t> reversed_data;
  if (!dnssec::canonical_signed_data(rrsig, reversed, reversed_data) ||
      reversed_data != signed_data)
    throw std::runtime_error("DNSSEC signed data depends on RR input order");

  std::vector<std::uint8_t> signature_wire;
  if (!dnssec::encode_rrsig(rrsig, signature_wire))
    throw std::runtime_error("DNSSEC validation signature encoding failed");
  const dns::ZoneRecord signature_record{
      .owner = name("www.example.com."),
      .type = packet::dns::type_rrsig,
      .record_class = packet::dns::internet_class,
      .ttl = 300U,
      .rdata = signature_wire};
  const dns::ZoneRecord key_record{.owner = name("example.com."),
                                   .type = packet::dns::type_dnskey,
                                   .record_class = packet::dns::internet_class,
                                   .ttl = 300U,
                                   .rdata = key_wire};
  InspectingVerifier verifier;
  verifier.expected_data = signed_data;
  verifier.expected_key = key.public_key;
  verifier.expected_signature = rrsig.signature;
  const std::array signature_records{signature_record};
  const std::array key_records{key_record};
  const auto valid = dnssec::validate_rrset(records, signature_records,
                                             key_records, 1500U, verifier);
  if (valid.state != dnssec::ValidationState::secure ||
      valid.key_tag != rrsig.key_tag)
    throw std::runtime_error("DNSSEC matching signature was not validated");

  const auto expired = dnssec::validate_rrset(records, signature_records,
                                               key_records, 2001U, verifier);
  if (expired.state != dnssec::ValidationState::bogus ||
      expired.failure != dnssec::ValidationFailure::signature_expired)
    throw std::runtime_error("DNSSEC expired signature was accepted");
  verifier.enabled = false;
  const auto unsupported = dnssec::validate_rrset(
      records, signature_records, key_records, 1500U, verifier);
  if (unsupported.state != dnssec::ValidationState::indeterminate ||
      unsupported.failure != dnssec::ValidationFailure::unsupported_algorithm)
    throw std::runtime_error("DNSSEC unsupported algorithm state is wrong");

  // RFC 6840 section 5.11 accepts an RRset if any signature validates, and
  // reports bogus when every locally supported candidate fails. Appending an
  // unsupported signature must not make that result depend on RRSIG order.
  verifier.enabled = true;
  auto bad_signature = rrsig;
  bad_signature.signature = {0U};
  std::vector<std::uint8_t> bad_signature_wire;
  if (!dnssec::encode_rrsig(bad_signature, bad_signature_wire))
    throw std::runtime_error("DNSSEC invalid-signature fixture did not encode");
  auto invalid_record = signature_record;
  invalid_record.rdata = bad_signature_wire;
  auto unknown_signature = rrsig;
  unknown_signature.algorithm = 253U;
  std::vector<std::uint8_t> unknown_signature_wire;
  if (!dnssec::encode_rrsig(unknown_signature, unknown_signature_wire))
    throw std::runtime_error("DNSSEC unknown-algorithm fixture did not encode");
  auto unknown_record = signature_record;
  unknown_record.rdata = unknown_signature_wire;
  const std::array invalid_then_unknown{invalid_record, unknown_record};
  const std::array unknown_then_invalid{unknown_record, invalid_record};
  for (const auto &ordered : {std::span{invalid_then_unknown},
                              std::span{unknown_then_invalid}}) {
    const auto result = dnssec::validate_rrset(records, ordered, key_records,
                                                1500U, verifier);
    if (result.state != dnssec::ValidationState::bogus ||
        result.failure != dnssec::ValidationFailure::invalid_signature)
      throw std::runtime_error("DNSSEC failure depends on RRSIG order");
  }

  auto mixed = records;
  mixed[1].type = packet::dns::type_aaaa;
  if (dnssec::canonical_signed_data(rrsig, mixed, reversed_data))
    throw std::runtime_error("DNSSEC accepted records from different RRsets");
}
