// Chain tests keep cryptography deterministic so failures identify trust and
// delegation logic rather than OpenSSL. Independent RFC vectors test the real
// provider in dnssec_openssl_test.cpp.

#include "router/dnssec_chain.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

router::packet::dns::Name name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("DNSSEC chain fixture name is malformed");
  return *parsed;
}

class AcceptingCrypto final : public router::dnssec::CryptoVerifier {
public:
  bool supports(std::uint8_t algorithm) const noexcept override {
    return algorithm == 13U;
  }
  bool verify(std::uint8_t algorithm,
              std::span<const std::uint8_t> public_key,
              std::span<const std::uint8_t> signed_data,
              std::span<const std::uint8_t> signature) const noexcept override {
    return algorithm == 13U && !public_key.empty() && !signed_data.empty() &&
           std::ranges::equal(signature, expected_signature);
  }

private:
  static constexpr std::array<std::uint8_t, 2> expected_signature{0xaaU,
                                                                  0x55U};
};

class DeterministicDigests final : public router::dnssec::DigestCalculator {
public:
  bool supports_digest(std::uint8_t digest_type) const noexcept override {
    return digest_type == 2U;
  }
  bool calculate_digest(std::uint8_t digest_type,
                        std::span<const std::uint8_t> input,
                        std::vector<std::uint8_t> &output) const noexcept override {
    if (digest_type != 2U || input.empty())
      return false;
    try {
      output = {0xd5U, static_cast<std::uint8_t>(input.size() & 0xffU)};
      return true;
    } catch (...) {
      return false;
    }
  }
};

} // namespace

void dnssec_chain_tests() {
  using namespace router;

  dnssec::Dnskey key{.flags = static_cast<std::uint16_t>(
                         dnssec::dnskey_zone_flag |
                         dnssec::dnskey_secure_entry_point_flag),
                     .protocol = dnssec::dnskey_protocol,
                     .algorithm = 13U,
                     .public_key = {1U, 2U, 3U, 4U}};
  std::vector<std::uint8_t> key_wire;
  if (!dnssec::encode_dnskey(key, key_wire))
    throw std::runtime_error("DNSSEC chain DNSKEY encoding failed");
  const auto owner = name("Child.Example.");
  const dns::ZoneRecord key_record{.owner = owner,
                                   .type = packet::dns::type_dnskey,
                                   .record_class = packet::dns::internet_class,
                                   .ttl = 3600U,
                                   .rdata = key_wire};
  const std::array key_records{key_record};

  dnssec::Rrsig signature{.type_covered = packet::dns::type_dnskey,
                           .algorithm = 13U,
                           .labels = 2U,
                           .original_ttl = 3600U,
                           .signature_expiration = 2000U,
                           .signature_inception = 1000U,
                           .key_tag = dnssec::key_tag(key_wire),
                           .signer_name = name("child.example."),
                           .signature = {0xaaU, 0x55U}};
  std::vector<std::uint8_t> signature_wire;
  if (!dnssec::encode_rrsig(signature, signature_wire))
    throw std::runtime_error("DNSSEC chain RRSIG encoding failed");
  const dns::ZoneRecord signature_record{
      .owner = owner,
      .type = packet::dns::type_rrsig,
      .record_class = packet::dns::internet_class,
      .ttl = 3600U,
      .rdata = signature_wire};
  const std::array signature_records{signature_record};
  AcceptingCrypto crypto;
  DeterministicDigests digests;

  dnssec::TrustAnchorStore anchors;
  if (anchors.add(key_record) != dnssec::AnchorMutation::applied ||
      anchors.add(key_record) != dnssec::AnchorMutation::duplicate)
    throw std::runtime_error("DNSSEC trust-anchor mutation result is wrong");
  const auto anchored = dnssec::validate_from_trust_anchor(
      key_records, signature_records, anchors, 1500U, crypto);
  if (anchored.state != dnssec::ChainState::secure ||
      anchored.key_tag != signature.key_tag)
    throw std::runtime_error("DNSSEC trust anchor did not authenticate DNSKEY");

  // Digest input is canonical owner wire plus complete DNSKEY RDATA. The
  // deterministic calculator publishes its input length as the second octet.
  constexpr std::uint8_t digest_input_length = 15U + 8U;
  dnssec::Ds ds{.key_tag = signature.key_tag,
                .algorithm = 13U,
                .digest_type = 2U,
                .digest = {0xd5U, digest_input_length}};
  std::vector<std::uint8_t> ds_wire;
  if (!dnssec::encode_ds(ds, ds_wire))
    throw std::runtime_error("DNSSEC chain DS encoding failed");
  const dns::ZoneRecord ds_record{.owner = name("child.example."),
                                  .type = packet::dns::type_ds,
                                  .record_class = packet::dns::internet_class,
                                  .ttl = 3600U,
                                  .rdata = ds_wire};
  const std::array ds_records{ds_record};
  const auto delegated = dnssec::validate_dnskey_delegation(
      key_records, signature_records, ds_records, 1500U, crypto, digests);
  if (delegated.state != dnssec::ChainState::secure)
    throw std::runtime_error("DNSSEC DS did not authenticate child DNSKEY");

  auto wrong_ds = ds_record;
  wrong_ds.rdata.back() ^= 1U;
  const auto mismatch = dnssec::validate_dnskey_delegation(
      key_records, signature_records, std::span{&wrong_ds, 1U}, 1500U, crypto,
      digests);
  if (mismatch.state != dnssec::ChainState::bogus ||
      mismatch.failure != dnssec::ChainFailure::ds_mismatch)
    throw std::runtime_error("DNSSEC mismatched DS was not bogus");

  auto unsupported_ds = ds_record;
  unsupported_ds.rdata[3] = 99U;
  const auto unsupported = dnssec::validate_dnskey_delegation(
      key_records, signature_records, std::span{&unsupported_ds, 1U}, 1500U,
      crypto, digests);
  if (unsupported.state != dnssec::ChainState::insecure ||
      unsupported.failure != dnssec::ChainFailure::unsupported_digest)
    throw std::runtime_error("DNSSEC unsupported DS digest state is wrong");

  auto unsupported_algorithm_ds = ds_record;
  unsupported_algorithm_ds.rdata[2] = 253U;
  const auto unsupported_algorithm = dnssec::validate_dnskey_delegation(
      key_records, signature_records,
      std::span{&unsupported_algorithm_ds, 1U}, 1500U, crypto, digests);
  if (unsupported_algorithm.state != dnssec::ChainState::insecure)
    throw std::runtime_error("DNSSEC unsupported DS algorithm was not insecure");

  const auto absent = dnssec::validate_dnskey_delegation(
      key_records, signature_records, {}, 1500U, crypto, digests);
  if (absent.state != dnssec::ChainState::indeterminate ||
      dnssec::classify_unsigned_delegation(false).state !=
          dnssec::ChainState::indeterminate ||
      dnssec::classify_unsigned_delegation(true).state !=
          dnssec::ChainState::insecure)
    throw std::runtime_error("DNSSEC unsigned delegation was inferred unsafely");

  if (anchors.remove(key_record) != dnssec::AnchorMutation::applied ||
      anchors.remove(key_record) != dnssec::AnchorMutation::not_found)
    throw std::runtime_error("DNSSEC trust-anchor removal result is wrong");
}
