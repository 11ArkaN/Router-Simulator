// DNSSEC record tests use the RFC 4034 DNSKEY example for its published key
// tag and independently fixed SHA-256 DS digest. Remaining records exercise
// strict variable-length and canonical type-bitmap parsing.

#include "router/dnssec_record.hpp"
#include "router/generated_dnssec_policy.hpp"

#include <array>
#include <stdexcept>
#include <string_view>

namespace {

std::vector<std::uint8_t> base64(std::string_view text) {
  static constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<std::uint8_t> output;
  std::uint32_t accumulator{};
  unsigned bits{};
  for (const auto character : text) {
    if (character == '=')
      break;
    const auto value = alphabet.find(character);
    if (value == std::string_view::npos)
      throw std::runtime_error("DNSSEC fixture base64 is invalid");
    accumulator = (accumulator << 6U) | static_cast<std::uint32_t>(value);
    bits += 6U;
    if (bits >= 8U) {
      bits -= 8U;
      output.push_back(static_cast<std::uint8_t>(accumulator >> bits));
      accumulator &= (1U << bits) - 1U;
    }
  }
  return output;
}

router::packet::dns::Name name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("DNSSEC fixture name is invalid");
  return *parsed;
}

std::vector<std::uint8_t> hex(std::string_view text) {
  const auto digit = [](char value) -> std::uint8_t {
    if (value >= '0' && value <= '9')
      return static_cast<std::uint8_t>(value - '0');
    if (value >= 'A' && value <= 'F')
      return static_cast<std::uint8_t>(value - 'A' + 10);
    throw std::runtime_error("DNSSEC fixture hex is invalid");
  };
  std::vector<std::uint8_t> output;
  for (std::size_t index = 0U; index < text.size(); index += 2U)
    output.push_back(
        static_cast<std::uint8_t>((digit(text[index]) << 4U) |
                                  digit(text[index + 1U])));
  return output;
}

} // namespace

void dnssec_record_tests() {
  using namespace router;

  // Registry policy is generated independently from crypto support. These
  // checks prevent a stale generated table from silently permitting a
  // deprecated signer or dropping a mandatory validator algorithm.
  const auto rsa_sha256 = dnssec::policy::algorithm(8U);
  const auto rsa_sha1 = dnssec::policy::algorithm(5U);
  const auto sha256 = dnssec::policy::digest(2U);
  if (!rsa_sha256 || !rsa_sha1 || !sha256 ||
      rsa_sha256->implement_signing != dnssec::policy::Recommendation::must ||
      rsa_sha1->use_signing !=
          dnssec::policy::Recommendation::not_recommended ||
      sha256->implement_validation != dnssec::policy::Recommendation::must ||
      dnssec::policy::algorithm(4U))
    throw std::runtime_error("generated DNSSEC registry policy is stale");

  const auto public_key = base64(
      "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/"
      "2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvx"
      "egXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc"
      "nOf+EPbtG9DMBmADjFDc2w/rljwvFw==");
  std::vector<std::uint8_t> dnskey_wire;
  if (!dnssec::encode_dnskey(
          {.flags = dnssec::dnskey_zone_flag,
           .protocol = dnssec::dnskey_protocol,
           .algorithm = 5U,
           .public_key = public_key},
          dnskey_wire) ||
      dnssec::key_tag(dnskey_wire) != 60485U)
    throw std::runtime_error("RFC 4034 DNSKEY key tag does not match");
  const auto decoded_key = dnssec::decode_dnskey(dnskey_wire);
  if (!decoded_key || decoded_key->public_key != public_key ||
      decoded_key->flags != dnssec::dnskey_zone_flag)
    throw std::runtime_error("DNSKEY RDATA round trip failed");

  const auto ds = dnssec::make_ds_sha256(name("DSKEY.Example.COM."),
                                         dnskey_wire);
  const auto expected_digest =
      hex("D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A");
  std::vector<std::uint8_t> ds_wire;
  if (!ds || ds->key_tag != 60485U || ds->algorithm != 5U ||
      ds->digest != expected_digest || !dnssec::encode_ds(*ds, ds_wire) ||
      !dnssec::decode_ds(ds_wire) ||
      dnssec::make_ds_sha256(name("dskey.example.com."), dnskey_wire)
              ->digest != expected_digest)
    throw std::runtime_error("RFC 4509 SHA-256 DS derivation failed");

  dnssec::Rrsig signature{
      .type_covered = packet::dns::type_a,
      .algorithm = 13U,
      .labels = 3U,
      .original_ttl = 86400U,
      .signature_expiration = 0x70000000U,
      .signature_inception = 0x60000000U,
      .key_tag = 2642U,
      .signer_name = name("EXAMPLE.com."),
      .signature = {1U, 2U, 3U, 4U}};
  std::vector<std::uint8_t> rrsig_wire;
  const auto decoded_signature =
      dnssec::encode_rrsig(signature, rrsig_wire)
          ? dnssec::decode_rrsig(rrsig_wire)
          : std::nullopt;
  if (!decoded_signature || decoded_signature->signature != signature.signature ||
      !packet::dns::equal_case_insensitive(decoded_signature->signer_name,
                                           name("example.com.")))
    throw std::runtime_error("RRSIG RDATA round trip failed");

  // Input types may arrive in any order from zone storage. Encoding produces
  // increasing windows and rejects duplicates, while decode rejects a bitmap
  // whose last octet is zero instead of accepting a non-canonical signature
  // input with multiple encodings.
  dnssec::Nsec nsec{.next_domain = name("NEXT.example."),
                    .types = {1234U, packet::dns::type_nsec,
                              packet::dns::type_a, packet::dns::type_mx,
                              packet::dns::type_rrsig}};
  std::vector<std::uint8_t> nsec_wire;
  const auto decoded_nsec = dnssec::encode_nsec(nsec, nsec_wire)
                                ? dnssec::decode_nsec(nsec_wire)
                                : std::nullopt;
  if (!decoded_nsec ||
      !packet::dns::equal_case_insensitive(decoded_nsec->next_domain,
                                           name("next.example.")) ||
      decoded_nsec->next_domain.wire[1U] != 'N' ||
      decoded_nsec->types !=
          std::vector<std::uint16_t>({packet::dns::type_a,
                                      packet::dns::type_mx,
                                      packet::dns::type_rrsig,
                                      packet::dns::type_nsec, 1234U}))
    throw std::runtime_error("NSEC canonical type bitmap failed");
  auto malformed_nsec = nsec_wire;
  malformed_nsec.back() = 0U;
  if (dnssec::decode_nsec(malformed_nsec) ||
      dnssec::encode_nsec(
          {.next_domain = name("next.example."), .types = {1U, 1U}},
          malformed_nsec))
    throw std::runtime_error("NSEC accepted non-canonical type bitmap");

  dnssec::Nsec3 nsec3{.hash_algorithm = 1U,
                      .flags = 1U,
                      .iterations = 10U,
                      .salt = {0xaaU, 0xbbU},
                      .next_hashed_owner = {1U, 2U, 3U, 4U},
                      .types = {packet::dns::type_a,
                                packet::dns::type_rrsig}};
  std::vector<std::uint8_t> nsec3_wire;
  const auto decoded_nsec3 = dnssec::encode_nsec3(nsec3, nsec3_wire)
                                 ? dnssec::decode_nsec3(nsec3_wire)
                                 : std::nullopt;
  if (!decoded_nsec3 || decoded_nsec3->salt != nsec3.salt ||
      decoded_nsec3->next_hashed_owner != nsec3.next_hashed_owner ||
      decoded_nsec3->types != nsec3.types)
    throw std::runtime_error("NSEC3 RDATA round trip failed");

  // RFC 5155 empty non-terminals own no ordinary RRsets, so their NSEC3 Type
  // Bit Maps field is legitimately zero octets. NSEC still requires a bitmap.
  nsec3.types.clear();
  if (!dnssec::encode_nsec3(nsec3, nsec3_wire) ||
      !dnssec::decode_nsec3(nsec3_wire) ||
      !dnssec::decode_nsec3(nsec3_wire)->types.empty())
    throw std::runtime_error("NSEC3 rejected an empty non-terminal bitmap");

  std::vector<std::uint8_t> parameter_wire;
  const dnssec::Nsec3param parameters{.hash_algorithm = 1U,
                                     .flags = 0U,
                                     .iterations = 5U,
                                     .salt = {0xdeU, 0xadU}};
  if (!dnssec::encode_nsec3param(parameters, parameter_wire) ||
      !dnssec::decode_nsec3param(parameter_wire) ||
      dnssec::encode_nsec3param(
          {.hash_algorithm = 1U,
           .flags = 1U,
           .iterations = 0U,
           .salt = {}},
          parameter_wire))
    throw std::runtime_error("NSEC3PARAM flag or salt validation failed");
}
