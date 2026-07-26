// Zone signer tests prove that generated DNSKEY flags match the operational
// role and that the emitted RRSIG validates using only published DNS records.

#include "router/dnssec_openssl.hpp"
#include "router/dnssec_validation.hpp"
#include "router/dnssec_zone_signer.hpp"

#include <array>
#include <stdexcept>

namespace {

router::packet::dns::Name signer_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("zone signer fixture name is malformed");
  return *parsed;
}

} // namespace

void dnssec_zone_signer_tests() {
  using namespace router;

  const auto key = dnssec::generate_signing_key(15U);
  if (!key)
    throw std::runtime_error("zone signer key generation failed");
  const auto zsk = dnssec::make_dnskey_record(
      signer_name("example."), 3600U, *key, dnssec::KeyRole::zone_signing);
  const auto ksk = dnssec::make_dnskey_record(
      signer_name("example."), 3600U, *key, dnssec::KeyRole::key_signing);
  if (!zsk || !ksk)
    throw std::runtime_error("zone signer DNSKEY construction failed");
  const auto decoded_zsk = dnssec::decode_dnskey(zsk->rdata);
  const auto decoded_ksk = dnssec::decode_dnskey(ksk->rdata);
  if (!decoded_zsk || !decoded_ksk ||
      (decoded_zsk->flags & dnssec::dnskey_secure_entry_point_flag) != 0U ||
      (decoded_ksk->flags & dnssec::dnskey_secure_entry_point_flag) == 0U)
    throw std::runtime_error("zone signer KSK/ZSK DNSKEY flags are wrong");

  const std::array rrset{dns::ZoneRecord{
      .owner = signer_name("www.example."),
      .type = packet::dns::type_aaaa,
      .record_class = packet::dns::internet_class,
      .ttl = 300U,
      .rdata = {0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
                0U,    0U,    0U,    0U,    0U, 0U, 0U, 1U}}};
  const auto signature =
      dnssec::sign_rrset(rrset, *zsk, *key, 1000U, 2000U);
  if (!signature)
    throw std::runtime_error("zone signer RRSIG generation failed");
  const std::array signatures{*signature};
  const std::array keys{*zsk};
  dnssec::OpenSslCryptoVerifier verifier;
  const auto result =
      dnssec::validate_rrset(rrset, signatures, keys, 1500U, verifier);
  if (result.state != dnssec::ValidationState::secure)
    throw std::runtime_error("zone signer emitted an unverifiable RRSIG");

  auto wildcard_rrset = rrset;
  wildcard_rrset[0].owner = signer_name("*.example.");
  const auto wildcard_signature =
      dnssec::sign_rrset(wildcard_rrset, *zsk, *key, 1000U, 2000U);
  const auto decoded_wildcard = wildcard_signature
                                    ? dnssec::decode_rrsig(
                                          wildcard_signature->rdata)
                                    : std::nullopt;
  if (!decoded_wildcard || decoded_wildcard->labels != 1U)
    throw std::runtime_error("zone signer wildcard Labels field is wrong");
}
