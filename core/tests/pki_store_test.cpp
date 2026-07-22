// Local PKI integration tests use real OpenSSL-generated certificates, keys,
// signatures, CRLs and OCSP messages. Fixed wall-clock values make validity
// assertions deterministic without replacing the production CSPRNG.

#include "router/pki_store.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

struct TestPkeyDeleter {
  void operator()(EVP_PKEY *value) const noexcept { EVP_PKEY_free(value); }
};

struct TestX509Deleter {
  void operator()(X509 *value) const noexcept { X509_free(value); }
};

struct TestBioDeleter {
  void operator()(BIO *value) const noexcept {
    static_cast<void>(BIO_free(value));
  }
};

struct PemIdentity {
  std::vector<std::uint8_t> certificate;
  std::vector<std::uint8_t> private_key;
};

PemIdentity make_import_fixture(std::span<const std::uint8_t> password) {
  std::unique_ptr<EVP_PKEY, TestPkeyDeleter> key{
      EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256")};
  std::unique_ptr<X509, TestX509Deleter> certificate{X509_new()};
  if (!key || !certificate || X509_set_version(certificate.get(), 2L) != 1 ||
      ASN1_INTEGER_set_uint64(X509_get_serialNumber(certificate.get()), 9U) !=
          1 ||
      !ASN1_TIME_set(X509_getm_notBefore(certificate.get()), 1861920000U) ||
      !ASN1_TIME_set(X509_getm_notAfter(certificate.get()), 1924992000U) ||
      X509_NAME_add_entry_by_txt(
          X509_get_subject_name(certificate.get()), "CN", MBSTRING_ASC,
          reinterpret_cast<const unsigned char *>("imported.lab.example"),
          -1, -1, 0) != 1 ||
      X509_set_issuer_name(certificate.get(),
                           X509_get_subject_name(certificate.get())) != 1 ||
      X509_set_pubkey(certificate.get(), key.get()) != 1 ||
      X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0)
    throw std::runtime_error("PKI PEM fixture generation failed");

  std::unique_ptr<BIO, TestBioDeleter> certificate_bio{BIO_new(BIO_s_mem())};
  std::unique_ptr<BIO, TestBioDeleter> key_bio{BIO_new(BIO_s_mem())};
  if (!certificate_bio || !key_bio ||
      PEM_write_bio_X509(certificate_bio.get(), certificate.get()) != 1 ||
      PEM_write_bio_PrivateKey(
          key_bio.get(), key.get(), EVP_aes_256_cbc(),
          password.empty() ? nullptr
                           : const_cast<unsigned char *>(password.data()),
          static_cast<int>(password.size()), nullptr, nullptr) != 1)
    throw std::runtime_error("PKI PEM fixture serialization failed");
  char *certificate_data{};
  char *key_data{};
  const auto certificate_size =
      BIO_get_mem_data(certificate_bio.get(), &certificate_data);
  const auto key_size = BIO_get_mem_data(key_bio.get(), &key_data);
  if (certificate_size <= 0 || key_size <= 0)
    throw std::runtime_error("PKI PEM fixture is empty");
  return {{reinterpret_cast<std::uint8_t *>(certificate_data),
           reinterpret_cast<std::uint8_t *>(certificate_data) +
               certificate_size},
          {reinterpret_cast<std::uint8_t *>(key_data),
           reinterpret_cast<std::uint8_t *>(key_data) + key_size}};
}

} // namespace

void pki_store_tests() {
  using namespace router::pki;

  std::array<std::uint8_t, 32U> wrapping_key{};
  for (std::size_t index = 0U; index < wrapping_key.size(); ++index)
    wrapping_key[index] = static_cast<std::uint8_t>(index + 1U);
  const std::array<std::uint8_t, 11U> context{
      'p', 'r', 'o', 'j', 'e', 'c', 't', '-', 'p', 'k', 'i'};
  auto store = Store::create(wrapping_key, context);
  if (!store)
    throw std::runtime_error("PKI store rejected valid vault material");

  constexpr std::uint64_t year_2025 = 1735689600U;
  constexpr std::uint64_t year_2030 = 1893456000U;
  constexpr std::uint64_t year_2035 = 2051222400U;
  const auto [authority_result, authority_id] = store->create_authority(
      {.subject = {.common_name = "Router Simulator Test Root",
                   .organization = "Router Simulator",
                   .organizational_unit = {},
                   .country = {}},
       .key_algorithm = KeyAlgorithm::ecdsa_p256,
       .not_before = year_2025,
       .not_after = year_2035,
       .path_length = 0U});
  if (authority_result != MutationResult::applied || authority_id == 0U)
    throw std::runtime_error("PKI authority generation failed");

  const auto [identity_result, identity_id] = store->issue_identity(
      authority_id,
      {.subject = {.common_name = "dns1.lab.example",
                   .organization = "Router Simulator",
                   .organizational_unit = {},
                   .country = {}},
       .key_algorithm = KeyAlgorithm::ecdsa_p256,
       .usage = CertificateUsage::tls_server,
       .dns_names = {"dns1.lab.example"},
       .ipv4_addresses = {{{192U, 0U, 2U, 53U}}},
       .ipv6_addresses = {},
       .not_before = year_2025,
       .not_after = year_2035});
  const auto *identity = store->identity(identity_id);
  const auto *authority = store->authority(authority_id);
  if (identity_result != MutationResult::applied || !identity || !authority ||
      identity->certificate_chain_der.size() != 2U)
    throw std::runtime_error("PKI leaf issuance failed");

  const std::vector<std::vector<std::uint8_t>> anchors{
      authority->certificate_der};
  auto validation = Store::validate(
      {.leaf_der = identity->certificate_chain_der[0],
       .intermediate_der = {},
       .trust_anchor_der = anchors,
       .crl_der = {},
       .ocsp_response_der = {},
       .hostname = "dns1.lab.example",
       .ipv4_address = std::nullopt,
       .ipv6_address = std::nullopt,
       .usage = CertificateUsage::tls_server,
       .wall_clock_seconds = year_2030,
       .require_revocation_status = false});
  if (validation.status != ValidationStatus::valid)
    throw std::runtime_error("valid PKI path or SAN was rejected");
  validation = Store::validate(
      {.leaf_der = identity->certificate_chain_der[0],
       .intermediate_der = {},
       .trust_anchor_der = anchors,
       .crl_der = {},
       .ocsp_response_der = {},
       .hostname = {},
       .ipv4_address = std::array<std::uint8_t, 4U>{192U, 0U, 2U, 53U},
       .ipv6_address = std::nullopt,
       .usage = CertificateUsage::tls_server,
       .wall_clock_seconds = year_2030,
       .require_revocation_status = false});
  if (validation.status != ValidationStatus::valid)
    throw std::runtime_error("valid IPv4 subjectAltName was rejected");
  validation = Store::validate(
      {.leaf_der = identity->certificate_chain_der[0],
       .intermediate_der = {},
       .trust_anchor_der = anchors,
       .crl_der = {},
       .ocsp_response_der = {},
       .hostname = "other.lab.example",
       .ipv4_address = std::nullopt,
       .ipv6_address = std::nullopt,
       .usage = CertificateUsage::tls_server,
       .wall_clock_seconds = year_2030,
       .require_revocation_status = false});
  if (validation.status != ValidationStatus::hostname_mismatch)
    throw std::runtime_error("PKI hostname mismatch was accepted");

  const auto [dual_result, dual_id] = store->issue_identity(
      authority_id,
      {.subject = {.common_name = "mutual.lab.example",
                   .organization = "Router Simulator",
                   .organizational_unit = {},
                   .country = {}},
       .key_algorithm = KeyAlgorithm::ecdsa_p256,
       .usage = CertificateUsage::tls_server_and_client,
       .dns_names = {"mutual.lab.example"},
       .ipv4_addresses = {},
       .ipv6_addresses = {},
       .not_before = year_2025,
       .not_after = year_2035});
  const auto *dual = store->identity(dual_id);
  if (dual_result != MutationResult::applied || !dual)
    throw std::runtime_error("dual-purpose PKI leaf issuance failed");
  const auto validate_usage = [&](const IdentityRecord &record,
                                  CertificateUsage usage) {
    return Store::validate(
        {.leaf_der = record.certificate_chain_der[0],
         .intermediate_der = {},
         .trust_anchor_der = anchors,
         .crl_der = {},
         .ocsp_response_der = {},
         .hostname = usage == CertificateUsage::tls_client
                         ? std::string{}
                         : std::string{"mutual.lab.example"},
         .ipv4_address = std::nullopt,
         .ipv6_address = std::nullopt,
         .usage = usage,
         .wall_clock_seconds = year_2030,
         .require_revocation_status = false});
  };
  if (validate_usage(*dual, CertificateUsage::tls_server).status !=
          ValidationStatus::valid ||
      validate_usage(*dual, CertificateUsage::tls_client).status !=
          ValidationStatus::valid ||
      validate_usage(*dual, CertificateUsage::tls_server_and_client).status !=
          ValidationStatus::valid)
    throw std::runtime_error("dual-purpose certificate failed an allowed TLS role");
  // issue_identity may reallocate the store's record vector. Public pointers
  // are borrowed only until the next mutation, so reacquire the first record
  // before validating it again.
  const auto *server_only = store->identity(identity_id);
  if (!server_only)
    throw std::runtime_error("server-only identity disappeared after issuance");
  const auto server_only_client_status =
      validate_usage(*server_only, CertificateUsage::tls_client).status;
  if (server_only_client_status != ValidationStatus::invalid_usage)
    throw std::runtime_error(
        "server-only certificate client validation status=" +
        std::to_string(static_cast<unsigned>(server_only_client_status)));
  identity = server_only;

  const auto clean_crl = store->issue_crl(authority_id, year_2030,
                                           year_2030 + 86400U);
  if (!clean_crl)
    throw std::runtime_error("empty signed CRL generation failed");
  const std::vector<std::vector<std::uint8_t>> clean_crls{*clean_crl};
  validation = Store::validate(
      {.leaf_der = identity->certificate_chain_der[0],
       .intermediate_der = {},
       .trust_anchor_der = anchors,
       .crl_der = clean_crls,
       .ocsp_response_der = {},
       .hostname = "dns1.lab.example",
       .ipv4_address = std::nullopt,
       .ipv6_address = std::nullopt,
       .usage = CertificateUsage::tls_server,
       .wall_clock_seconds = year_2030,
       .require_revocation_status = true});
  if (validation.status != ValidationStatus::valid)
    throw std::runtime_error("current non-revoking CRL was rejected");

  if (store->revoke(authority_id, identity_id, year_2025 + 100U,
                    RevocationReason::key_compromise) !=
      MutationResult::applied)
    throw std::runtime_error("PKI revocation mutation failed");
  const auto revoked_crl = store->issue_crl(authority_id, year_2030,
                                             year_2030 + 86400U);
  const std::vector<std::vector<std::uint8_t>> revoked_crls{
      revoked_crl ? *revoked_crl : std::vector<std::uint8_t>{}};
  validation = Store::validate(
      {.leaf_der = identity->certificate_chain_der[0],
       .intermediate_der = {},
       .trust_anchor_der = anchors,
       .crl_der = revoked_crls,
       .ocsp_response_der = {},
       .hostname = "dns1.lab.example",
       .ipv4_address = std::nullopt,
       .ipv6_address = std::nullopt,
       .usage = CertificateUsage::tls_server,
       .wall_clock_seconds = year_2030,
       .require_revocation_status = true});
  if (validation.status != ValidationStatus::revoked)
    throw std::runtime_error("revoked certificate passed CRL validation");

  const auto ocsp_request = store->make_ocsp_request(identity_id);
  const auto wall_now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  const auto ocsp_response =
      ocsp_request
          ? store->answer_ocsp(authority_id, *ocsp_request, wall_now,
                               wall_now + 3600U)
          : std::nullopt;
  if (!ocsp_request || !ocsp_response)
    throw std::runtime_error("signed OCSP exchange generation failed");
  const auto validation_now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  validation = Store::validate(
      {.leaf_der = identity->certificate_chain_der[0],
       .intermediate_der = {},
       .trust_anchor_der = anchors,
       .crl_der = {},
       .ocsp_response_der = *ocsp_response,
       .hostname = "dns1.lab.example",
       .ipv4_address = std::nullopt,
       .ipv6_address = std::nullopt,
       .usage = CertificateUsage::tls_server,
       .wall_clock_seconds = validation_now,
       .require_revocation_status = true});
  if (validation.status != ValidationStatus::revoked)
    throw std::runtime_error("revoked certificate passed OCSP validation");

  const std::array<std::uint8_t, 8U> import_password{
      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
  const auto imported_pem = make_import_fixture(import_password);
  const auto [import_result, import_id] = store->import_identity(
      imported_pem.certificate, imported_pem.private_key, import_password);
  const auto *imported = store->identity(import_id);
  if (import_result != MutationResult::applied || !imported ||
      imported->issuer != 0U || imported->sealed_private_key.empty())
    throw std::runtime_error("encrypted PEM identity import failed");
  auto wrong_password = import_password;
  wrong_password[0] ^= 1U;
  if (store->import_identity(imported_pem.certificate,
                             imported_pem.private_key, wrong_password)
          .first != MutationResult::cryptographic_failure)
    throw std::runtime_error("incorrect PEM key password was accepted");

  const auto checkpoint = store->checkpoint();
  auto restored = Store::restore(checkpoint, wrapping_key, context);
  if (!restored || !restored->identity(identity_id) ||
      restored->authority(authority_id)->revocations.size() != 1U)
    throw std::runtime_error("encrypted PKI checkpoint did not restore");
  auto tampered = checkpoint;
  tampered.identities[0].certificate_chain_der[0][0] ^= 0x01U;
  if (Store::restore(tampered, wrapping_key, context))
    throw std::runtime_error("tampered PKI checkpoint was accepted");
}
