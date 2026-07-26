// OpenSSL 3.5 PKIX implementation for the local project store. All provider
// objects are automatic owners scoped to one operation. Private-key DER is
// held only in cleansing buffers while AES-256-GCM seals or opens a record.
// Source: ietf.pki.path_validation.rfc5280
// Source: ietf.pki.ocsp.rfc6960
// Source: nist.project_key_vault.aes_gcm

#include "router/pki_store.hpp"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>

namespace router::pki {
namespace {

template <typename T, void (*Free)(T *)> struct OpenSslDeleter {
  void operator()(T *value) const noexcept {
    if (value)
      Free(value);
  }
};

struct BioDeleter {
  void operator()(BIO *value) const noexcept {
    if (value)
      static_cast<void>(BIO_free(value));
  }
};

struct OwnedCertificateStackDeleter {
  void operator()(STACK_OF(X509) *value) const noexcept {
    if (value)
      sk_X509_pop_free(value, X509_free);
  }
};

using PkeyOwner =
    std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using CipherOwner = std::unique_ptr<EVP_CIPHER_CTX,
                                    OpenSslDeleter<EVP_CIPHER_CTX,
                                                   EVP_CIPHER_CTX_free>>;
using X509Owner = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using CrlOwner =
    std::unique_ptr<X509_CRL, OpenSslDeleter<X509_CRL, X509_CRL_free>>;
using StoreOwner =
    std::unique_ptr<X509_STORE, OpenSslDeleter<X509_STORE, X509_STORE_free>>;
using StoreContextOwner =
    std::unique_ptr<X509_STORE_CTX,
                    OpenSslDeleter<X509_STORE_CTX, X509_STORE_CTX_free>>;
using VerifyParametersOwner =
    std::unique_ptr<X509_VERIFY_PARAM,
                    OpenSslDeleter<X509_VERIFY_PARAM, X509_VERIFY_PARAM_free>>;
using OcspRequestOwner =
    std::unique_ptr<OCSP_REQUEST,
                    OpenSslDeleter<OCSP_REQUEST, OCSP_REQUEST_free>>;
using OcspResponseOwner =
    std::unique_ptr<OCSP_RESPONSE,
                    OpenSslDeleter<OCSP_RESPONSE, OCSP_RESPONSE_free>>;
using OcspBasicOwner =
    std::unique_ptr<OCSP_BASICRESP,
                    OpenSslDeleter<OCSP_BASICRESP, OCSP_BASICRESP_free>>;
using BnOwner = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using IntegerOwner =
    std::unique_ptr<ASN1_INTEGER,
                    OpenSslDeleter<ASN1_INTEGER, ASN1_INTEGER_free>>;
using TimeOwner =
    std::unique_ptr<ASN1_TIME, OpenSslDeleter<ASN1_TIME, ASN1_TIME_free>>;
using BioOwner = std::unique_ptr<BIO, BioDeleter>;
using OwnedCertificateStack =
    std::unique_ptr<STACK_OF(X509), OwnedCertificateStackDeleter>;

constexpr std::array<std::uint8_t, 4U> sealed_magic{'R', 'P', 'K', '1'};
constexpr std::size_t nonce_octets = 12U;
constexpr std::size_t tag_octets = 16U;
constexpr std::size_t sealed_header_octets =
    sealed_magic.size() + nonce_octets + 4U;

struct SensitiveBytes {
  std::vector<std::uint8_t> bytes;
  ~SensitiveBytes() {
    // OPENSSL_cleanse is a provider-supported erasure barrier and cannot be
    // removed as an apparently dead store by the optimizer.
    if (!bytes.empty())
      OPENSSL_cleanse(bytes.data(), bytes.size());
  }
};

bool valid_time(std::uint64_t value) noexcept {
  return value != 0U &&
         value <= static_cast<std::uint64_t>(
                      std::numeric_limits<std::time_t>::max());
}

TimeOwner make_time(std::uint64_t value) noexcept {
  if (!valid_time(value))
    return {};
  TimeOwner result{ASN1_TIME_new()};
  const auto converted = static_cast<std::time_t>(value);
  return result && ASN1_TIME_set(result.get(), converted) ? std::move(result)
                                                          : TimeOwner{};
}

void write_u32(std::span<std::uint8_t> output, std::size_t offset,
               std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint32_t read_u32(std::span<const std::uint8_t> input,
                       std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(input[offset]) << 24U) |
         (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
         input[offset + 3U];
}

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    output.push_back(static_cast<std::uint8_t>(value >> shift));
}

std::vector<std::uint8_t>
key_binding(std::span<const std::uint8_t> context, ObjectId id,
            std::span<const std::uint8_t> certificate_der) {
  std::vector<std::uint8_t> binding{context.begin(), context.end()};
  binding.reserve(binding.size() + 8U + 32U);
  append_u64(binding, id);
  std::array<std::uint8_t, 32U> digest{};
  unsigned int digest_size{};
  if (EVP_Digest(certificate_der.data(), certificate_der.size(),
                 digest.data(), &digest_size, EVP_sha256(), nullptr) != 1 ||
      digest_size != digest.size())
    return {};
  binding.insert(binding.end(), digest.begin(), digest.end());
  return binding;
}

bool add_aad(EVP_CIPHER_CTX *cipher,
             std::span<const std::uint8_t> header,
             std::span<const std::uint8_t> binding, bool encrypt) noexcept {
  if (header.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      binding.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;
  int written{};
  const auto update = encrypt ? EVP_EncryptUpdate : EVP_DecryptUpdate;
  return update(cipher, nullptr, &written, header.data(),
                static_cast<int>(header.size())) == 1 &&
         (binding.empty() ||
          update(cipher, nullptr, &written, binding.data(),
                 static_cast<int>(binding.size())) == 1);
}

bool encode_private_key(EVP_PKEY *key, SensitiveBytes &result) {
  const auto length = i2d_PrivateKey(key, nullptr);
  if (length <= 0)
    return false;
  result.bytes.resize(static_cast<std::size_t>(length));
  auto *cursor = result.bytes.data();
  return i2d_PrivateKey(key, &cursor) == length &&
         cursor == result.bytes.data() + result.bytes.size();
}

bool seal_private_key(EVP_PKEY *key,
                      std::span<const std::uint8_t> wrapping_key,
                      std::span<const std::uint8_t> binding,
                      std::vector<std::uint8_t> &output) {
  if (!key || wrapping_key.size() != 32U)
    return false;
  SensitiveBytes plaintext;
  if (!encode_private_key(key, plaintext) ||
      plaintext.bytes.size() > std::numeric_limits<std::uint32_t>::max() ||
      plaintext.bytes.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;
  std::array<std::uint8_t, nonce_octets> nonce{};
  if (RAND_priv_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
    return false;
  std::vector<std::uint8_t> staged(sealed_header_octets +
                                   plaintext.bytes.size() + tag_octets);
  std::copy(sealed_magic.begin(), sealed_magic.end(), staged.begin());
  std::copy(nonce.begin(), nonce.end(), staged.begin() + sealed_magic.size());
  write_u32(staged, sealed_header_octets - 4U,
            static_cast<std::uint32_t>(plaintext.bytes.size()));
  CipherOwner cipher{EVP_CIPHER_CTX_new()};
  if (!cipher ||
      EVP_EncryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(cipher.get(), nullptr, nullptr, wrapping_key.data(),
                         nonce.data()) != 1 ||
      !add_aad(cipher.get(),
               std::span<const std::uint8_t>{staged}.first(
                   sealed_header_octets),
               binding, true))
    return false;
  int written{};
  int final_written{};
  auto *ciphertext = staged.data() + sealed_header_octets;
  if (EVP_EncryptUpdate(cipher.get(), ciphertext, &written,
                        plaintext.bytes.data(),
                        static_cast<int>(plaintext.bytes.size())) != 1 ||
      EVP_EncryptFinal_ex(cipher.get(), ciphertext + written,
                          &final_written) != 1 ||
      static_cast<std::size_t>(written + final_written) !=
          plaintext.bytes.size() ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(tag_octets),
                          staged.data() + sealed_header_octets +
                              plaintext.bytes.size()) != 1)
    return false;
  output = std::move(staged);
  return true;
}

PkeyOwner open_private_key(std::span<const std::uint8_t> sealed,
                           std::span<const std::uint8_t> wrapping_key,
                           std::span<const std::uint8_t> binding) {
  if (wrapping_key.size() != 32U ||
      sealed.size() < sealed_header_octets + tag_octets ||
      !std::ranges::equal(sealed.first(sealed_magic.size()), sealed_magic))
    return {};
  const auto ciphertext_size = read_u32(sealed, sealed_header_octets - 4U);
  if (ciphertext_size == 0U ||
      ciphertext_size >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      sealed.size() != sealed_header_octets + ciphertext_size + tag_octets)
    return {};
  const auto nonce = sealed.subspan(sealed_magic.size(), nonce_octets);
  const auto ciphertext =
      sealed.subspan(sealed_header_octets, ciphertext_size);
  const auto tag = sealed.last(tag_octets);
  SensitiveBytes plaintext{.bytes =
                               std::vector<std::uint8_t>(ciphertext_size)};
  CipherOwner cipher{EVP_CIPHER_CTX_new()};
  if (!cipher ||
      EVP_DecryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_DecryptInit_ex(cipher.get(), nullptr, nullptr, wrapping_key.data(),
                         nonce.data()) != 1 ||
      !add_aad(cipher.get(), sealed.first(sealed_header_octets), binding,
               false))
    return {};
  int written{};
  int final_written{};
  if (EVP_DecryptUpdate(cipher.get(), plaintext.bytes.data(), &written,
                        ciphertext.data(),
                        static_cast<int>(ciphertext.size())) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG,
                          static_cast<int>(tag.size()),
                          const_cast<std::uint8_t *>(tag.data())) != 1 ||
      EVP_DecryptFinal_ex(cipher.get(), plaintext.bytes.data() + written,
                          &final_written) != 1 ||
      static_cast<std::size_t>(written + final_written) !=
          plaintext.bytes.size())
    return {};
  const auto *cursor = plaintext.bytes.data();
  PkeyOwner key{d2i_AutoPrivateKey(
      nullptr, &cursor, static_cast<long>(plaintext.bytes.size()))};
  return key && cursor == plaintext.bytes.data() + plaintext.bytes.size()
             ? std::move(key)
             : PkeyOwner{};
}

PkeyOwner generate_key(KeyAlgorithm algorithm) noexcept {
  switch (algorithm) {
  case KeyAlgorithm::ecdsa_p256:
    return PkeyOwner{
        EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256")};
  case KeyAlgorithm::rsa_3072: {
    std::unique_ptr<EVP_PKEY_CTX,
                    OpenSslDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>
        context{EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)};
    EVP_PKEY *raw{};
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 3072) != 1 ||
        EVP_PKEY_generate(context.get(), &raw) != 1)
      return {};
    return PkeyOwner{raw};
  }
  case KeyAlgorithm::ed25519:
    return PkeyOwner{EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")};
  }
  return {};
}

X509Owner decode_certificate(std::span<const std::uint8_t> der) noexcept {
  if (der.empty() ||
      der.size() > static_cast<std::size_t>(std::numeric_limits<long>::max()))
    return {};
  const auto *cursor = der.data();
  X509Owner certificate{
      d2i_X509(nullptr, &cursor, static_cast<long>(der.size()))};
  return certificate && cursor == der.data() + der.size()
             ? std::move(certificate)
             : X509Owner{};
}

std::optional<std::vector<std::uint8_t>>
encode_certificate(X509 *certificate) {
  const auto length = i2d_X509(certificate, nullptr);
  if (length <= 0)
    return std::nullopt;
  std::vector<std::uint8_t> output(static_cast<std::size_t>(length));
  auto *cursor = output.data();
  if (i2d_X509(certificate, &cursor) != length)
    return std::nullopt;
  return output;
}

template <typename T, int (*Encode)(const T *, unsigned char **)>
std::optional<std::vector<std::uint8_t>> encode_der(const T *value) {
  const auto length = Encode(value, nullptr);
  if (length <= 0)
    return std::nullopt;
  std::vector<std::uint8_t> output(static_cast<std::size_t>(length));
  auto *cursor = output.data();
  return Encode(value, &cursor) == length
             ? std::optional<std::vector<std::uint8_t>>{std::move(output)}
             : std::nullopt;
}

bool append_name_entry(X509_NAME *name, const char *field,
                       const std::string &value) {
  if (value.empty())
    return true;
  return value.size() <=
             static_cast<std::size_t>(std::numeric_limits<int>::max()) &&
         X509_NAME_add_entry_by_txt(
             name, field, MBSTRING_UTF8,
             reinterpret_cast<const unsigned char *>(value.data()),
             static_cast<int>(value.size()), -1, 0) == 1;
}

bool set_subject(X509 *certificate, const DistinguishedName &subject) {
  if (subject.common_name.empty() ||
      (!subject.country.empty() && subject.country.size() != 2U))
    return false;
  auto *name = X509_get_subject_name(certificate);
  return name && append_name_entry(name, "C", subject.country) &&
         append_name_entry(name, "O", subject.organization) &&
         append_name_entry(name, "OU", subject.organizational_unit) &&
         append_name_entry(name, "CN", subject.common_name);
}

bool add_text_extension(X509 *certificate, X509 *issuer, int nid,
                        const std::string &text) {
  X509V3_CTX context{};
  X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
  std::unique_ptr<X509_EXTENSION,
                  OpenSslDeleter<X509_EXTENSION, X509_EXTENSION_free>>
      extension{X509V3_EXT_conf_nid(
          nullptr, &context, nid, const_cast<char *>(text.c_str()))};
  return extension && X509_add_ext(certificate, extension.get(), -1) == 1;
}

bool set_serial(X509 *certificate, std::uint64_t serial) noexcept {
  auto *value = X509_get_serialNumber(certificate);
  return value && serial != 0U && ASN1_INTEGER_set_uint64(value, serial) == 1;
}

std::vector<std::uint8_t> serial_bytes(const ASN1_INTEGER *serial) {
  BnOwner value{ASN1_INTEGER_to_BN(serial, nullptr)};
  if (!value || BN_is_negative(value.get()) != 0)
    return {};
  const auto octets = BN_num_bytes(value.get());
  std::vector<std::uint8_t> result(
      static_cast<std::size_t>(std::max(octets, 1)));
  if (octets == 0)
    result.front() = 0U;
  else if (BN_bn2bin(value.get(), result.data()) != octets)
    return {};
  return result;
}

IntegerOwner integer_from_bytes(std::span<const std::uint8_t> serial) {
  if (serial.empty() ||
      serial.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return {};
  BnOwner value{BN_bin2bn(serial.data(), static_cast<int>(serial.size()),
                          nullptr)};
  return value ? IntegerOwner{BN_to_ASN1_INTEGER(value.get(), nullptr)}
               : IntegerOwner{};
}

bool set_validity(X509 *certificate, std::uint64_t not_before,
                  std::uint64_t not_after) noexcept {
  if (!valid_time(not_before) || !valid_time(not_after) ||
      not_after <= not_before)
    return false;
  const auto begin = static_cast<std::time_t>(not_before);
  const auto end = static_cast<std::time_t>(not_after);
  return ASN1_TIME_set(X509_getm_notBefore(certificate), begin) &&
         ASN1_TIME_set(X509_getm_notAfter(certificate), end);
}

bool validity_within(X509 *issuer, std::uint64_t not_before,
                     std::uint64_t not_after) noexcept {
  auto begin = make_time(not_before);
  auto end = make_time(not_after);
  return begin && end &&
         ASN1_TIME_compare(begin.get(), X509_get0_notBefore(issuer)) >= 0 &&
         ASN1_TIME_compare(end.get(), X509_get0_notAfter(issuer)) <= 0;
}

bool add_subject_alt_names(X509 *certificate,
                           const IdentityProfile &profile) {
  if (profile.dns_names.empty() && profile.ipv4_addresses.empty() &&
      profile.ipv6_addresses.empty())
    return true;
  auto *names = sk_GENERAL_NAME_new_null();
  if (!names)
    return false;
  const auto cleanup = [&] { sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free); };
  const auto add_dns = [&](const std::string &value) {
    if (value.empty() || value.find('\0') != std::string::npos)
      return false;
    auto *name = GENERAL_NAME_new();
    auto *string = ASN1_IA5STRING_new();
    if (!name || !string ||
        value.size() >
            static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        ASN1_STRING_set(string, value.data(), static_cast<int>(value.size())) !=
            1) {
      GENERAL_NAME_free(name);
      ASN1_IA5STRING_free(string);
      return false;
    }
    GENERAL_NAME_set0_value(name, GEN_DNS, string);
    if (!sk_GENERAL_NAME_push(names, name)) {
      GENERAL_NAME_free(name);
      return false;
    }
    return true;
  };
  const auto add_ip = [&](std::span<const std::uint8_t> address) {
    auto *name = GENERAL_NAME_new();
    auto *octets = ASN1_OCTET_STRING_new();
    if (!name || !octets ||
        ASN1_OCTET_STRING_set(octets, address.data(),
                              static_cast<int>(address.size())) != 1) {
      GENERAL_NAME_free(name);
      ASN1_OCTET_STRING_free(octets);
      return false;
    }
    GENERAL_NAME_set0_value(name, GEN_IPADD, octets);
    if (!sk_GENERAL_NAME_push(names, name)) {
      GENERAL_NAME_free(name);
      return false;
    }
    return true;
  };
  for (const auto &name : profile.dns_names)
    if (!add_dns(name)) {
      cleanup();
      return false;
    }
  for (const auto &address : profile.ipv4_addresses)
    if (!add_ip(address)) {
      cleanup();
      return false;
    }
  for (const auto &address : profile.ipv6_addresses)
    if (!add_ip(address)) {
      cleanup();
      return false;
    }
  const auto added = X509_add1_ext_i2d(certificate, NID_subject_alt_name,
                                       names, 0, X509V3_ADD_DEFAULT) == 1;
  cleanup();
  return added;
}

bool add_identity_extensions(X509 *certificate, X509 *issuer,
                             const IdentityProfile &profile) {
  std::string eku;
  switch (profile.usage) {
  case CertificateUsage::tls_server:
    eku = "serverAuth";
    break;
  case CertificateUsage::tls_client:
    eku = "clientAuth";
    break;
  case CertificateUsage::tls_server_and_client:
    eku = "serverAuth,clientAuth";
    break;
  }
  return add_text_extension(certificate, issuer, NID_basic_constraints,
                            "critical,CA:FALSE") &&
         add_text_extension(certificate, issuer, NID_key_usage,
                            "critical,digitalSignature") &&
         add_text_extension(certificate, issuer, NID_ext_key_usage, eku) &&
         add_text_extension(certificate, issuer, NID_subject_key_identifier,
                            "hash") &&
         add_text_extension(certificate, issuer, NID_authority_key_identifier,
                            "keyid:always") &&
         add_subject_alt_names(certificate, profile);
}

bool add_authority_extensions(X509 *certificate,
                              std::optional<std::uint32_t> path_length) {
  auto constraints = std::string{"critical,CA:TRUE"};
  if (path_length)
    constraints += ",pathlen:" + std::to_string(*path_length);
  return add_text_extension(certificate, certificate, NID_basic_constraints,
                            constraints) &&
         add_text_extension(certificate, certificate, NID_key_usage,
                            "critical,keyCertSign,cRLSign") &&
         add_text_extension(certificate, certificate,
                            NID_subject_key_identifier, "hash") &&
         add_text_extension(certificate, certificate,
                            NID_authority_key_identifier, "keyid:always");
}

const EVP_MD *signing_digest(EVP_PKEY *key) noexcept {
  // Ed25519 performs its own pure signature operation and OpenSSL requires a
  // null digest. RSA and ECDSA certificates use SHA-256.
  return EVP_PKEY_is_a(key, "ED25519") == 1 ? nullptr : EVP_sha256();
}

bool sign_certificate(X509 *certificate, EVP_PKEY *key) noexcept {
  return X509_sign(certificate, key, signing_digest(key)) > 0;
}

bool has_key_entropy(std::span<const std::uint8_t> key) noexcept {
  return key.size() == 32U &&
         std::ranges::any_of(key, [](auto byte) { return byte != 0U; });
}

ValidationStatus map_verify_error(int error) noexcept {
  switch (error) {
  case X509_V_OK:
    return ValidationStatus::valid;
  case X509_V_ERR_CERT_NOT_YET_VALID:
  case X509_V_ERR_CRL_NOT_YET_VALID:
    return ValidationStatus::not_yet_valid;
  case X509_V_ERR_CERT_HAS_EXPIRED:
  case X509_V_ERR_CRL_HAS_EXPIRED:
    return ValidationStatus::expired;
  case X509_V_ERR_HOSTNAME_MISMATCH:
  case X509_V_ERR_IP_ADDRESS_MISMATCH:
    return ValidationStatus::hostname_mismatch;
  case X509_V_ERR_INVALID_PURPOSE:
    return ValidationStatus::invalid_usage;
  case X509_V_ERR_CERT_REVOKED:
    return ValidationStatus::revoked;
  case X509_V_ERR_UNABLE_TO_GET_CRL:
  case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
    return ValidationStatus::revocation_status_unknown;
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
  case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
  case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
  case X509_V_ERR_CERT_UNTRUSTED:
    return ValidationStatus::untrusted;
  default:
    return ValidationStatus::cryptographic_failure;
  }
}

struct PasswordView {
  std::span<const std::uint8_t> bytes;
};

int copy_pem_password(char *output, int capacity, int,
                      void *context) noexcept {
  const auto *password = static_cast<const PasswordView *>(context);
  if (!password || capacity < 0 ||
      password->bytes.size() > static_cast<std::size_t>(capacity) ||
      password->bytes.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return -1;
  if (!password->bytes.empty())
    std::memcpy(output, password->bytes.data(), password->bytes.size());
  return static_cast<int>(password->bytes.size());
}

} // namespace

struct OpenIdentity::Impl {
  // The key never leaves this owner except as a borrowed provider pointer used
  // by the friend TLS adapter on the same service shard. The certificate chain
  // is copied because the store may later reallocate its identity vector.
  PkeyOwner private_key;
  std::vector<std::vector<std::uint8_t>> certificate_chain_der;
};

OpenIdentity::OpenIdentity(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

OpenIdentity::OpenIdentity(OpenIdentity &&) noexcept = default;
OpenIdentity &OpenIdentity::operator=(OpenIdentity &&) noexcept = default;
OpenIdentity::~OpenIdentity() = default;

std::span<const std::vector<std::uint8_t>>
OpenIdentity::certificate_chain_der() const noexcept {
  return impl_ ? std::span<const std::vector<std::uint8_t>>{
                     impl_->certificate_chain_der}
               : std::span<const std::vector<std::uint8_t>>{};
}

void *OpenIdentity::native_private_key() const noexcept {
  return impl_ ? impl_->private_key.get() : nullptr;
}

Store::Store(std::array<std::uint8_t, 32U> wrapping_key,
             std::vector<std::uint8_t> vault_context,
             StoreCheckpoint state) noexcept
    : wrapping_key_(wrapping_key), vault_context_(std::move(vault_context)),
      state_(std::move(state)) {}

std::optional<Store>
Store::create(std::span<const std::uint8_t> wrapping_key,
              std::span<const std::uint8_t> vault_context) noexcept {
  if (!has_key_entropy(wrapping_key) || vault_context.empty())
    return std::nullopt;
  try {
    std::array<std::uint8_t, 32U> key{};
    std::ranges::copy(wrapping_key, key.begin());
    return Store{key,
                 {vault_context.begin(), vault_context.end()},
                 StoreCheckpoint{}};
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Store>
Store::restore(const StoreCheckpoint &checkpoint,
               std::span<const std::uint8_t> wrapping_key,
               std::span<const std::uint8_t> vault_context) noexcept {
  auto candidate = create(wrapping_key, vault_context);
  if (!candidate || checkpoint.next_id == 0U)
    return std::nullopt;
  try {
    std::vector<ObjectId> ids;
    ids.reserve(checkpoint.authorities.size() + checkpoint.identities.size());
    for (const auto &authority : checkpoint.authorities)
      ids.push_back(authority.id);
    for (const auto &identity : checkpoint.identities)
      ids.push_back(identity.id);
    std::ranges::sort(ids);
    if (std::ranges::any_of(ids, [](ObjectId id) { return id == 0U; }) ||
        std::adjacent_find(ids.begin(), ids.end()) != ids.end())
      return std::nullopt;

    // Validate every identity and encrypted key before replacing the empty
    // candidate. This makes restore atomic and rejects edited object IDs or
    // certificate bytes because those fields are part of the AEAD binding.
    for (const auto &authority : checkpoint.authorities) {
      if (authority.certificate_der.empty() ||
          authority.sealed_private_key.empty())
        return std::nullopt;
      auto certificate = decode_certificate(authority.certificate_der);
      const auto binding = key_binding(vault_context, authority.id,
                                       authority.certificate_der);
      auto key = open_private_key(authority.sealed_private_key, wrapping_key,
                                  binding);
      PkeyOwner public_key{certificate ? X509_get_pubkey(certificate.get())
                                       : nullptr};
      if (!certificate || !key || !public_key ||
          X509_check_ca(certificate.get()) <= 0 ||
          X509_NAME_cmp(X509_get_subject_name(certificate.get()),
                        X509_get_issuer_name(certificate.get())) != 0 ||
          X509_verify(certificate.get(), public_key.get()) != 1 ||
          X509_check_private_key(certificate.get(), key.get()) != 1 ||
          authority.next_serial == 0U)
        return std::nullopt;
    }
    for (const auto &identity : checkpoint.identities) {
      if (identity.certificate_chain_der.empty() ||
          identity.sealed_private_key.empty() || identity.serial.empty())
        return std::nullopt;
      auto certificate = decode_certificate(identity.certificate_chain_der[0]);
      const auto binding = key_binding(vault_context, identity.id,
                                       identity.certificate_chain_der[0]);
      auto key = open_private_key(identity.sealed_private_key, wrapping_key,
                                  binding);
      if (!certificate || !key || X509_check_private_key(certificate.get(),
                                                         key.get()) != 1 ||
          !std::ranges::equal(
              identity.serial,
              serial_bytes(X509_get0_serialNumber(certificate.get()))))
        return std::nullopt;
      for (std::size_t index = 1U;
           index < identity.certificate_chain_der.size(); ++index)
        if (!decode_certificate(identity.certificate_chain_der[index]))
          return std::nullopt;
      if (identity.issuer != 0U) {
        const auto issuer = std::ranges::find(
            checkpoint.authorities, identity.issuer, &AuthorityRecord::id);
        if (issuer == checkpoint.authorities.end() ||
            identity.certificate_chain_der.size() < 2U ||
            identity.certificate_chain_der[1] != issuer->certificate_der)
          return std::nullopt;
        auto issuer_certificate = decode_certificate(issuer->certificate_der);
        PkeyOwner issuer_key{issuer_certificate
                                 ? X509_get_pubkey(issuer_certificate.get())
                                 : nullptr};
        if (!issuer_key || X509_verify(certificate.get(), issuer_key.get()) != 1)
          return std::nullopt;
      }
    }
    for (const auto &authority : checkpoint.authorities) {
      std::vector<ObjectId> revoked_ids;
      revoked_ids.reserve(authority.revocations.size());
      for (const auto &revocation : authority.revocations) {
        const auto identity = std::ranges::find(
            checkpoint.identities, revocation.identity, &IdentityRecord::id);
        const auto reason = static_cast<std::uint8_t>(revocation.reason);
        if (identity == checkpoint.identities.end() ||
            identity->issuer != authority.id ||
            identity->serial != revocation.serial ||
            !valid_time(revocation.revoked_at) || reason > 10U || reason == 7U ||
            reason == static_cast<std::uint8_t>(
                          RevocationReason::remove_from_crl))
          return std::nullopt;
        revoked_ids.push_back(revocation.identity);
      }
      std::ranges::sort(revoked_ids);
      if (std::adjacent_find(revoked_ids.begin(), revoked_ids.end()) !=
          revoked_ids.end())
        return std::nullopt;
    }
    candidate->state_ = checkpoint;
    return candidate;
  } catch (...) {
    return std::nullopt;
  }
}

Store::Store(Store &&other) noexcept
    : wrapping_key_(other.wrapping_key_),
      vault_context_(std::move(other.vault_context_)),
      state_(std::move(other.state_)) {
  OPENSSL_cleanse(other.wrapping_key_.data(), other.wrapping_key_.size());
}

Store &Store::operator=(Store &&other) noexcept {
  if (this != &other) {
    cleanse_secrets();
    wrapping_key_ = other.wrapping_key_;
    vault_context_ = std::move(other.vault_context_);
    state_ = std::move(other.state_);
    OPENSSL_cleanse(other.wrapping_key_.data(), other.wrapping_key_.size());
  }
  return *this;
}

Store::~Store() { cleanse_secrets(); }

void Store::cleanse_secrets() noexcept {
  OPENSSL_cleanse(wrapping_key_.data(), wrapping_key_.size());
  if (!vault_context_.empty())
    OPENSSL_cleanse(vault_context_.data(), vault_context_.size());
}

ObjectId Store::allocate_id() noexcept {
  if (state_.next_id == 0U)
    return 0U;
  const auto start = state_.next_id;
  auto candidate = start;
  do {
    const auto used_by_authority =
        std::ranges::any_of(state_.authorities, [&](const auto &entry) {
          return entry.id == candidate;
        });
    const auto used_by_identity =
        std::ranges::any_of(state_.identities, [&](const auto &entry) {
          return entry.id == candidate;
        });
    if (!used_by_authority && !used_by_identity) {
      state_.next_id = candidate + 1U;
      if (state_.next_id == 0U)
        state_.next_id = 1U;
      return candidate;
    }
    ++candidate;
    if (candidate == 0U)
      candidate = 1U;
  } while (candidate != start);
  return 0U;
}

const AuthorityRecord *Store::authority(ObjectId id) const noexcept {
  const auto found = std::ranges::find(state_.authorities, id,
                                       &AuthorityRecord::id);
  return found == state_.authorities.end() ? nullptr : &*found;
}

const IdentityRecord *Store::identity(ObjectId id) const noexcept {
  const auto found =
      std::ranges::find(state_.identities, id, &IdentityRecord::id);
  return found == state_.identities.end() ? nullptr : &*found;
}

std::optional<OpenIdentity>
Store::open_identity(ObjectId id) const noexcept {
  const auto *record = identity(id);
  if (!record || record->certificate_chain_der.empty())
    return std::nullopt;
  try {
    const auto binding = key_binding(vault_context_, record->id,
                                     record->certificate_chain_der.front());
    auto key = open_private_key(record->sealed_private_key, wrapping_key_,
                                binding);
    auto certificate = decode_certificate(record->certificate_chain_der.front());
    if (!key || !certificate ||
        X509_check_private_key(certificate.get(), key.get()) != 1)
      return std::nullopt;
    auto impl = std::make_unique<OpenIdentity::Impl>();
    impl->private_key = std::move(key);
    impl->certificate_chain_der = record->certificate_chain_der;
    return OpenIdentity{std::move(impl)};
  } catch (...) {
    return std::nullopt;
  }
}

std::pair<MutationResult, ObjectId>
Store::create_authority(const AuthorityProfile &profile) noexcept {
  if (profile.subject.common_name.empty() ||
      !valid_time(profile.not_before) || !valid_time(profile.not_after) ||
      profile.not_after <= profile.not_before)
    return {MutationResult::invalid_argument, 0U};
  try {
    auto key = generate_key(profile.key_algorithm);
    X509Owner certificate{X509_new()};
    if (!key || !certificate || X509_set_version(certificate.get(), 2L) != 1 ||
        !set_serial(certificate.get(), 1U) ||
        !set_validity(certificate.get(), profile.not_before,
                      profile.not_after) ||
        !set_subject(certificate.get(), profile.subject) ||
        X509_set_issuer_name(certificate.get(),
                             X509_get_subject_name(certificate.get())) != 1 ||
        X509_set_pubkey(certificate.get(), key.get()) != 1 ||
        !add_authority_extensions(certificate.get(), profile.path_length) ||
        !sign_certificate(certificate.get(), key.get()))
      return {MutationResult::cryptographic_failure, 0U};
    const auto der = encode_certificate(certificate.get());
    if (!der)
      return {MutationResult::cryptographic_failure, 0U};
    state_.authorities.reserve(state_.authorities.size() + 1U);
    const auto id = allocate_id();
    if (id == 0U)
      return {MutationResult::resource_exhausted, 0U};
    AuthorityRecord record{.id = id,
                           .certificate_der = *der,
                           .sealed_private_key = {},
                           .next_serial = 2U,
                           .revocations = {}};
    const auto binding = key_binding(vault_context_, id, *der);
    if (binding.empty() ||
        !seal_private_key(key.get(), wrapping_key_, binding,
                          record.sealed_private_key)) {
      return {MutationResult::cryptographic_failure, 0U};
    }
    state_.authorities.push_back(std::move(record));
    return {MutationResult::applied, id};
  } catch (...) {
    return {MutationResult::resource_exhausted, 0U};
  }
}

std::pair<MutationResult, ObjectId>
Store::issue_identity(ObjectId authority_id,
                      const IdentityProfile &profile) noexcept {
  auto *issuer_record = const_cast<AuthorityRecord *>(authority(authority_id));
  if (!issuer_record)
    return {MutationResult::not_found, 0U};
  if (profile.subject.common_name.empty() ||
      !valid_time(profile.not_before) || !valid_time(profile.not_after) ||
      profile.not_after <= profile.not_before)
    return {MutationResult::invalid_argument, 0U};
  if (issuer_record->next_serial == 0U ||
      issuer_record->next_serial == std::numeric_limits<std::uint64_t>::max())
    return {MutationResult::serial_exhausted, 0U};
  try {
    auto issuer = decode_certificate(issuer_record->certificate_der);
    const auto issuer_binding = key_binding(
        vault_context_, issuer_record->id, issuer_record->certificate_der);
    auto issuer_key = open_private_key(issuer_record->sealed_private_key,
                                       wrapping_key_, issuer_binding);
    if (!issuer || !issuer_key ||
        X509_check_private_key(issuer.get(), issuer_key.get()) != 1)
      return {MutationResult::cryptographic_failure, 0U};
    if (!validity_within(issuer.get(), profile.not_before, profile.not_after))
      return {MutationResult::expired_issuer, 0U};
    auto key = generate_key(profile.key_algorithm);
    X509Owner certificate{X509_new()};
    const auto serial = issuer_record->next_serial;
    if (!key || !certificate || X509_set_version(certificate.get(), 2L) != 1 ||
        !set_serial(certificate.get(), serial) ||
        !set_validity(certificate.get(), profile.not_before,
                      profile.not_after) ||
        !set_subject(certificate.get(), profile.subject) ||
        X509_set_issuer_name(certificate.get(),
                             X509_get_subject_name(issuer.get())) != 1 ||
        X509_set_pubkey(certificate.get(), key.get()) != 1 ||
        !add_identity_extensions(certificate.get(), issuer.get(), profile) ||
        !sign_certificate(certificate.get(), issuer_key.get()))
      return {MutationResult::cryptographic_failure, 0U};
    const auto leaf_der = encode_certificate(certificate.get());
    if (!leaf_der)
      return {MutationResult::cryptographic_failure, 0U};
    state_.identities.reserve(state_.identities.size() + 1U);
    const auto id = allocate_id();
    if (id == 0U)
      return {MutationResult::resource_exhausted, 0U};
    IdentityRecord record{
        .id = id,
        .issuer = authority_id,
        .serial = serial_bytes(X509_get0_serialNumber(certificate.get())),
        .certificate_chain_der = {*leaf_der, issuer_record->certificate_der},
        .sealed_private_key = {}};
    const auto binding = key_binding(vault_context_, id, *leaf_der);
    if (record.serial.empty() || binding.empty() ||
        !seal_private_key(key.get(), wrapping_key_, binding,
                          record.sealed_private_key)) {
      return {MutationResult::cryptographic_failure, 0U};
    }
    state_.identities.push_back(std::move(record));
    ++issuer_record->next_serial;
    return {MutationResult::applied, id};
  } catch (...) {
    return {MutationResult::resource_exhausted, 0U};
  }
}

std::pair<MutationResult, ObjectId>
Store::import_identity(std::span<const std::uint8_t> certificate_chain_pem,
                       std::span<const std::uint8_t> private_key_pem,
                       std::span<const std::uint8_t> password) noexcept {
  if (certificate_chain_pem.empty() || private_key_pem.empty() ||
      certificate_chain_pem.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      private_key_pem.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return {MutationResult::invalid_argument, 0U};
  try {
    BioOwner certificate_bio{BIO_new_mem_buf(
        certificate_chain_pem.data(),
        static_cast<int>(certificate_chain_pem.size()))};
    std::vector<X509Owner> certificates;
    while (certificate_bio) {
      X509Owner certificate{
          PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr)};
      if (!certificate)
        break;
      certificates.push_back(std::move(certificate));
    }
    // PEM_read reports NO_START_LINE when it reaches trailing whitespace after
    // the last certificate. Clear that expected queue entry so it cannot be
    // mistaken for a later cryptographic failure on this service shard.
    ERR_clear_error();
    if (certificates.empty())
      return {MutationResult::invalid_certificate, 0U};

    BioOwner key_bio{BIO_new_mem_buf(private_key_pem.data(),
                                    static_cast<int>(private_key_pem.size()))};
    PasswordView password_view{.bytes = password};
    PkeyOwner key{key_bio ? PEM_read_bio_PrivateKey(
                               key_bio.get(), nullptr, copy_pem_password,
                               &password_view)
                         : nullptr};
    if (!key)
      return {MutationResult::cryptographic_failure, 0U};
    if (X509_check_private_key(certificates.front().get(), key.get()) != 1)
      return {MutationResult::key_mismatch, 0U};

    std::vector<std::vector<std::uint8_t>> chain;
    chain.reserve(certificates.size());
    for (const auto &certificate : certificates) {
      auto der = encode_certificate(certificate.get());
      if (!der)
        return {MutationResult::invalid_certificate, 0U};
      chain.push_back(std::move(*der));
    }
    state_.identities.reserve(state_.identities.size() + 1U);
    const auto id = allocate_id();
    if (id == 0U)
      return {MutationResult::resource_exhausted, 0U};
    IdentityRecord record{
        .id = id,
        .issuer = 0U,
        .serial = serial_bytes(
            X509_get0_serialNumber(certificates.front().get())),
        .certificate_chain_der = std::move(chain),
        .sealed_private_key = {}};
    const auto binding = key_binding(vault_context_, id,
                                     record.certificate_chain_der.front());
    if (record.serial.empty() || binding.empty() ||
        !seal_private_key(key.get(), wrapping_key_, binding,
                          record.sealed_private_key)) {
      return {MutationResult::cryptographic_failure, 0U};
    }
    state_.identities.push_back(std::move(record));
    return {MutationResult::applied, id};
  } catch (...) {
    return {MutationResult::resource_exhausted, 0U};
  }
}

MutationResult Store::revoke(ObjectId authority_id, ObjectId identity_id,
                             std::uint64_t revoked_at,
                             RevocationReason reason) noexcept {
  auto *issuer = const_cast<AuthorityRecord *>(authority(authority_id));
  const auto *certificate = identity(identity_id);
  if (!issuer || !certificate || certificate->issuer != authority_id)
    return MutationResult::not_found;
  if (!valid_time(revoked_at))
    return MutationResult::invalid_argument;
  const auto reason_value = static_cast<std::uint8_t>(reason);
  // removeFromCRL belongs to delta CRLs and cannot be inserted as a positive
  // revocation in the complete CRL emitted by this store. Value 7 is unassigned
  // by RFC 5280 and out-of-range enum casts are rejected at the boundary.
  if (reason_value > 10U || reason_value == 7U ||
      reason == RevocationReason::remove_from_crl)
    return MutationResult::invalid_argument;
  if (std::ranges::any_of(issuer->revocations, [&](const auto &entry) {
        return entry.identity == identity_id;
      }))
    return MutationResult::duplicate;
  try {
    issuer->revocations.reserve(issuer->revocations.size() + 1U);
    issuer->revocations.push_back({.identity = identity_id,
                                   .serial = certificate->serial,
                                   .revoked_at = revoked_at,
                                   .reason = reason});
    return MutationResult::applied;
  } catch (...) {
    return MutationResult::resource_exhausted;
  }
}

std::optional<std::vector<std::uint8_t>>
Store::issue_crl(ObjectId authority_id, std::uint64_t this_update,
                 std::uint64_t next_update) const noexcept {
  const auto *record = authority(authority_id);
  if (!record || !valid_time(this_update) || !valid_time(next_update) ||
      next_update <= this_update)
    return std::nullopt;
  try {
    auto issuer = decode_certificate(record->certificate_der);
    const auto binding = key_binding(vault_context_, record->id,
                                     record->certificate_der);
    auto key = open_private_key(record->sealed_private_key, wrapping_key_,
                                binding);
    CrlOwner crl{X509_CRL_new()};
    auto last = make_time(this_update);
    auto next = make_time(next_update);
    if (!issuer || !key || !crl || !last || !next ||
        X509_CRL_set_version(crl.get(), 1L) != 1 ||
        X509_CRL_set_issuer_name(crl.get(),
                                 X509_get_subject_name(issuer.get())) != 1 ||
        X509_CRL_set1_lastUpdate(crl.get(), last.get()) != 1 ||
        X509_CRL_set1_nextUpdate(crl.get(), next.get()) != 1)
      return std::nullopt;
    for (const auto &revocation : record->revocations) {
      auto serial = integer_from_bytes(revocation.serial);
      auto revoked_at = make_time(revocation.revoked_at);
      std::unique_ptr<X509_REVOKED,
                      OpenSslDeleter<X509_REVOKED, X509_REVOKED_free>>
          revoked{X509_REVOKED_new()};
      std::unique_ptr<ASN1_ENUMERATED,
                      OpenSslDeleter<ASN1_ENUMERATED, ASN1_ENUMERATED_free>>
          reason{ASN1_ENUMERATED_new()};
      if (!serial || !revoked_at || !revoked || !reason ||
          ASN1_ENUMERATED_set(reason.get(),
                              static_cast<long>(revocation.reason)) != 1 ||
          X509_REVOKED_set_serialNumber(revoked.get(), serial.get()) != 1 ||
          X509_REVOKED_set_revocationDate(revoked.get(), revoked_at.get()) !=
              1 ||
          X509_REVOKED_add1_ext_i2d(revoked.get(), NID_crl_reason,
                                    reason.get(), 0, X509V3_ADD_DEFAULT) != 1 ||
          X509_CRL_add0_revoked(crl.get(), revoked.release()) != 1)
        return std::nullopt;
    }
    X509_CRL_sort(crl.get());
    if (X509_CRL_sign(crl.get(), key.get(), signing_digest(key.get())) <= 0)
      return std::nullopt;
    return encode_der<X509_CRL, i2d_X509_CRL>(crl.get());
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::vector<std::uint8_t>>
Store::make_ocsp_request(ObjectId identity_id) const noexcept {
  const auto *record = identity(identity_id);
  const auto *issuer_record = record ? authority(record->issuer) : nullptr;
  if (!record || !issuer_record || record->certificate_chain_der.empty())
    return std::nullopt;
  auto certificate = decode_certificate(record->certificate_chain_der[0]);
  auto issuer = decode_certificate(issuer_record->certificate_der);
  OcspRequestOwner request{OCSP_REQUEST_new()};
  auto *id = certificate && issuer
                 ? OCSP_cert_to_id(EVP_sha256(), certificate.get(), issuer.get())
                 : nullptr;
  if (!request || !id || !OCSP_request_add0_id(request.get(), id)) {
    OCSP_CERTID_free(id);
    return std::nullopt;
  }
  return encode_der<OCSP_REQUEST, i2d_OCSP_REQUEST>(request.get());
}

std::optional<std::vector<std::uint8_t>>
Store::answer_ocsp(ObjectId authority_id,
                   std::span<const std::uint8_t> request_der,
                   std::uint64_t this_update,
                   std::uint64_t next_update) const noexcept {
  const auto *issuer_record = authority(authority_id);
  if (!issuer_record || request_der.empty() || !valid_time(this_update) ||
      !valid_time(next_update) || next_update <= this_update ||
      request_der.size() >
          static_cast<std::size_t>(std::numeric_limits<long>::max()))
    return std::nullopt;
  try {
    const auto *cursor = request_der.data();
    OcspRequestOwner request{d2i_OCSP_REQUEST(
        nullptr, &cursor, static_cast<long>(request_der.size()))};
    if (!request || cursor != request_der.data() + request_der.size())
      return std::nullopt;
    auto issuer = decode_certificate(issuer_record->certificate_der);
    const auto binding = key_binding(vault_context_, issuer_record->id,
                                     issuer_record->certificate_der);
    auto key = open_private_key(issuer_record->sealed_private_key,
                                wrapping_key_, binding);
    OcspBasicOwner basic{OCSP_BASICRESP_new()};
    auto current = make_time(this_update);
    auto next = make_time(next_update);
    if (!issuer || !key || !basic || !current || !next)
      return std::nullopt;
    const auto requests = OCSP_request_onereq_count(request.get());
    if (requests <= 0)
      return std::nullopt;
    for (int index = 0; index < requests; ++index) {
      auto *one = OCSP_request_onereq_get0(request.get(), index);
      auto *requested_id = one ? OCSP_onereq_get0_id(one) : nullptr;
      if (!requested_id)
        return std::nullopt;
      const IdentityRecord *matched{};
      for (const auto &candidate : state_.identities) {
        if (candidate.issuer != authority_id ||
            candidate.certificate_chain_der.empty())
          continue;
        auto leaf = decode_certificate(candidate.certificate_chain_der[0]);
        std::unique_ptr<OCSP_CERTID,
                        OpenSslDeleter<OCSP_CERTID, OCSP_CERTID_free>>
            candidate_id{leaf ? OCSP_cert_to_id(EVP_sha256(), leaf.get(),
                                                issuer.get())
                              : nullptr};
        if (candidate_id && OCSP_id_cmp(requested_id, candidate_id.get()) == 0) {
          matched = &candidate;
          break;
        }
      }
      const RevocationRecord *revocation{};
      if (matched)
        for (const auto &entry : issuer_record->revocations)
          if (entry.identity == matched->id) {
            revocation = &entry;
            break;
          }
      auto revoked_at = revocation ? make_time(revocation->revoked_at)
                                   : TimeOwner{};
      const auto status = !matched         ? V_OCSP_CERTSTATUS_UNKNOWN
                          : revocation     ? V_OCSP_CERTSTATUS_REVOKED
                                           : V_OCSP_CERTSTATUS_GOOD;
      const auto reason = revocation
                              ? static_cast<int>(revocation->reason)
                              : OCSP_REVOKED_STATUS_NOSTATUS;
      if (!OCSP_basic_add1_status(basic.get(), requested_id, status, reason,
                                  revoked_at.get(), current.get(), next.get()))
        return std::nullopt;
    }
    if (OCSP_basic_sign(basic.get(), issuer.get(), key.get(),
                        signing_digest(key.get()), nullptr, 0U) != 1)
      return std::nullopt;
    OcspResponseOwner response{
        OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.release())};
    return response
               ? encode_der<OCSP_RESPONSE, i2d_OCSP_RESPONSE>(response.get())
               : std::nullopt;
  } catch (...) {
    return std::nullopt;
  }
}

ValidationResult Store::validate(const ValidationRequest &request) noexcept {
  const auto identity_selectors =
      static_cast<unsigned>(!request.hostname.empty()) +
      static_cast<unsigned>(request.ipv4_address.has_value()) +
      static_cast<unsigned>(request.ipv6_address.has_value());
  if (!valid_time(request.wall_clock_seconds) || identity_selectors > 1U ||
      request.hostname.find('\0') != std::string::npos)
    return {.status = ValidationStatus::cryptographic_failure};
  try {
    auto leaf = decode_certificate(request.leaf_der);
    StoreOwner store{X509_STORE_new()};
    StoreContextOwner context{X509_STORE_CTX_new()};
    VerifyParametersOwner store_parameters{X509_VERIFY_PARAM_new()};
    if (!leaf || !store || !context || !store_parameters)
      return {.status = ValidationStatus::malformed_certificate};

    // OCSP_basic_verify creates its own path context from X509_STORE. Applying
    // the injected wall clock to the store as well as the leaf context keeps
    // both certificate paths on the same caller-owned time source.
    X509_VERIFY_PARAM_set_time(
        store_parameters.get(),
        static_cast<std::time_t>(request.wall_clock_seconds));
    if (X509_STORE_set1_param(store.get(), store_parameters.get()) != 1)
      return {.status = ValidationStatus::cryptographic_failure};

    // X509_STORE takes a reference to accepted objects. Local RAII owners may
    // therefore release safely after insertion without leaving dangling
    // pointers in the validation store.
    for (const auto &der : request.trust_anchor_der) {
      auto anchor = decode_certificate(der);
      if (!anchor || X509_STORE_add_cert(store.get(), anchor.get()) != 1)
        return {.status = ValidationStatus::malformed_certificate};
    }
    for (const auto &der : request.crl_der) {
      if (der.empty() ||
          der.size() >
              static_cast<std::size_t>(std::numeric_limits<long>::max()))
        return {.status = ValidationStatus::invalid_revocation_data};
      const auto *cursor = der.data();
      CrlOwner crl{d2i_X509_CRL(nullptr, &cursor,
                                static_cast<long>(der.size()))};
      if (!crl || cursor != der.data() + der.size() ||
          X509_STORE_add_crl(store.get(), crl.get()) != 1)
        return {.status = ValidationStatus::invalid_revocation_data};
    }

    auto *untrusted = sk_X509_new_null();
    if (!untrusted)
      return {.status = ValidationStatus::cryptographic_failure};
    std::vector<X509Owner> intermediate_owners;
    intermediate_owners.reserve(request.intermediate_der.size());
    for (const auto &der : request.intermediate_der) {
      auto intermediate = decode_certificate(der);
      if (!intermediate || !sk_X509_push(untrusted, intermediate.get())) {
        sk_X509_free(untrusted);
        return {.status = ValidationStatus::malformed_certificate};
      }
      intermediate_owners.push_back(std::move(intermediate));
    }
    if (X509_STORE_CTX_init(context.get(), store.get(), leaf.get(),
                            untrusted) != 1) {
      sk_X509_free(untrusted);
      return {.status = ValidationStatus::cryptographic_failure};
    }
    auto *parameters = X509_STORE_CTX_get0_param(context.get());
    const auto purpose = request.usage == CertificateUsage::tls_client
                             ? X509_PURPOSE_SSL_CLIENT
                             : X509_PURPOSE_SSL_SERVER;
    if (!parameters) {
      sk_X509_free(untrusted);
      return {.status = ValidationStatus::cryptographic_failure};
    }
    X509_VERIFY_PARAM_set_time(
        parameters, static_cast<std::time_t>(request.wall_clock_seconds));
    const auto ipv4_matches =
        !request.ipv4_address ||
        X509_VERIFY_PARAM_set1_ip(parameters, request.ipv4_address->data(),
                                  request.ipv4_address->size()) == 1;
    const auto ipv6_matches =
        !request.ipv6_address ||
        X509_VERIFY_PARAM_set1_ip(parameters, request.ipv6_address->data(),
                                  request.ipv6_address->size()) == 1;
    if (X509_VERIFY_PARAM_set_purpose(parameters, purpose) != 1 ||
        (!request.hostname.empty() &&
         X509_VERIFY_PARAM_set1_host(parameters, request.hostname.c_str(),
                                     request.hostname.size()) != 1) ||
        !ipv4_matches || !ipv6_matches) {
      sk_X509_free(untrusted);
      return {.status = ValidationStatus::cryptographic_failure};
    }
    if (!request.crl_der.empty() &&
        X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_CRL_CHECK) != 1) {
      sk_X509_free(untrusted);
      return {.status = ValidationStatus::cryptographic_failure};
    }
    const auto verified = X509_verify_cert(context.get());
    const auto provider_error = X509_STORE_CTX_get_error(context.get());
    const auto depth = X509_STORE_CTX_get_error_depth(context.get());
    OwnedCertificateStack verified_chain{
        verified == 1 ? X509_STORE_CTX_get1_chain(context.get()) : nullptr};
    sk_X509_free(untrusted);
    if (verified != 1)
      return {.status = map_verify_error(provider_error),
              .provider_error = provider_error,
              .error_depth = depth};

    if (request.usage == CertificateUsage::tls_server_and_client) {
      // The initial X509_verify_cert call used the server purpose. A dual-use
      // request is an intersection, not an alias for server authentication.
      // Check the client purpose on every certificate in the already verified
      // path so an intermediate EKU restriction cannot be bypassed by a leaf
      // that happens to contain both OIDs. OpenSSL uses `ca = 0` for the leaf
      // and `ca = 1` for issuer certificates, matching its purpose checks in a
      // normal path validation run.
      if (!verified_chain)
        return {.status = ValidationStatus::cryptographic_failure};
      for (int index = 0; index < sk_X509_num(verified_chain.get()); ++index) {
        auto *certificate = sk_X509_value(verified_chain.get(), index);
        if (!certificate ||
            X509_check_purpose(certificate, X509_PURPOSE_SSL_CLIENT,
                               index == 0 ? 0 : 1) != 1)
          return {.status = ValidationStatus::invalid_usage,
                  .error_depth = index};
      }
    }

    bool definitive_ocsp{};
    if (!request.ocsp_response_der.empty()) {
      if (!verified_chain || sk_X509_num(verified_chain.get()) < 2 ||
          request.ocsp_response_der.size() >
              static_cast<std::size_t>(std::numeric_limits<long>::max()))
        return {.status = ValidationStatus::invalid_revocation_data};
      const auto *cursor = request.ocsp_response_der.data();
      OcspResponseOwner response{d2i_OCSP_RESPONSE(
          nullptr, &cursor,
          static_cast<long>(request.ocsp_response_der.size()))};
      if (!response ||
          cursor != request.ocsp_response_der.data() +
                        request.ocsp_response_der.size() ||
          OCSP_response_status(response.get()) !=
              OCSP_RESPONSE_STATUS_SUCCESSFUL)
        return {.status = ValidationStatus::invalid_revocation_data};
      OcspBasicOwner basic{OCSP_response_get1_basic(response.get())};
      auto *issuer = sk_X509_value(verified_chain.get(), 1);
      std::unique_ptr<OCSP_CERTID,
                      OpenSslDeleter<OCSP_CERTID, OCSP_CERTID_free>>
          certificate_id{issuer ? OCSP_cert_to_id(EVP_sha256(), leaf.get(),
                                                  issuer)
                                : nullptr};
      if (!basic || !certificate_id ||
          OCSP_basic_verify(basic.get(), verified_chain.get(), store.get(),
                            0UL) != 1)
        return {.status = ValidationStatus::invalid_revocation_data};

      int status{};
      int reason{};
      ASN1_GENERALIZEDTIME *revoked_at{};
      ASN1_GENERALIZEDTIME *this_update{};
      ASN1_GENERALIZEDTIME *next_update{};
      if (OCSP_resp_find_status(basic.get(), certificate_id.get(), &status,
                                &reason, &revoked_at, &this_update,
                                &next_update) != 1 ||
          !this_update)
        return {.status = ValidationStatus::revocation_status_unknown};
      auto validation_time = make_time(request.wall_clock_seconds);
      const auto *produced_at = OCSP_resp_get0_produced_at(basic.get());
      // RFC 6960 permits nextUpdate to be absent. When it is present it is the
      // first time a newer response will be available, so an older response
      // cannot satisfy current status after that instant. No arbitrary clock
      // skew or maximum age is introduced by this layer.
      if (!validation_time || !produced_at ||
          ASN1_TIME_compare(produced_at, validation_time.get()) > 0 ||
          ASN1_TIME_compare(this_update, validation_time.get()) > 0 ||
          (next_update &&
           ASN1_TIME_compare(next_update, validation_time.get()) < 0))
        return {.status = ValidationStatus::invalid_revocation_data};
      definitive_ocsp = status == V_OCSP_CERTSTATUS_GOOD ||
                        status == V_OCSP_CERTSTATUS_REVOKED;
      if (status == V_OCSP_CERTSTATUS_REVOKED) {
        if (!revoked_at ||
            ASN1_TIME_compare(revoked_at, validation_time.get()) > 0)
          return {.status = ValidationStatus::invalid_revocation_data};
        return {.status = ValidationStatus::revoked};
      }
      if (status != V_OCSP_CERTSTATUS_GOOD)
        return {.status = ValidationStatus::revocation_status_unknown};
      static_cast<void>(reason);
    }
    if (request.require_revocation_status && request.crl_der.empty() &&
        !definitive_ocsp)
      return {.status = ValidationStatus::revocation_status_unknown};
    return {.status = ValidationStatus::valid,
            .provider_error = X509_V_OK,
            .error_depth = 0};
  } catch (...) {
    return {.status = ValidationStatus::cryptographic_failure};
  }
}

} // namespace router::pki
