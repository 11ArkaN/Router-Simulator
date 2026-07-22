// OpenSSL 3.5 DNSSEC key generation and signing adapter. EVP_PKEY is the sole
// owner of private material and is released by RAII. Public keys and signatures
// use the DNS wire formats from RFC 3110, RFC 6605 and RFC 8080.
// Source: ietf.dnssec.rsa.rfc3110
// Source: ietf.dnssec.ecdsa.rfc6605
// Source: ietf.dnssec.ed25519.rfc8080

#include "router/dnssec_signer.hpp"

#include "router/generated_dnssec_policy.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <array>
#include <limits>
#include <memory>

namespace router::dnssec {
namespace {

template <typename T, void (*Free)(T *)> struct OpenSslDeleter {
  void operator()(T *value) const noexcept {
    if (value != nullptr)
      Free(value);
  }
};

using BnOwner = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using PkeyOwner =
    std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using PkeyContextOwner =
    std::unique_ptr<EVP_PKEY_CTX,
                    OpenSslDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using DigestContextOwner =
    std::unique_ptr<EVP_MD_CTX,
                    OpenSslDeleter<EVP_MD_CTX, EVP_MD_CTX_free>>;
using EcdsaSignatureOwner =
    std::unique_ptr<ECDSA_SIG, OpenSslDeleter<ECDSA_SIG, ECDSA_SIG_free>>;
using CipherContextOwner =
    std::unique_ptr<EVP_CIPHER_CTX,
                    OpenSslDeleter<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>>;

constexpr std::array<std::uint8_t, 4U> sealed_magic{'R', 'V', 'K', '1'};
constexpr std::size_t wrapping_key_octets = 32U;
constexpr std::size_t nonce_octets = 12U;
constexpr std::size_t tag_octets = 16U;
constexpr std::size_t sealed_header_octets =
    sealed_magic.size() + 1U + nonce_octets + 4U;

struct SensitiveBytes {
  std::vector<std::uint8_t> value;
  ~SensitiveBytes() {
    // The optimizer cannot remove OPENSSL_cleanse. Capacity may exceed size,
    // but only initialized size bytes can contain DER private material.
    if (!value.empty())
      OPENSSL_cleanse(value.data(), value.size());
  }
};

void write_u32(std::span<std::uint8_t> bytes, std::size_t offset,
               std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
         bytes[offset + 3U];
}

bool append_bn(const BIGNUM *value, std::vector<std::uint8_t> &output) {
  if (value == nullptr || BN_is_negative(value) != 0 || BN_is_zero(value) != 0)
    return false;
  const auto octets = BN_num_bytes(value);
  if (octets <= 0)
    return false;
  const auto offset = output.size();
  output.resize(offset + static_cast<std::size_t>(octets));
  return BN_bn2bin(value, output.data() + offset) == octets;
}

bool rsa_public_wire(EVP_PKEY *key, std::vector<std::uint8_t> &wire) {
  BIGNUM *raw_exponent{};
  BIGNUM *raw_modulus{};
  if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &raw_exponent) != 1 ||
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &raw_modulus) != 1) {
    BN_free(raw_exponent);
    BN_free(raw_modulus);
    return false;
  }
  BnOwner exponent{raw_exponent};
  BnOwner modulus{raw_modulus};
  const auto exponent_octets = BN_num_bytes(exponent.get());
  if (exponent_octets <= 0 || exponent_octets > 65535)
    return false;
  std::vector<std::uint8_t> staged;
  if (exponent_octets < 256) {
    staged.push_back(static_cast<std::uint8_t>(exponent_octets));
  } else {
    staged.push_back(0U);
    staged.push_back(static_cast<std::uint8_t>(exponent_octets >> 8U));
    staged.push_back(static_cast<std::uint8_t>(exponent_octets));
  }
  if (!append_bn(exponent.get(), staged) || !append_bn(modulus.get(), staged))
    return false;
  wire = std::move(staged);
  return true;
}

bool ec_public_wire(EVP_PKEY *key, std::vector<std::uint8_t> &wire) {
  std::size_t size{};
  if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0U,
                                      &size) != 1 ||
      size != 65U)
    return false;
  std::array<std::uint8_t, 65U> point{};
  if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                      point.data(), point.size(), &size) != 1 ||
      point[0] != 0x04U)
    return false;
  wire.assign(point.begin() + 1, point.end());
  return true;
}

bool ed25519_public_wire(EVP_PKEY *key, std::vector<std::uint8_t> &wire) {
  std::array<std::uint8_t, 32U> public_key{};
  std::size_t size = public_key.size();
  if (EVP_PKEY_get_raw_public_key(key, public_key.data(), &size) != 1 ||
      size != public_key.size())
    return false;
  wire.assign(public_key.begin(), public_key.end());
  return true;
}

bool public_wire(std::uint8_t algorithm, EVP_PKEY *key,
                 std::vector<std::uint8_t> &wire) {
  const auto entry = policy::algorithm(algorithm);
  if (!entry || !key)
    return false;
  switch (entry->backend) {
  case policy::CryptoBackend::rsa_sha256:
    return EVP_PKEY_is_a(key, "RSA") == 1 && rsa_public_wire(key, wire);
  case policy::CryptoBackend::ecdsa_p256_sha256:
    return EVP_PKEY_is_a(key, "EC") == 1 && ec_public_wire(key, wire);
  case policy::CryptoBackend::ed25519:
    return EVP_PKEY_is_a(key, "ED25519") == 1 &&
           ed25519_public_wire(key, wire);
  case policy::CryptoBackend::none:
    return false;
  }
  return false;
}

bool private_der(EVP_PKEY *key, SensitiveBytes &der) {
  const auto size = i2d_PrivateKey(key, nullptr);
  if (size <= 0)
    return false;
  der.value.resize(static_cast<std::size_t>(size));
  auto *cursor = der.value.data();
  return i2d_PrivateKey(key, &cursor) == size &&
         cursor == der.value.data() + der.value.size();
}

bool add_aad(EVP_CIPHER_CTX *context,
             std::span<const std::uint8_t> header,
             std::span<const std::uint8_t> binding, bool encrypt) noexcept {
  if (header.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      binding.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;
  int written{};
  const auto update = encrypt ? EVP_EncryptUpdate : EVP_DecryptUpdate;
  return update(context, nullptr, &written, header.data(),
                static_cast<int>(header.size())) == 1 &&
         (binding.empty() ||
          update(context, nullptr, &written, binding.data(),
                 static_cast<int>(binding.size())) == 1);
}

bool encrypt_private(std::uint8_t algorithm, EVP_PKEY *key,
                     std::span<const std::uint8_t> wrapping_key,
                     std::span<const std::uint8_t> binding,
                     std::vector<std::uint8_t> &output) {
  if (wrapping_key.size() != wrapping_key_octets)
    return false;
  SensitiveBytes der;
  if (!private_der(key, der) ||
      der.value.size() > std::numeric_limits<std::uint32_t>::max() ||
      der.value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;

  std::array<std::uint8_t, nonce_octets> nonce{};
  if (RAND_priv_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
    return false;
  std::vector<std::uint8_t> staged(sealed_header_octets + der.value.size() +
                                   tag_octets);
  std::copy(sealed_magic.begin(), sealed_magic.end(), staged.begin());
  staged[sealed_magic.size()] = algorithm;
  std::copy(nonce.begin(), nonce.end(),
            staged.begin() + static_cast<std::ptrdiff_t>(sealed_magic.size() +
                                                         1U));
  write_u32(staged, sealed_header_octets - 4U,
            static_cast<std::uint32_t>(der.value.size()));

  CipherContextOwner cipher{EVP_CIPHER_CTX_new()};
  if (!cipher ||
      EVP_EncryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(cipher.get(), nullptr, nullptr, wrapping_key.data(),
                         nonce.data()) != 1 ||
      !add_aad(cipher.get(), std::span<const std::uint8_t>{staged}.first(
                                  sealed_header_octets),
               binding, true))
    return false;

  int written{};
  int final_written{};
  auto *ciphertext = staged.data() + sealed_header_octets;
  if (EVP_EncryptUpdate(cipher.get(), ciphertext, &written, der.value.data(),
                        static_cast<int>(der.value.size())) != 1 ||
      EVP_EncryptFinal_ex(cipher.get(), ciphertext + written,
                          &final_written) != 1 ||
      static_cast<std::size_t>(written + final_written) != der.value.size() ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(tag_octets),
                          staged.data() + sealed_header_octets +
                              der.value.size()) != 1)
    return false;
  output = std::move(staged);
  return true;
}

PkeyOwner decrypt_private(std::span<const std::uint8_t> sealed,
                          std::span<const std::uint8_t> wrapping_key,
                          std::span<const std::uint8_t> binding,
                          std::uint8_t &algorithm) {
  if (wrapping_key.size() != wrapping_key_octets ||
      sealed.size() < sealed_header_octets + tag_octets ||
      !std::ranges::equal(sealed.first(sealed_magic.size()), sealed_magic))
    return {};
  algorithm = sealed[sealed_magic.size()];
  const auto ciphertext_octets = read_u32(sealed, sealed_header_octets - 4U);
  if (ciphertext_octets == 0U ||
      ciphertext_octets >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      sealed.size() != sealed_header_octets + ciphertext_octets + tag_octets)
    return {};
  const auto nonce = sealed.subspan(sealed_magic.size() + 1U, nonce_octets);
  const auto ciphertext = sealed.subspan(sealed_header_octets,
                                         ciphertext_octets);
  const auto tag = sealed.last(tag_octets);

  SensitiveBytes der;
  der.value.resize(ciphertext.size());
  CipherContextOwner cipher{EVP_CIPHER_CTX_new()};
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
  if (EVP_DecryptUpdate(cipher.get(), der.value.data(), &written,
                        ciphertext.data(),
                        static_cast<int>(ciphertext.size())) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG,
                          static_cast<int>(tag.size()),
                          const_cast<std::uint8_t *>(tag.data())) != 1 ||
      EVP_DecryptFinal_ex(cipher.get(), der.value.data() + written,
                          &final_written) != 1 ||
      static_cast<std::size_t>(written + final_written) != der.value.size())
    return {};
  const auto *cursor = der.value.data();
  PkeyOwner key{d2i_AutoPrivateKey(
      nullptr, &cursor, static_cast<long>(der.value.size()))};
  return key && cursor == der.value.data() + der.value.size() ? std::move(key)
                                                              : PkeyOwner{};
}

PkeyOwner generate_rsa(std::uint16_t bits) noexcept {
  // Reject rather than clamp, because silently changing key policy is unsafe.
  if (bits < 512U || bits > 4096U)
    return {};
  PkeyContextOwner context{
      EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)};
  if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), bits) != 1)
    return {};
  EVP_PKEY *raw{};
  return EVP_PKEY_generate(context.get(), &raw) == 1 ? PkeyOwner{raw}
                                                      : PkeyOwner{};
}

PkeyOwner generate_named(const char *algorithm, const char *parameter) noexcept {
  return PkeyOwner{EVP_PKEY_Q_keygen(nullptr, nullptr, algorithm, parameter)};
}

bool digest_sign(EVP_PKEY *key, const EVP_MD *digest,
                 std::span<const std::uint8_t> data,
                 std::vector<std::uint8_t> &signature) {
  DigestContextOwner context{EVP_MD_CTX_new()};
  if (!context ||
      EVP_DigestSignInit(context.get(), nullptr, digest, nullptr, key) != 1 ||
      EVP_DigestSignUpdate(context.get(), data.data(), data.size()) != 1)
    return false;
  std::size_t size{};
  if (EVP_DigestSignFinal(context.get(), nullptr, &size) != 1 || size == 0U)
    return false;
  std::vector<std::uint8_t> staged(size);
  if (EVP_DigestSignFinal(context.get(), staged.data(), &size) != 1)
    return false;
  staged.resize(size);
  signature = std::move(staged);
  return true;
}

bool ed25519_sign(EVP_PKEY *key, std::span<const std::uint8_t> data,
                  std::vector<std::uint8_t> &signature) {
  DigestContextOwner context{EVP_MD_CTX_new()};
  if (!context ||
      EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key) != 1)
    return false;
  std::size_t size{};
  if (EVP_DigestSign(context.get(), nullptr, &size, data.data(), data.size()) !=
          1 ||
      size != 64U)
    return false;
  std::vector<std::uint8_t> staged(size);
  if (EVP_DigestSign(context.get(), staged.data(), &size, data.data(),
                     data.size()) != 1 ||
      size != 64U)
    return false;
  signature = std::move(staged);
  return true;
}

bool ecdsa_der_to_wire(std::span<const std::uint8_t> der,
                       std::vector<std::uint8_t> &wire) {
  const auto *cursor = der.data();
  EcdsaSignatureOwner signature{
      d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(der.size()))};
  if (!signature || cursor != der.data() + der.size())
    return false;
  const BIGNUM *r{};
  const BIGNUM *s{};
  ECDSA_SIG_get0(signature.get(), &r, &s);
  std::array<std::uint8_t, 64U> staged{};
  if (BN_bn2binpad(r, staged.data(), 32) != 32 ||
      BN_bn2binpad(s, staged.data() + 32, 32) != 32)
    return false;
  wire.assign(staged.begin(), staged.end());
  return true;
}

class OpenSslSigningKey final : public SigningKey {
public:
  OpenSslSigningKey(std::uint8_t algorithm, PkeyOwner key,
                    std::vector<std::uint8_t> public_key) noexcept
      : algorithm_(algorithm), key_(std::move(key)),
        public_key_(std::move(public_key)) {}

  [[nodiscard]] std::uint8_t algorithm() const noexcept override {
    return algorithm_;
  }
  [[nodiscard]] std::span<const std::uint8_t>
  public_key() const noexcept override {
    return public_key_;
  }

  [[nodiscard]] bool
  sign(std::span<const std::uint8_t> signed_data,
       std::vector<std::uint8_t> &output) const noexcept override {
    try {
      const auto entry = policy::algorithm(algorithm_);
      if (!entry || !key_)
        return false;
      switch (entry->backend) {
      case policy::CryptoBackend::rsa_sha256:
        return digest_sign(key_.get(), EVP_sha256(), signed_data, output);
      case policy::CryptoBackend::ecdsa_p256_sha256: {
        std::vector<std::uint8_t> der;
        return digest_sign(key_.get(), EVP_sha256(), signed_data, der) &&
               ecdsa_der_to_wire(der, output);
      }
      case policy::CryptoBackend::ed25519:
        return ed25519_sign(key_.get(), signed_data, output);
      case policy::CryptoBackend::none:
        return false;
      }
    } catch (...) {
      return false;
    }
    return false;
  }

  [[nodiscard]] bool
  seal(std::span<const std::uint8_t> wrapping_key,
       std::span<const std::uint8_t> context,
       std::vector<std::uint8_t> &output) const noexcept override {
    try {
      return key_ && encrypt_private(algorithm_, key_.get(), wrapping_key,
                                     context, output);
    } catch (...) {
      return false;
    }
  }

private:
  std::uint8_t algorithm_{};
  PkeyOwner key_;
  std::vector<std::uint8_t> public_key_;
};

} // namespace

std::unique_ptr<SigningKey>
generate_signing_key(std::uint8_t algorithm,
                     SigningKeyGeneration options) noexcept {
  const auto entry = policy::algorithm(algorithm);
  if (!entry || entry->backend == policy::CryptoBackend::none)
    return {};
  try {
    PkeyOwner key;
    std::vector<std::uint8_t> public_wire;
    switch (entry->backend) {
    case policy::CryptoBackend::rsa_sha256:
      key = generate_rsa(options.rsa_bits);
      if (!key || !rsa_public_wire(key.get(), public_wire))
        return {};
      break;
    case policy::CryptoBackend::ecdsa_p256_sha256:
      key = generate_named("EC", "prime256v1");
      if (!key || !ec_public_wire(key.get(), public_wire))
        return {};
      break;
    case policy::CryptoBackend::ed25519:
      key = generate_named("ED25519", nullptr);
      if (!key || !ed25519_public_wire(key.get(), public_wire))
        return {};
      break;
    case policy::CryptoBackend::none:
      return {};
    }
    return std::make_unique<OpenSslSigningKey>(algorithm, std::move(key),
                                               std::move(public_wire));
  } catch (...) {
    return {};
  }
}

std::unique_ptr<SigningKey>
unseal_signing_key(std::span<const std::uint8_t> sealed,
                   std::span<const std::uint8_t> wrapping_key,
                   std::span<const std::uint8_t> context) noexcept {
  try {
    std::uint8_t algorithm{};
    auto key = decrypt_private(sealed, wrapping_key, context, algorithm);
    std::vector<std::uint8_t> public_key;
    if (!key || !public_wire(algorithm, key.get(), public_key))
      return {};
    return std::make_unique<OpenSslSigningKey>(algorithm, std::move(key),
                                               std::move(public_key));
  } catch (...) {
    return {};
  }
}

} // namespace router::dnssec
