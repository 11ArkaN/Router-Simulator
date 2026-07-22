// Converts DNSSEC public keys and signatures into OpenSSL 3 provider objects.
// Wire encodings come from RFC 3110, RFC 6605 and RFC 8080. All ownership is
// local and deterministic: EVP/BIGNUM objects are released before returning.
// Source: ietf.dnssec.rsa.rfc3110
// Source: ietf.dnssec.ecdsa.rfc6605
// Source: ietf.dnssec.ed25519.rfc8080

#include "router/dnssec_openssl.hpp"

#include "router/generated_dnssec_policy.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <vector>

namespace router::dnssec {
namespace {

template <typename T, void (*Free)(T *)> struct OpenSslDeleter {
  void operator()(T *value) const noexcept {
    if (value != nullptr)
      Free(value);
  }
};

using BnOwner = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using ParamBuildOwner =
    std::unique_ptr<OSSL_PARAM_BLD,
                    OpenSslDeleter<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free>>;
using ParamOwner =
    std::unique_ptr<OSSL_PARAM, OpenSslDeleter<OSSL_PARAM, OSSL_PARAM_free>>;
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

PkeyOwner key_from_parameters(const char *type,
                              OSSL_PARAM_BLD *builder) noexcept {
  ParamOwner parameters{OSSL_PARAM_BLD_to_param(builder)};
  PkeyContextOwner context{EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr)};
  if (!parameters || !context || EVP_PKEY_fromdata_init(context.get()) != 1)
    return {};

  EVP_PKEY *raw{};
  // PUBLIC_KEY prevents a DNSKEY from being mistaken for private material and
  // avoids provider attempts to derive fields which are absent on the wire.
  if (EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_PUBLIC_KEY,
                        parameters.get()) != 1)
    return {};
  return PkeyOwner{raw};
}

PkeyOwner decode_rsa_key(std::span<const std::uint8_t> wire) noexcept {
  if (wire.empty())
    return {};
  std::size_t offset{1U};
  std::size_t exponent_length{wire[0]};
  if (exponent_length == 0U) {
    if (wire.size() < 3U)
      return {};
    exponent_length =
        (static_cast<std::size_t>(wire[1]) << 8U) | wire[2];
    offset = 3U;
  }
  if (exponent_length == 0U || exponent_length > 512U ||
      exponent_length > wire.size() - offset || wire[offset] == 0U)
    return {};
  const auto modulus_offset = offset + exponent_length;
  const auto modulus_length = wire.size() - modulus_offset;
  // RFC 5702 retains RFC 3110's 512 through 4096-bit RSA key range for
  // RSA/SHA-256. Leading zero octets are prohibited in both integers.
  if (modulus_length < 64U || modulus_length > 512U ||
      wire[modulus_offset] == 0U ||
      exponent_length > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      modulus_length >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return {};

  BnOwner exponent{BN_bin2bn(wire.data() + offset,
                             static_cast<int>(exponent_length), nullptr)};
  BnOwner modulus{BN_bin2bn(wire.data() + modulus_offset,
                            static_cast<int>(modulus_length),
                            nullptr)};
  ParamBuildOwner builder{OSSL_PARAM_BLD_new()};
  if (!exponent || !modulus || !builder || BN_is_zero(exponent.get()) != 0 ||
      BN_is_zero(modulus.get()) != 0 ||
      OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_E,
                             exponent.get()) != 1 ||
      OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_N,
                             modulus.get()) != 1)
    return {};
  return key_from_parameters("RSA", builder.get());
}

PkeyOwner decode_p256_key(std::span<const std::uint8_t> wire) noexcept {
  // RFC 6605 fixes algorithm 13 to exactly two 256-bit coordinates without
  // the SEC1 uncompressed-point marker. OpenSSL expects that marker.
  if (wire.size() != 64U)
    return {};
  std::array<std::uint8_t, 65U> point{};
  point[0] = 0x04U;
  std::copy(wire.begin(), wire.end(), point.begin() + 1);

  ParamBuildOwner builder{OSSL_PARAM_BLD_new()};
  if (!builder ||
      OSSL_PARAM_BLD_push_utf8_string(builder.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                      "prime256v1", 0U) != 1 ||
      OSSL_PARAM_BLD_push_octet_string(builder.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                       point.data(), point.size()) != 1)
    return {};
  return key_from_parameters("EC", builder.get());
}

PkeyOwner decode_ed25519_key(std::span<const std::uint8_t> wire) noexcept {
  if (wire.size() != 32U)
    return {};
  return PkeyOwner{EVP_PKEY_new_raw_public_key_ex(
      nullptr, "ED25519", nullptr, wire.data(), wire.size())};
}

std::vector<std::uint8_t>
ecdsa_signature_der(std::span<const std::uint8_t> wire) {
  if (wire.size() != 64U)
    return {};
  BnOwner r{BN_bin2bn(wire.data(), 32, nullptr)};
  BnOwner s{BN_bin2bn(wire.data() + 32, 32, nullptr)};
  EcdsaSignatureOwner signature{ECDSA_SIG_new()};
  if (!r || !s || !signature || BN_is_zero(r.get()) != 0 ||
      BN_is_zero(s.get()) != 0 ||
      ECDSA_SIG_set0(signature.get(), r.release(), s.release()) != 1)
    return {};

  const auto encoded_length = i2d_ECDSA_SIG(signature.get(), nullptr);
  if (encoded_length <= 0)
    return {};
  std::vector<std::uint8_t> encoded(static_cast<std::size_t>(encoded_length));
  auto *cursor = encoded.data();
  if (i2d_ECDSA_SIG(signature.get(), &cursor) != encoded_length)
    return {};
  return encoded;
}

bool verify_digest(EVP_PKEY *key, const EVP_MD *digest,
                   std::span<const std::uint8_t> data,
                   std::span<const std::uint8_t> signature) noexcept {
  DigestContextOwner context{EVP_MD_CTX_new()};
  if (!context ||
      EVP_DigestVerifyInit(context.get(), nullptr, digest, nullptr, key) != 1 ||
      EVP_DigestVerifyUpdate(context.get(), data.data(), data.size()) != 1)
    return false;
  return EVP_DigestVerifyFinal(context.get(), signature.data(),
                               signature.size()) == 1;
}

bool verify_ed25519(EVP_PKEY *key, std::span<const std::uint8_t> data,
                    std::span<const std::uint8_t> signature) noexcept {
  if (signature.size() != 64U)
    return false;
  DigestContextOwner context{EVP_MD_CTX_new()};
  if (!context ||
      EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key) != 1)
    return false;
  // Ed25519 is intrinsically one-shot in EVP. Supplying a separate digest or
  // calling Update would change the algorithm contract and is rejected.
  return EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                          data.data(), data.size()) == 1;
}

} // namespace

bool OpenSslCryptoVerifier::supports(std::uint8_t algorithm) const noexcept {
  const auto entry = policy::algorithm(algorithm);
  return entry && entry->backend != policy::CryptoBackend::none;
}

bool OpenSslCryptoVerifier::verify(
    std::uint8_t algorithm, std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> signed_data,
    std::span<const std::uint8_t> signature) const noexcept {
  const auto entry = policy::algorithm(algorithm);
  if (!entry)
    return false;
  try {
    switch (entry->backend) {
    case policy::CryptoBackend::rsa_sha256: {
      const auto key = decode_rsa_key(public_key);
      return key && verify_digest(key.get(), EVP_sha256(), signed_data, signature);
    }
    case policy::CryptoBackend::ecdsa_p256_sha256: {
      const auto key = decode_p256_key(public_key);
      const auto der = ecdsa_signature_der(signature);
      return key && !der.empty() &&
             verify_digest(key.get(), EVP_sha256(), signed_data, der);
    }
    case policy::CryptoBackend::ed25519: {
      const auto key = decode_ed25519_key(public_key);
      return key && verify_ed25519(key.get(), signed_data, signature);
    }
    case policy::CryptoBackend::none:
      return false;
    }
  } catch (...) {
    // Allocation failure is an ordinary verification failure at this narrow
    // noexcept boundary. Higher validation layers retain the DNSSEC state.
    return false;
  }
  return false;
}

bool OpenSslCryptoVerifier::supports_digest(
    std::uint8_t digest_type) const noexcept {
  const auto entry = policy::digest(digest_type);
  return entry && entry->backend != policy::DigestBackend::none;
}

bool OpenSslCryptoVerifier::calculate_digest(
    std::uint8_t digest_type, std::span<const std::uint8_t> input,
    std::vector<std::uint8_t> &output) const noexcept {
  const auto entry = policy::digest(digest_type);
  if (!entry)
    return false;
  const EVP_MD *algorithm{};
  switch (entry->backend) {
  case policy::DigestBackend::sha1:
    algorithm = EVP_sha1();
    break;
  case policy::DigestBackend::sha256:
    algorithm = EVP_sha256();
    break;
  case policy::DigestBackend::sha384:
    algorithm = EVP_sha384();
    break;
  case policy::DigestBackend::none:
    return false;
  }

  std::array<std::uint8_t, EVP_MAX_MD_SIZE> staged{};
  unsigned int length{};
  if (EVP_Digest(input.data(), input.size(), staged.data(), &length, algorithm,
                 nullptr) != 1)
    return false;
  try {
    output.assign(staged.begin(), staged.begin() + length);
    return true;
  } catch (...) {
    return false;
  }
}

} // namespace router::dnssec
