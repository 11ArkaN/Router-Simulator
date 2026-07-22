// RFC 5903 group 19 ECDH on NIST P-256 through OpenSSL's provider API. IKE
// transmits fixed-width X followed by Y, while OpenSSL imports and exports the
// same point with the standard uncompressed 0x04 prefix.

#include "router/ikev2_dh.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>

namespace router::ikev2::dh {
namespace {

EVP_PKEY *import_peer(std::span<const std::uint8_t> peer_value) noexcept {
  if (peer_value.size() != group_19_public_octets)
    return nullptr;
  std::array<std::uint8_t, group_19_public_octets + 1U> encoded{};
  encoded[0U] = 0x04U;
  std::copy(peer_value.begin(), peer_value.end(), encoded.begin() + 1U);
  char mutable_group_name[] = "prime256v1";
  auto group_parameter = OSSL_PARAM_construct_utf8_string(
      OSSL_PKEY_PARAM_GROUP_NAME, mutable_group_name, 0U);
  auto public_parameter = OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_PUB_KEY, encoded.data(), encoded.size());
  std::array parameters{group_parameter, public_parameter,
                        OSSL_PARAM_construct_end()};
  auto *context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!context)
    return nullptr;
  EVP_PKEY *peer{};
  const bool imported = EVP_PKEY_fromdata_init(context) == 1 &&
                        EVP_PKEY_fromdata(context, &peer, EVP_PKEY_PUBLIC_KEY,
                                          parameters.data()) == 1;
  EVP_PKEY_CTX_free(context);
  return imported ? peer : nullptr;
}

} // namespace

std::unique_ptr<EphemeralKey> EphemeralKey::generate_group_19() noexcept {
  auto *context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!context)
    return nullptr;
  char mutable_group_name[] = "prime256v1";
  auto group_parameter = OSSL_PARAM_construct_utf8_string(
      OSSL_PKEY_PARAM_GROUP_NAME, mutable_group_name, 0U);
  std::array parameters{group_parameter, OSSL_PARAM_construct_end()};
  EVP_PKEY *key{};
  const bool generated = EVP_PKEY_keygen_init(context) == 1 &&
                         EVP_PKEY_CTX_set_params(context, parameters.data()) ==
                             1 &&
                         EVP_PKEY_generate(context, &key) == 1;
  EVP_PKEY_CTX_free(context);
  if (!generated)
    return nullptr;
  try {
    return std::unique_ptr<EphemeralKey>{new EphemeralKey{key}};
  } catch (...) {
    EVP_PKEY_free(key);
    return nullptr;
  }
}

EphemeralKey::~EphemeralKey() {
  EVP_PKEY_free(static_cast<EVP_PKEY *>(key_));
}

Status EphemeralKey::public_value(std::span<std::uint8_t> output) const noexcept {
  if (output.size() < group_19_public_octets)
    return Status::output_too_small;
  std::array<std::uint8_t, group_19_public_octets + 1U> encoded{};
  std::size_t encoded_octets{};
  if (EVP_PKEY_get_octet_string_param(
          static_cast<EVP_PKEY *>(key_), OSSL_PKEY_PARAM_PUB_KEY,
          encoded.data(), encoded.size(), &encoded_octets) != 1 ||
      encoded_octets != encoded.size() || encoded[0U] != 0x04U)
    return Status::provider_failure;
  std::copy(encoded.begin() + 1U, encoded.end(), output.begin());
  return Status::ok;
}

Status EphemeralKey::derive(
    std::span<const std::uint8_t> peer_public_value,
    std::span<std::uint8_t> shared_secret_output) const noexcept {
  if (peer_public_value.size() != group_19_public_octets)
    return Status::invalid_peer_value;
  if (shared_secret_output.size() < group_19_secret_octets)
    return Status::output_too_small;
  auto *peer = import_peer(peer_public_value);
  if (!peer)
    return Status::invalid_peer_value;
  auto *context =
      EVP_PKEY_CTX_new(static_cast<EVP_PKEY *>(key_), nullptr);
  std::size_t secret_octets = group_19_secret_octets;
  const bool derived = context && EVP_PKEY_derive_init(context) == 1 &&
                       EVP_PKEY_derive_set_peer(context, peer) == 1 &&
                       EVP_PKEY_derive(context, shared_secret_output.data(),
                                       &secret_octets) == 1 &&
                       secret_octets == group_19_secret_octets;
  EVP_PKEY_CTX_free(context);
  EVP_PKEY_free(peer);
  if (!derived) {
    OPENSSL_cleanse(shared_secret_output.data(), group_19_secret_octets);
    return Status::invalid_peer_value;
  }
  return Status::ok;
}

} // namespace router::ikev2::dh
