// RFC 5282 AES-GCM processing for IKEv2 Encrypted Payloads. Unlike ESP, the
// associated data is the complete IKE prefix and plaintext padding has no
// alignment requirement. Authentication succeeds before padding is inspected.

#include "router/ikev2_aes_gcm.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <limits>

namespace router::ikev2::aes_gcm {
namespace {

constexpr std::size_t iv_octets{8U};
constexpr std::size_t nonce_octets{12U};
constexpr std::size_t tag_octets{16U};

std::array<std::uint8_t, nonce_octets>
make_nonce(const std::array<std::uint8_t, 4U> &salt,
           std::uint64_t iv) noexcept {
  std::array<std::uint8_t, nonce_octets> nonce{};
  std::copy(salt.begin(), salt.end(), nonce.begin());
  for (std::size_t index = 0U; index < iv_octets; ++index)
    nonce[4U + index] = static_cast<std::uint8_t>(
        iv >> ((iv_octets - index - 1U) * 8U));
  return nonce;
}

std::uint64_t read_iv(std::span<const std::uint8_t> bytes) noexcept {
  std::uint64_t value{};
  for (std::size_t index = 0U; index < iv_octets; ++index)
    value = value << 8U | bytes[index];
  return value;
}

void write_iv(std::span<std::uint8_t> bytes, std::uint64_t value) noexcept {
  for (std::size_t index = 0U; index < iv_octets; ++index)
    bytes[index] = static_cast<std::uint8_t>(
        value >> ((iv_octets - index - 1U) * 8U));
}

void cleanse(std::span<std::uint8_t> bytes) noexcept {
  if (!bytes.empty())
    OPENSSL_cleanse(bytes.data(), bytes.size());
}

bool provider_length(std::size_t octets) noexcept {
  return octets <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

} // namespace

Engine::Engine(void *context, const KeyMaterial &material) noexcept
    : context_(context), material_(material) {}

std::unique_ptr<Engine> Engine::create(const KeyMaterial &material) noexcept {
  if (material.key_octets != 16U && material.key_octets != 24U &&
      material.key_octets != 32U)
    return nullptr;
  auto *context = EVP_CIPHER_CTX_new();
  if (!context)
    return nullptr;
  try {
    return std::unique_ptr<Engine>{new Engine{context, material}};
  } catch (...) {
    EVP_CIPHER_CTX_free(context);
    return nullptr;
  }
}

Engine::~Engine() {
  EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(context_));
  OPENSSL_cleanse(material_.key.data(), material_.key.size());
  OPENSSL_cleanse(material_.salt.data(), material_.salt.size());
}

const void *Engine::cipher() const noexcept {
  switch (material_.key_octets) {
  case 16U:
    return EVP_aes_128_gcm();
  case 24U:
    return EVP_aes_192_gcm();
  case 32U:
    return EVP_aes_256_gcm();
  default:
    return nullptr;
  }
}

ProtectResult Engine::protect(
    std::uint64_t unique_iv, std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> plaintext_payloads,
    std::span<const std::uint8_t> padding,
    std::span<std::uint8_t> output) noexcept {
  if (unique_iv == 0U || padding.size() > 255U || !context_ || !cipher() ||
      !provider_length(associated_data.size()) ||
      !provider_length(plaintext_payloads.size()) ||
      !provider_length(padding.size()))
    return {.status = Status::invalid_argument};
  const auto plaintext_octets =
      plaintext_payloads.size() + padding.size() + 1U;
  const auto required = iv_octets + plaintext_octets + tag_octets;
  if (output.size() < required)
    return {.status = Status::output_too_small};

  auto *context = static_cast<EVP_CIPHER_CTX *>(context_);
  const auto nonce = make_nonce(material_.salt, unique_iv);
  write_iv(output, unique_iv);
  if (EVP_EncryptInit_ex(context, static_cast<const EVP_CIPHER *>(cipher()),
                         nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(context, nullptr, nullptr, material_.key.data(),
                         nonce.data()) != 1) {
    cleanse(output.first(required));
    return {.status = Status::provider_failure};
  }
  int written{};
  if ((!associated_data.empty() &&
       EVP_EncryptUpdate(context, nullptr, &written, associated_data.data(),
                         static_cast<int>(associated_data.size())) != 1)) {
    cleanse(output.first(required));
    return {.status = Status::provider_failure};
  }
  auto ciphertext = output.subspan(iv_octets, plaintext_octets);
  std::size_t offset{};
  const auto encrypt_segment = [&](std::span<const std::uint8_t> input) {
    if (input.empty())
      return true;
    int produced{};
    if (EVP_EncryptUpdate(context, ciphertext.data() + offset, &produced,
                          input.data(), static_cast<int>(input.size())) != 1 ||
        produced != static_cast<int>(input.size()))
      return false;
    offset += static_cast<std::size_t>(produced);
    return true;
  };
  const std::uint8_t pad_length = static_cast<std::uint8_t>(padding.size());
  if (!encrypt_segment(plaintext_payloads) || !encrypt_segment(padding) ||
      !encrypt_segment(std::span{&pad_length, 1U}) ||
      EVP_EncryptFinal_ex(context, ciphertext.data() + offset, &written) != 1 ||
      written != 0 ||
      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(tag_octets),
                          output.data() + iv_octets + plaintext_octets) != 1) {
    cleanse(output.first(required));
    return {.status = Status::provider_failure};
  }
  return {.status = Status::ok, .encrypted_body_octets = required};
}

UnprotectResult Engine::unprotect(
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> encrypted_body,
    std::span<std::uint8_t> plaintext_output) noexcept {
  if (!context_ || !cipher() || encrypted_body.size() < iv_octets + 1U +
                                                         tag_octets ||
      !provider_length(associated_data.size()))
    return {.status = Status::invalid_argument};
  const auto ciphertext_octets = encrypted_body.size() - iv_octets - tag_octets;
  if (!provider_length(ciphertext_octets))
    return {.status = Status::invalid_argument};
  if (plaintext_output.size() < ciphertext_octets)
    return {.status = Status::output_too_small};

  auto *context = static_cast<EVP_CIPHER_CTX *>(context_);
  const auto nonce = make_nonce(material_.salt, read_iv(encrypted_body));
  if (EVP_DecryptInit_ex(context, static_cast<const EVP_CIPHER *>(cipher()),
                         nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_DecryptInit_ex(context, nullptr, nullptr, material_.key.data(),
                         nonce.data()) != 1) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::provider_failure};
  }
  int written{};
  if ((!associated_data.empty() &&
       EVP_DecryptUpdate(context, nullptr, &written, associated_data.data(),
                         static_cast<int>(associated_data.size())) != 1) ||
      EVP_DecryptUpdate(context, plaintext_output.data(), &written,
                        encrypted_body.data() + iv_octets,
                        static_cast<int>(ciphertext_octets)) != 1 ||
      written != static_cast<int>(ciphertext_octets) ||
      EVP_CIPHER_CTX_ctrl(
          context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_octets),
          const_cast<std::uint8_t *>(encrypted_body.data() + iv_octets +
                                     ciphertext_octets)) != 1) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::provider_failure};
  }
  int final_octets{};
  if (EVP_DecryptFinal_ex(context, plaintext_output.data() + written,
                          &final_octets) != 1) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::authentication_failed};
  }
  const auto pad_length = plaintext_output[ciphertext_octets - 1U];
  if (static_cast<std::size_t>(pad_length) + 1U > ciphertext_octets) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::invalid_padding};
  }
  return {.status = Status::ok,
          .payload_octets = ciphertext_octets - pad_length - 1U};
}

} // namespace router::ikev2::aes_gcm
