// RFC 4106 AES-GCM-ESP using a reusable OpenSSL EVP context. The fixed packet
// expansion is SPI(4), sequence(4), explicit IV(8), minimal ESP trailer(2 to 5)
// and the required full ICV(16). Plaintext is released only after tag and
// deterministic ESP padding validation both succeed.

#include "router/ipsec_esp_gcm.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <limits>

namespace router::ipsec::esp_gcm {
namespace {

constexpr std::size_t esp_header_octets{8U};
constexpr std::size_t explicit_iv_octets{8U};
constexpr std::size_t nonce_octets{12U};
constexpr std::size_t full_icv_octets{16U};

void put_u32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

std::array<std::uint8_t, nonce_octets>
nonce(const std::array<std::uint8_t, 4> &salt,
      std::uint64_t explicit_iv) noexcept {
  std::array<std::uint8_t, nonce_octets> result{};
  std::copy(salt.begin(), salt.end(), result.begin());
  for (std::size_t index = 0U; index < explicit_iv_octets; ++index) {
    result[4U + index] = static_cast<std::uint8_t>(
        explicit_iv >> ((explicit_iv_octets - 1U - index) * 8U));
  }
  return result;
}

std::array<std::uint8_t, 12>
additional_data(std::uint32_t spi, std::uint64_t sequence) noexcept {
  std::array<std::uint8_t, 12> result{};
  put_u32(result, 0U, spi);
  put_u32(result, 4U, static_cast<std::uint32_t>(sequence >> 32U));
  put_u32(result, 8U, static_cast<std::uint32_t>(sequence));
  return result;
}

bool sequence_valid(std::uint64_t sequence, bool esn) noexcept {
  if (sequence == 0U)
    return false;
  return esn || sequence <= std::numeric_limits<std::uint32_t>::max();
}

void cleanse(std::span<std::uint8_t> output) noexcept {
  if (!output.empty())
    OPENSSL_cleanse(output.data(), output.size());
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

ProtectResult Engine::protect(std::uint32_t spi, std::uint64_t sequence,
                              bool esn, std::uint8_t next_header,
                              std::span<const std::uint8_t> plaintext,
                              std::span<std::uint8_t> output) noexcept {
  if (spi == 0U || !sequence_valid(sequence, esn) || !context_ || !cipher())
    return {.status = Status::invalid_argument};
  if (plaintext.size() >
      static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return {.status = Status::invalid_argument};

  // RFC 4106 recommends minimum padding. ESP alignment is four octets when the
  // transform has no stronger block boundary requirement.
  const auto padding = (4U - ((plaintext.size() + 2U) % 4U)) % 4U;
  const auto encrypted_octets = plaintext.size() + padding + 2U;
  const auto required = esp_header_octets + explicit_iv_octets +
                        encrypted_octets + full_icv_octets;
  if (output.size() < required)
    return {.status = Status::output_too_small};

  put_u32(output, 0U, spi);
  put_u32(output, 4U, static_cast<std::uint32_t>(sequence));
  for (std::size_t index = 0U; index < explicit_iv_octets; ++index) {
    output[esp_header_octets + index] = static_cast<std::uint8_t>(
        sequence >> ((explicit_iv_octets - 1U - index) * 8U));
  }

  const auto nonce_bytes = nonce(material_.salt, sequence);
  const auto aad = additional_data(spi, sequence);
  // Non-ESN AAD is SPI followed by low32. It is not the first eight bytes of
  // the ESN array because that array stores SPI, high32, low32.
  std::array<std::uint8_t, 8> short_aad{};
  put_u32(short_aad, 0U, spi);
  put_u32(short_aad, 4U, static_cast<std::uint32_t>(sequence));

  auto *context = static_cast<EVP_CIPHER_CTX *>(context_);
  int written{};
  int produced{};
  const auto *selected = static_cast<const EVP_CIPHER *>(cipher());
  if (EVP_EncryptInit_ex(context, selected, nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce_bytes.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(context, nullptr, nullptr, material_.key.data(),
                         nonce_bytes.data()) != 1 ||
      EVP_EncryptUpdate(context, nullptr, &written,
                        esn ? aad.data() : short_aad.data(),
                        static_cast<int>(esn ? aad.size()
                                             : short_aad.size())) != 1 ||
      EVP_EncryptUpdate(context,
                        output.data() + esp_header_octets + explicit_iv_octets,
                        &written, plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1) {
    cleanse(output.first(required));
    return {.status = Status::provider_failure};
  }
  produced = written;

  std::array<std::uint8_t, 5> trailer{};
  for (std::size_t index = 0U; index < padding; ++index)
    trailer[index] = static_cast<std::uint8_t>(index + 1U);
  trailer[padding] = static_cast<std::uint8_t>(padding);
  trailer[padding + 1U] = next_header;
  if (EVP_EncryptUpdate(
          context,
          output.data() + esp_header_octets + explicit_iv_octets + produced,
          &written, trailer.data(), static_cast<int>(padding + 2U)) != 1) {
    cleanse(output.first(required));
    return {.status = Status::provider_failure};
  }
  produced += written;
  if (EVP_EncryptFinal_ex(
          context,
          output.data() + esp_header_octets + explicit_iv_octets + produced,
          &written) != 1 ||
      EVP_CIPHER_CTX_ctrl(
          context, EVP_CTRL_GCM_GET_TAG, static_cast<int>(full_icv_octets),
          output.data() + required - full_icv_octets) != 1) {
    cleanse(output.first(required));
    return {.status = Status::provider_failure};
  }
  return {.status = Status::ok, .packet_octets = required};
}

UnprotectResult Engine::unprotect(
    std::uint64_t reconstructed_sequence, bool esn,
    std::span<const std::uint8_t> packet,
    std::span<std::uint8_t> plaintext_output) noexcept {
  if (!sequence_valid(reconstructed_sequence, esn) || !context_ || !cipher() ||
      packet.size() < esp_header_octets + explicit_iv_octets + 2U +
                          full_icv_octets)
    return {.status = Status::invalid_argument};
  const auto spi = read_u32(packet, 0U);
  const auto low = read_u32(packet, 4U);
  if (spi == 0U || low != static_cast<std::uint32_t>(reconstructed_sequence))
    return {.status = Status::invalid_argument};
  const auto ciphertext_octets = packet.size() - esp_header_octets -
                                  explicit_iv_octets - full_icv_octets;
  if (ciphertext_octets >
          static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      plaintext_output.size() < ciphertext_octets)
    return {.status = Status::output_too_small};

  std::uint64_t explicit_iv{};
  for (std::size_t index = 0U; index < explicit_iv_octets; ++index) {
    explicit_iv = (explicit_iv << 8U) |
                  packet[esp_header_octets + index];
  }
  const auto nonce_bytes = nonce(material_.salt, explicit_iv);
  const auto aad = additional_data(spi, reconstructed_sequence);
  std::array<std::uint8_t, 8> short_aad{};
  put_u32(short_aad, 0U, spi);
  put_u32(short_aad, 4U, low);

  auto *context = static_cast<EVP_CIPHER_CTX *>(context_);
  const auto *selected = static_cast<const EVP_CIPHER *>(cipher());
  int written{};
  int produced{};
  if (EVP_DecryptInit_ex(context, selected, nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce_bytes.size()), nullptr) != 1 ||
      EVP_DecryptInit_ex(context, nullptr, nullptr, material_.key.data(),
                         nonce_bytes.data()) != 1 ||
      EVP_DecryptUpdate(context, nullptr, &written,
                        esn ? aad.data() : short_aad.data(),
                        static_cast<int>(esn ? aad.size()
                                             : short_aad.size())) != 1 ||
      EVP_DecryptUpdate(
          context, plaintext_output.data(), &written,
          packet.data() + esp_header_octets + explicit_iv_octets,
          static_cast<int>(ciphertext_octets)) != 1) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::provider_failure};
  }
  produced = written;
  if (EVP_CIPHER_CTX_ctrl(
          context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(full_icv_octets),
          const_cast<std::uint8_t *>(packet.data() + packet.size() -
                                    full_icv_octets)) != 1 ||
      EVP_DecryptFinal_ex(context, plaintext_output.data() + produced,
                          &written) != 1) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::authentication_failed};
  }
  produced += written;
  if (produced < 2) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::invalid_padding};
  }
  const auto padding = plaintext_output[static_cast<std::size_t>(produced) - 2U];
  if (static_cast<std::size_t>(padding) + 2U >
      static_cast<std::size_t>(produced)) {
    cleanse(plaintext_output.first(ciphertext_octets));
    return {.status = Status::invalid_padding};
  }
  const auto padding_begin = static_cast<std::size_t>(produced) - 2U - padding;
  for (std::size_t index = 0U; index < padding; ++index) {
    if (plaintext_output[padding_begin + index] != index + 1U) {
      cleanse(plaintext_output.first(ciphertext_octets));
      return {.status = Status::invalid_padding};
    }
  }
  return {.status = Status::ok,
          .plaintext_octets = padding_begin,
          .next_header = plaintext_output[static_cast<std::size_t>(produced) - 1U],
          .spi = spi};
}

} // namespace router::ipsec::esp_gcm
