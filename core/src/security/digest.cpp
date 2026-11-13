// Shared segmented routing-protocol hashing. All temporary state belongs to
// one invocation. SHA-256 depends on its value helper, legacy digests on EVP;
// this layer has no packet, protocol-process, keychain or runtime dependency.
// Source: ietf.crypto.hmac.rfc2104

#include "router/digest.hpp"
#include "router/sha256.hpp"

#include <algorithm>
#include <array>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace router::crypto {
namespace {
constexpr std::size_t block_octets = 64U;
constexpr std::size_t maximum_digest = 32U;

[[nodiscard]] bool calculate(DigestAlgorithm algorithm,
    std::span<const std::uint8_t> prefix,
    std::span<const std::span<const std::uint8_t>> segments,
    std::span<std::uint8_t> output) noexcept {
  if (algorithm == DigestAlgorithm::sha256) {
    Sha256 context;
    context.update(prefix);
    for (const auto segment : segments) context.update(segment);
    const auto value = context.finish();
    std::copy(value.begin(), value.end(), output.begin());
    return true;
  }
  auto *context = EVP_MD_CTX_new();
  if (!context) return false;
  const auto *provider = algorithm == DigestAlgorithm::md5 ? EVP_md5() : EVP_sha1();
  bool valid = EVP_DigestInit_ex(context, provider, nullptr) == 1 &&
               EVP_DigestUpdate(context, prefix.data(), prefix.size()) == 1;
  for (const auto segment : segments)
    valid = valid && EVP_DigestUpdate(context, segment.data(), segment.size()) == 1;
  unsigned written{};
  valid = valid && EVP_DigestFinal_ex(context, output.data(), &written) == 1 && written == output.size();
  EVP_MD_CTX_free(context);
  return valid;
}

template <std::size_t Size> struct SecretBytes {
  std::array<std::uint8_t, Size> bytes{};
  ~SecretBytes() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
}

bool digest(DigestAlgorithm algorithm,
    std::span<const std::span<const std::uint8_t>> segments,
    std::span<std::uint8_t> output) noexcept {
  const auto size = digest_octets(algorithm);
  if (!size || output.size() != size) return false;
  SecretBytes<maximum_digest> staged;
  if (!calculate(algorithm, {}, segments, std::span(staged.bytes).first(size))) return false;
  std::copy_n(staged.bytes.begin(), size, output.begin());
  return true;
}

bool hmac(DigestAlgorithm algorithm, KeyNormalization normalization,
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> segments,
    std::span<std::uint8_t> output) noexcept {
  const auto size = digest_octets(algorithm);
  if (!size || output.size() != size ||
      (normalization != KeyNormalization::rfc2104 && normalization != KeyNormalization::digest_length))
    return false;
  SecretBytes<block_octets> normalized;
  const auto threshold = normalization == KeyNormalization::rfc2104 ? block_octets : size;
  if (key.size() > threshold) {
    const std::array input{key};
    if (!digest(algorithm, input, std::span(normalized.bytes).first(size))) return false;
  } else std::copy(key.begin(), key.end(), normalized.bytes.begin());
  SecretBytes<block_octets> inner_pad;
  SecretBytes<block_octets> outer_pad;
  for (std::size_t i = 0U; i < block_octets; ++i) {
    inner_pad.bytes[i] = static_cast<std::uint8_t>(normalized.bytes[i] ^ 0x36U);
    outer_pad.bytes[i] = static_cast<std::uint8_t>(normalized.bytes[i] ^ 0x5cU);
  }
  SecretBytes<maximum_digest> inner;
  const auto inner_value = std::span(inner.bytes).first(size);
  if (!calculate(algorithm, inner_pad.bytes, segments, inner_value)) return false;
  const std::array outer_segments{std::span<const std::uint8_t>(inner_value)};
  SecretBytes<maximum_digest> result;
  if (!calculate(algorithm, outer_pad.bytes, outer_segments, std::span(result.bytes).first(size))) return false;
  std::copy_n(result.bytes.begin(), size, output.begin());
  return true;
}

} // namespace router::crypto
