// RFC 2202 and RFC 4231 HMAC vectors verify shared routing digest arithmetic.
// Test-owned buffers exercise segmentation, output aliasing and failure safety.

#include "router/digest.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string_view>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
bool hex_equal(std::span<const std::uint8_t> bytes, std::string_view hex) {
  constexpr std::string_view digits = "0123456789abcdef";
  if (hex.size() != bytes.size() * 2U) return false;
  for (std::size_t i = 0U; i < bytes.size(); ++i)
    if (digits[bytes[i] >> 4U] != hex[i * 2U] || digits[bytes[i] & 0x0fU] != hex[i * 2U + 1U])
      return false;
  return true;
}
}

void digest_tests() {
  using namespace router::crypto;
  const std::array<std::uint8_t, 8U> message{'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
  const std::array segments{std::span(message).first(3U), std::span(message).subspan(3U)};
  const std::array<std::string_view, 3U> expected{
    "9294727a3638bb1c13f48ef8158bfc9d", "b617318655057264e28bc0b6fb378c8ef146be00",
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"};
  std::array<std::uint8_t, 20U> key{};
  key.fill(0x0bU);
  std::size_t vector{};
  for (const auto algorithm : {DigestAlgorithm::md5, DigestAlgorithm::sha1, DigestAlgorithm::sha256}) {
    std::array<std::uint8_t, 32U> output{};
    const auto value = std::span(output).first(digest_octets(algorithm));
    const auto selected_key = std::span(key).first(algorithm == DigestAlgorithm::md5 ? 16U : 20U);
    require(hmac(algorithm, KeyNormalization::rfc2104, selected_key, segments, value) &&
              hex_equal(value, expected[vector++]), "shared RFC HMAC vector failed");
  }
  const std::array<std::uint8_t, 3U> abc{'a', 'b', 'c'};
  const std::array input{std::span<const std::uint8_t>(abc)};
  std::array<std::uint8_t, 32U> output{};
  require(digest(DigestAlgorithm::sha256, input, output) &&
            hex_equal(output, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
          "shared SHA-256 vector failed");
  const auto unchanged = output;
  require(!digest(static_cast<DigestAlgorithm>(255U), input, output) && output == unchanged &&
            !hmac(DigestAlgorithm::md5, KeyNormalization::rfc2104, key, input, output) && output == unchanged,
          "shared digest failure mutated output");
  std::copy(abc.begin(), abc.end(), output.begin());
  const std::array alias{std::span<const std::uint8_t>(output).first(3U)};
  require(digest(DigestAlgorithm::sha256, alias, output) && output == unchanged,
          "shared digest output alias corrupted input");
}
