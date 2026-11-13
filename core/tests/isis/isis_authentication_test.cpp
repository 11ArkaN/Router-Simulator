// Independent Python hashlib/hmac fixtures cover complete fixed P2P packets.
// Test-owned keys and packets exercise exclusion fields, padding, wrong keys
// and structural failures without any protocol acceptance side effects.

#include "router/isis_authentication.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_authentication_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  const SystemId source{1U, 2U, 3U, 4U, 5U, 6U};
  std::array<std::uint8_t, 40U> secret{};
  secret.fill('K');
  const std::array<std::uint8_t, 16U> md5{0xd9U, 0x50U, 0x4eU, 0x7aU, 0x42U, 0x5bU, 0x71U, 0x5eU,
    0x74U, 0x72U, 0xe6U, 0x15U, 0xd5U, 0x38U, 0xcdU, 0xb7U};
  const std::array<std::uint8_t, 20U> sha1{0xd0U, 0xddU, 0x79U, 0x7eU, 0x94U, 0xcaU, 0xd9U, 0xdcU,
    0x01U, 0x8dU, 0x60U, 0x6eU, 0x26U, 0x4eU, 0x9aU, 0xb5U, 0xcfU, 0x97U, 0xd0U, 0xf9U};
  const std::array<std::uint8_t, 32U> sha256{0xc9U, 0xacU, 0x8cU, 0x1fU, 0x7bU, 0xefU, 0xabU, 0x38U,
    0xa8U, 0x9aU, 0xcaU, 0x1cU, 0x90U, 0xbdU, 0x24U, 0xf6U, 0x56U, 0xe8U, 0x1eU, 0xecU, 0xf5U,
    0xc1U, 0xb9U, 0xc5U, 0x3cU, 0x9fU, 0x28U, 0x38U, 0xc0U, 0xf7U, 0xb6U, 0xa9U};
  for (const auto method : {AuthenticationMethod::password, AuthenticationMethod::hmac_md5,
                           AuthenticationMethod::hmac_sha1, AuthenticationMethod::hmac_sha256}) {
    const AuthenticationKey key{method, 0x1234U, secret};
    std::array<std::uint8_t, 512U> tlv_bytes{};
    TlvWriter writer(tlv_bytes);
    require(append_authentication(writer, key), "IS-IS authentication TLV encoding failed");
    std::array<std::uint8_t, 1024U> output{};
    const auto hello = encode_hello(output,
        {PduType::point_to_point_hello, source, 30U, 3U, 7U}, writer.bytes());
    require(hello.has_value(), "IS-IS authentication Hello fixture failed");
    auto wire = std::span(output).first(hello->size());
    // Independent fixtures use explicit ID Length 6, not its equivalent 0.
    wire[3U] = 6U;
    require(finalize_authentication(wire, key, source) == AuthenticationError::none &&
              verify_authentication(wire, key) == AuthenticationError::none,
            "IS-IS authentication Hello failed");
    const auto expected = method == AuthenticationMethod::hmac_md5 ? std::span<const std::uint8_t>(md5) :
        method == AuthenticationMethod::hmac_sha1 ? std::span<const std::uint8_t>(sha1) :
        method == AuthenticationMethod::hmac_sha256 ? std::span<const std::uint8_t>(sha256) :
        std::span<const std::uint8_t>(secret);
    require(std::equal(expected.begin(), expected.end(), wire.end() - expected.size()),
            "IS-IS independent authentication digest mismatch");
    const auto original = output;
    auto other_source = source;
    other_source[0U] ^= 1U;
    require(finalize_authentication(wire, key, other_source) == AuthenticationError::originator_mismatch &&
              output == original, "IS-IS authentication identity failure mutated output");
    wire.back() ^= 1U;
    require(verify_authentication(wire, key) == AuthenticationError::mismatch,
            "IS-IS accepted corrupted authentication data");
    wire.back() ^= 1U;
    auto other_secret = secret;
    other_secret[0U] ^= 1U;
    require(verify_authentication(wire, {method, key.id, other_secret}) == AuthenticationError::mismatch,
            "IS-IS accepted another authentication key");
    if (method == AuthenticationMethod::hmac_sha1 || method == AuthenticationMethod::hmac_sha256)
      require(verify_authentication(wire, {method, 1U, secret}) == AuthenticationError::wrong_key_id,
              "IS-IS accepted another security association");

    LspInput lsp_input{PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U};
    const auto lsp_wire = encode_lsp(output, lsp_input, writer.bytes());
    require(lsp_wire.has_value(), "IS-IS authenticated LSP encoding failed");
    wire = std::span(output).first(lsp_wire->size());
    require(finalize_authentication(wire, key, source) == AuthenticationError::none,
            "IS-IS LSP authentication finalization failed");
    DecodeError error{};
    auto pdu = parse(wire, error);
    require(pdu && valid_lsp_checksum(*pdu) && verify_authentication(wire, key) == AuthenticationError::none,
            "IS-IS authentication/checksum ordering failed");
    wire[11U] ^= 1U;
    require(verify_authentication(wire, key) == AuthenticationError::none,
            "IS-IS authentication incorrectly covered LSP aging");
    if (method != AuthenticationMethod::password) {
      wire[24U] ^= 1U;
      require(verify_authentication(wire, key) == AuthenticationError::none && !valid_lsp_checksum(*pdu),
              "IS-IS checksum exclusion confused checksum verification");
      wire[20U] ^= 1U;
      require(verify_authentication(wire, key) == AuthenticationError::mismatch,
              "IS-IS authentication did not cover LSP sequence number");
    }
  }
  const AuthenticationKey key{AuthenticationMethod::hmac_sha256, 0x1234U, secret};
  std::array<std::uint8_t, 512U> options{};
  TlvWriter duplicate(options);
  require(append_authentication(duplicate, key) && append_authentication(duplicate, key),
          "IS-IS duplicate auth fixture failed");
  std::array<std::uint8_t, 512U> output{};
  auto encoded = encode_hello(output, {PduType::point_to_point_hello, source, 30U, 3U}, duplicate.bytes());
  require(encoded && verify_authentication(*encoded, key) == AuthenticationError::duplicate,
          "IS-IS accepted duplicate authentication TLVs");
  TlvWriter padded(options);
  require(append_authentication(padded, key) && padded.pad_to(100U), "IS-IS auth padding fixture failed");
  encoded = encode_hello(output, {PduType::point_to_point_hello, source, 30U, 3U}, padded.bytes());
  require(encoded && finalize_authentication(std::span(output).first(encoded->size()), key, source) ==
              AuthenticationError::none, "IS-IS padded authentication failed");
  output[encoded->size() - 1U] ^= 1U;
  require(verify_authentication(*encoded, key) == AuthenticationError::mismatch,
          "IS-IS authentication omitted Hello padding");
  TlvWriter checksum(options);
  const std::array<std::uint8_t, 2U> checksum_value{};
  require(append_authentication(checksum, key) && checksum.append(12U, checksum_value),
          "IS-IS checksum auth fixture failed");
  encoded = encode_snp(output, {PduType::psnp_l1, source}, checksum.bytes());
  require(encoded && verify_authentication(*encoded, key) == AuthenticationError::checksum_tlv,
          "IS-IS cryptographic SNP accepted optional checksum TLV");
  encoded = encode_snp(output, {PduType::psnp_l1, source}, {});
  require(encoded && verify_authentication(*encoded, key) == AuthenticationError::missing,
          "IS-IS missing authentication was accepted");
}
