// RFC 5304 and 5310 authentication framing and canonical message segments.
// Temporary digest state is call-local. Protocol and keychain owners decide
// which key and PDU classes require checks, including updated purge policy.
// Source: ietf.isis.authentication.rfc5304
// Source: ietf.isis.authentication.rfc5310

#include "router/isis_authentication.hpp"
#include "router/digest.hpp"
#include "router/iso_checksum.hpp"

#include <algorithm>
#include <array>
#include <openssl/crypto.h>

namespace router::isis {
namespace {
using namespace packet::isis;
using Error = AuthenticationError;
using Method = AuthenticationMethod;

struct Layout {
  PduView pdu;
  std::size_t value_offset{};
  std::size_t value_size{};
  bool lsp{};
};

[[nodiscard]] std::size_t digest_size(Method method) noexcept {
  switch (method) {
  case Method::hmac_md5: return 16U;
  case Method::hmac_sha1: return 20U;
  case Method::hmac_sha256: return 32U;
  default: return 0U;
  }
}

[[nodiscard]] Error locate(std::span<const std::uint8_t> wire,
                            const AuthenticationKey &key, Layout &layout) noexcept {
  if (key.method > Method::hmac_sha256) return Error::invalid_method;
  DecodeError decode{};
  const auto parsed = parse(wire, decode);
  if (!parsed) return Error::malformed_pdu;
  layout.pdu = *parsed;
  layout.lsp = parsed->type == PduType::lsp_l1 || parsed->type == PduType::lsp_l2;
  TlvCursor cursor(parsed->tlvs);
  std::optional<TlvView> found;
  while (const auto tlv = cursor.next()) {
    if (tlv->code == 12U && !layout.lsp && key.method != Method::password)
      return Error::checksum_tlv;
    if (tlv->code != 10U) continue;
    if (found) return Error::duplicate;
    found = tlv;
  }
  if (!found) return Error::missing;
  const auto value = found->value;
  if (value.empty()) return Error::wrong_length;
  const bool sha = key.method == Method::hmac_sha1 || key.method == Method::hmac_sha256;
  const std::uint8_t type = key.method == Method::password ? 1U : sha ? 3U : 54U;
  if (value[0U] != type) return Error::wrong_type;
  const std::size_t prefix = sha ? 3U : 1U;
  const auto size = key.method == Method::password ? key.bytes.size() : digest_size(key.method);
  if ((key.method == Method::password && key.bytes.size() > 253U) || value.size() != prefix + size)
    return Error::wrong_length;
  if (sha && (static_cast<std::uint16_t>(value[1U]) << 8U | value[2U]) != key.id)
    return Error::wrong_key_id;
  layout.value_offset = static_cast<std::size_t>(value.data() - parsed->bytes.data()) + prefix;
  layout.value_size = size;
  return Error::none;
}

[[nodiscard]] bool calculate(const Layout &layout, const AuthenticationKey &key,
                              std::span<std::uint8_t> output) noexcept {
  std::array<std::uint8_t, 32U> replacement{};
  if (key.method != Method::hmac_md5) {
    constexpr std::array<std::uint8_t, 4U> apad{0x87U, 0x8fU, 0xe1U, 0xf3U};
    for (std::size_t i = 0U; i < layout.value_size; ++i) replacement[i] = apad[i % apad.size()];
  }
  const std::array<std::uint8_t, 2U> zero{};
  std::array<std::span<const std::uint8_t>, 7U> segments{};
  std::size_t count{};
  const auto wire = layout.pdu.bytes;
  std::size_t start{};
  if (layout.lsp) {
    segments[count++] = wire.first(10U);
    segments[count++] = zero;
    segments[count++] = wire.subspan(12U, 12U);
    segments[count++] = zero;
    start = 26U;
  }
  segments[count++] = wire.subspan(start, layout.value_offset - start);
  segments[count++] = std::span(replacement).first(layout.value_size);
  segments[count++] = wire.subspan(layout.value_offset + layout.value_size);
  const auto algorithm = key.method == Method::hmac_md5 ? crypto::DigestAlgorithm::md5 :
      key.method == Method::hmac_sha1 ? crypto::DigestAlgorithm::sha1 : crypto::DigestAlgorithm::sha256;
  return crypto::hmac(algorithm, key.method == Method::hmac_md5 ? crypto::KeyNormalization::rfc2104 :
      crypto::KeyNormalization::digest_length, key.bytes, std::span(segments).first(count), output);
}
}

bool append_authentication(TlvWriter &writer, const AuthenticationKey &key) noexcept {
  if (key.method > Method::hmac_sha256 || (key.method == Method::password && key.bytes.size() > 253U))
    return false;
  std::array<std::uint8_t, 254U> value{};
  if (key.method == Method::password) {
    value[0U] = 1U;
    std::copy(key.bytes.begin(), key.bytes.end(), value.begin() + 1U);
    const bool appended = writer.append(10U, std::span(value).first(1U + key.bytes.size()));
    OPENSSL_cleanse(value.data(), value.size());
    return appended;
  }
  const bool sha = key.method != Method::hmac_md5;
  value[0U] = sha ? 3U : 54U;
  if (sha) {
    value[1U] = static_cast<std::uint8_t>(key.id >> 8U);
    value[2U] = static_cast<std::uint8_t>(key.id);
  }
  return writer.append(10U, std::span(value).first((sha ? 3U : 1U) + digest_size(key.method)));
}

AuthenticationError finalize_authentication(std::span<std::uint8_t> wire,
    const AuthenticationKey &key, const SystemId &originator) noexcept {
  Layout layout;
  const auto error = locate(wire, key, layout);
  if (error != Error::none) return error;
  const auto type = layout.pdu.type;
  const auto source_offset = layout.lsp ? 12U :
      (type == PduType::lan_hello_l1 || type == PduType::lan_hello_l2 ||
       type == PduType::point_to_point_hello) ? 9U : 10U;
  if (!std::equal(originator.begin(), originator.end(), wire.begin() + source_offset))
    return Error::originator_mismatch;
  if (key.method == Method::password) {
    if (!key.bytes.empty() && CRYPTO_memcmp(wire.data() + layout.value_offset, key.bytes.data(), key.bytes.size()) != 0)
      return Error::mismatch;
  } else {
    std::array<std::uint8_t, 32U> digest{};
    const auto value = std::span(digest).first(layout.value_size);
    if (!calculate(layout, key, value)) return Error::provider_failure;
    std::copy(value.begin(), value.end(), wire.begin() + layout.value_offset);
    OPENSSL_cleanse(digest.data(), digest.size());
  }
  if (layout.lsp) {
    // Validated envelope bounds make insertion infallible after digest commit.
    const auto inserted = packet::iso::insert(wire.first(layout.pdu.bytes.size()).subspan(12U),
        12U, originator.size(), packet::iso::accumulate(originator));
    if (!inserted) return Error::malformed_pdu;
  }
  return Error::none;
}

AuthenticationError verify_authentication(std::span<const std::uint8_t> wire,
    const AuthenticationKey &key) noexcept {
  Layout layout;
  const auto error = locate(wire, key, layout);
  if (error != Error::none) return error;
  const auto received = layout.pdu.bytes.subspan(layout.value_offset, layout.value_size);
  if (key.method == Method::password)
    return received.empty() || CRYPTO_memcmp(received.data(), key.bytes.data(), received.size()) == 0 ? Error::none : Error::mismatch;
  std::array<std::uint8_t, 32U> digest{};
  const auto value = std::span(digest).first(layout.value_size);
  if (!calculate(layout, key, value)) return Error::provider_failure;
  const bool equal = CRYPTO_memcmp(received.data(), value.data(), value.size()) == 0;
  OPENSSL_cleanse(digest.data(), digest.size());
  return equal ? Error::none : Error::mismatch;
}

} // namespace router::isis
