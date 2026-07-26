// RFC-backed IPv6 text and prefix operations. This module owns no mutable
// state. Parsing rejects ambiguous input instead of repairing configuration,
// while formatting emits one deterministic RFC 5952 representation.

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>

namespace router::ip {
namespace {

struct WordList {
  std::array<std::uint16_t, 8> words{};
  std::uint8_t count{};
};

[[nodiscard]] std::optional<IpAddress>
parse_ipv4_address(std::string_view text) noexcept {
  IpAddress result;
  result.family = AddressFamily::ipv4;
  std::size_t begin{};
  for (std::size_t octet = 0; octet < 4U; ++octet) {
    const auto separator = octet == 3U ? std::string_view::npos
                                       : text.find('.', begin);
    const auto end = separator == std::string_view::npos ? text.size()
                                                         : separator;
    if (begin == end || (octet < 3U) != (separator != std::string_view::npos))
      return std::nullopt;
    unsigned value{};
    const auto conversion =
        std::from_chars(text.data() + begin, text.data() + end, value, 10);
    // Leading zeroes are valid decimal IPv4 text, but signs, hexadecimal and
    // trailing characters are not accepted by this canonical value boundary.
    if (conversion.ec != std::errc{} || conversion.ptr != text.data() + end ||
        value > 255U)
      return std::nullopt;
    result.bytes[octet] = static_cast<std::uint8_t>(value);
    begin = end + 1U;
  }
  return result;
}

[[nodiscard]] bool parse_ipv4_tail(std::string_view text,
                                   std::uint16_t &high,
                                   std::uint16_t &low) noexcept {
  // RFC 4291 permits a dotted-decimal tail in the final 32 bits. Each decimal
  // component is parsed independently so hexadecimal notation, signs and
  // empty components cannot be accepted by a permissive library conversion.
  std::array<std::uint8_t, 4> octets{};
  std::size_t start{};
  for (std::size_t index = 0; index < octets.size(); ++index) {
    const auto separator = text.find('.', start);
    const auto end = separator == std::string_view::npos ? text.size()
                                                         : separator;
    if (end == start || (index < 3) != (separator != std::string_view::npos))
      return false;
    unsigned value{};
    const auto conversion =
        std::from_chars(text.data() + start, text.data() + end, value, 10);
    if (conversion.ec != std::errc{} || conversion.ptr != text.data() + end ||
        value > std::numeric_limits<std::uint8_t>::max())
      return false;
    octets[index] = static_cast<std::uint8_t>(value);
    start = end + 1U;
  }
  high = static_cast<std::uint16_t>((octets[0] << 8U) | octets[1]);
  low = static_cast<std::uint16_t>((octets[2] << 8U) | octets[3]);
  return true;
}

[[nodiscard]] bool parse_words(std::string_view text, WordList &result,
                               bool allow_ipv4_tail) noexcept {
  if (text.empty())
    return true;
  std::size_t start{};
  while (start < text.size()) {
    const auto separator = text.find(':', start);
    const auto end = separator == std::string_view::npos ? text.size()
                                                         : separator;
    const auto token = text.substr(start, end - start);
    if (token.empty())
      return false;
    if (token.find('.') != std::string_view::npos) {
      // A dotted tail consumes two words and is legal only as the final token
      // of the complete IPv6 address.
      if (!allow_ipv4_tail || end != text.size() || result.count > 6)
        return false;
      std::uint16_t high{};
      std::uint16_t low{};
      if (!parse_ipv4_tail(token, high, low))
        return false;
      result.words[result.count++] = high;
      result.words[result.count++] = low;
    } else {
      if (token.size() > 4 || result.count == result.words.size())
        return false;
      unsigned value{};
      const auto conversion = std::from_chars(token.data(),
                                               token.data() + token.size(),
                                               value, 16);
      if (conversion.ec != std::errc{} ||
          conversion.ptr != token.data() + token.size() || value > 0xffffU)
        return false;
      result.words[result.count++] = static_cast<std::uint16_t>(value);
    }
    if (separator == std::string_view::npos)
      break;
    start = separator + 1U;
  }
  return true;
}

void write_word(std::string &result, std::uint16_t word) {
  // Four hexadecimal digits plus no terminator fit in this local buffer.
  // from_chars and to_chars keep locale out of wire-address formatting.
  std::array<char, 4> buffer{};
  const auto conversion = std::to_chars(buffer.data(),
                                         buffer.data() + buffer.size(), word,
                                         16);
  result.append(buffer.data(), conversion.ptr);
}

} // namespace

std::optional<Ipv6> parse_ipv6(std::string_view text) noexcept {
  // Zone identifiers belong to ScopedIpv6Address and are deliberately not
  // consumed here. Accepting '%' would lose the interface identity at this
  // value boundary and could later route a link-local packet incorrectly.
  if (text.empty() || text.find('%') != std::string_view::npos)
    return std::nullopt;

  const auto compression = text.find("::");
  if (compression != std::string_view::npos &&
      text.find("::", compression + 2U) != std::string_view::npos)
    return std::nullopt;

  WordList left;
  WordList right;
  if (compression == std::string_view::npos) {
    if (!parse_words(text, left, true) || left.count != 8)
      return std::nullopt;
  } else {
    const auto left_text = text.substr(0, compression);
    const auto right_text = text.substr(compression + 2U);
    // An IPv4 tail can occur only on the right side unless there is no
    // compression after it, which the grammar already prevents.
    if (!parse_words(left_text, left, false) ||
        !parse_words(right_text, right, true) ||
        left.count + right.count >= 8)
      return std::nullopt;
  }

  std::array<std::uint16_t, 8> words{};
  std::copy_n(left.words.begin(), left.count, words.begin());
  if (compression != std::string_view::npos) {
    std::copy_n(right.words.begin(), right.count,
                words.end() - right.count);
  }

  Ipv6 result{};
  for (std::size_t index = 0; index < words.size(); ++index) {
    result[index * 2U] = static_cast<std::uint8_t>(words[index] >> 8U);
    result[index * 2U + 1U] = static_cast<std::uint8_t>(words[index]);
  }
  return result;
}

std::optional<Ipv6Prefix> parse_ipv6_prefix(std::string_view text) noexcept {
  const auto separator = text.rfind('/');
  if (separator == std::string_view::npos || separator + 1U == text.size())
    return std::nullopt;
  const auto address = parse_ipv6(text.substr(0, separator));
  unsigned length{};
  const auto length_text = text.substr(separator + 1U);
  const auto conversion = std::from_chars(length_text.data(),
                                           length_text.data() + length_text.size(),
                                           length, 10);
  if (!address || conversion.ec != std::errc{} ||
      conversion.ptr != length_text.data() + length_text.size() ||
      length > ipv6_address_bits)
    return std::nullopt;
  const auto canonical = mask(*address, static_cast<std::uint8_t>(length));
  // Route and prefix configuration rejects host bits instead of normalizing
  // them invisibly. Interface-address parsing can pair an address with a
  // separate prefix length when host bits are expected.
  if (canonical != *address)
    return std::nullopt;
  return Ipv6Prefix{.network = canonical,
                    .length = static_cast<std::uint8_t>(length)};
}

std::optional<IpAddress> parse_ip_address(std::string_view text) noexcept {
  if (const auto ipv6 = parse_ipv6(text)) {
    IpAddress result;
    result.family = AddressFamily::ipv6;
    result.bytes = *ipv6;
    return result;
  }
  return parse_ipv4_address(text);
}

std::optional<IpPrefix> parse_ip_prefix(std::string_view text) noexcept {
  const auto separator = text.rfind('/');
  if (separator == std::string_view::npos || separator + 1U == text.size())
    return std::nullopt;
  const auto address = parse_ip_address(text.substr(0, separator));
  unsigned length{};
  const auto length_text = text.substr(separator + 1U);
  const auto conversion = std::from_chars(length_text.data(),
                                           length_text.data() + length_text.size(),
                                           length, 10);
  if (!address || conversion.ec != std::errc{} ||
      conversion.ptr != length_text.data() + length_text.size() ||
      length > address_bits(address->family))
    return std::nullopt;
  const auto canonical = mask(*address, static_cast<std::uint8_t>(length));
  // Policy list keys are prefixes rather than host addresses. Rejecting host
  // bits prevents two text forms from naming the same SR OS list element.
  if (canonical != *address)
    return std::nullopt;
  return IpPrefix{.network = canonical,
                  .length = static_cast<std::uint8_t>(length)};
}

std::string format_ipv6(const Ipv6 &address) {
  std::array<std::uint16_t, 8> words{};
  for (std::size_t index = 0; index < words.size(); ++index) {
    words[index] = static_cast<std::uint16_t>(
        (address[index * 2U] << 8U) | address[index * 2U + 1U]);
  }

  // RFC 5952 compresses the longest run of at least two zero words and uses
  // the first run when lengths tie. A single zero word must remain explicit.
  std::size_t best_start = words.size();
  std::size_t best_length{};
  for (std::size_t start = 0; start < words.size();) {
    if (words[start] != 0) {
      ++start;
      continue;
    }
    auto end = start;
    while (end < words.size() && words[end] == 0)
      ++end;
    if (end - start > best_length && end - start >= 2U) {
      best_start = start;
      best_length = end - start;
    }
    start = end;
  }

  std::string result;
  result.reserve(39);
  for (std::size_t index = 0; index < words.size();) {
    if (index == best_start) {
      result.append("::");
      index += best_length;
      continue;
    }
    if (!result.empty() && result.back() != ':')
      result.push_back(':');
    write_word(result, words[index]);
    ++index;
  }
  return result.empty() ? "::" : result;
}

std::string format_ipv6_prefix(const Ipv6Prefix &prefix) {
  return format_ipv6(prefix.network) + "/" + std::to_string(prefix.length);
}

std::string format_ip_address(const IpAddress &address) {
  if (address.family == AddressFamily::ipv6)
    return format_ipv6(address.bytes);
  return std::to_string(address.bytes[0]) + "." +
         std::to_string(address.bytes[1]) + "." +
         std::to_string(address.bytes[2]) + "." +
         std::to_string(address.bytes[3]);
}

std::string format_ip_prefix(const IpPrefix &prefix) {
  return format_ip_address(prefix.network) + "/" +
         std::to_string(prefix.length);
}

IpAddress mask(const IpAddress &address, std::uint8_t length) noexcept {
  IpAddress result = address;
  const auto maximum = address_bits(address.family);
  if (length >= maximum)
    return result;
  const auto complete_bytes = static_cast<std::size_t>(length / 8U);
  const auto remainder = static_cast<std::uint8_t>(length % 8U);
  if (remainder)
    result.bytes[complete_bytes] &=
        static_cast<std::uint8_t>(0xffU << (8U - remainder));
  const auto first_zero = complete_bytes + (remainder ? 1U : 0U);
  std::fill(result.bytes.begin() + static_cast<std::ptrdiff_t>(first_zero),
            result.bytes.begin() +
                static_cast<std::ptrdiff_t>(address_octets(address.family)),
            0U);
  // IPv4 values must retain the shared-value invariant even when the caller
  // supplied a malformed object rather than one produced by the parser.
  if (address.family == AddressFamily::ipv4)
    std::fill(result.bytes.begin() + 4, result.bytes.end(), 0U);
  return result;
}

bool contains(const IpPrefix &prefix, const IpAddress &address) noexcept {
  return prefix.network.family == address.family &&
         prefix.length <= address_bits(address.family) &&
         mask(address, prefix.length) == prefix.network;
}

Ipv6 mask(const Ipv6 &address, std::uint8_t length) noexcept {
  Ipv6 result = address;
  if (length >= ipv6_address_bits)
    return result;
  const auto complete_bytes = static_cast<std::size_t>(length / 8U);
  const auto remainder = static_cast<std::uint8_t>(length % 8U);
  if (remainder != 0) {
    result[complete_bytes] &=
        static_cast<std::uint8_t>(0xffU << (8U - remainder));
  }
  const auto zero_start = complete_bytes + (remainder == 0 ? 0U : 1U);
  std::fill(result.begin() + static_cast<std::ptrdiff_t>(zero_start),
            result.end(), std::uint8_t{0});
  return result;
}

bool contains(const Ipv6Prefix &prefix, const Ipv6 &address) noexcept {
  if (prefix.length > ipv6_address_bits)
    return false;
  return mask(address, prefix.length) == prefix.network;
}

Ipv6 solicited_node_multicast(const Ipv6 &unicast) noexcept {
  // RFC 4291 fixes ff02::1:ff00:0/104 and copies the low 24 unicast bits.
  Ipv6 result{0xff, 0x02, 0, 0, 0, 0, 0, 0,
              0,    0,    0, 0x01, 0xff, 0, 0, 0};
  std::copy_n(unicast.end() - 3, 3, result.end() - 3);
  return result;
}

Ipv6 link_local_from_mac(
    const std::array<std::uint8_t, 6> &mac) noexcept {
  // fe80::/64 supplies the link-local prefix. The interface identifier keeps
  // MAC octet order, inserts ff:fe in the middle and toggles bit 1 of the
  // first octet as specified for modified EUI-64 identifiers.
  Ipv6 result{0xfe, 0x80};
  result[8] = static_cast<std::uint8_t>(mac[0] ^ 0x02U);
  result[9] = mac[1];
  result[10] = mac[2];
  result[11] = 0xff;
  result[12] = 0xfe;
  result[13] = mac[3];
  result[14] = mac[4];
  result[15] = mac[5];
  return result;
}

std::optional<Ipv6>
address_from_eui64(const Ipv6 &prefix, std::uint8_t prefix_length,
                   const std::array<std::uint8_t, 6> &mac) noexcept {
  if (prefix_length != 64U)
    return std::nullopt;
  auto result = mask(prefix, prefix_length);
  const auto identifier = link_local_from_mac(mac);
  std::copy(identifier.begin() + 8, identifier.end(), result.begin() + 8);
  return result;
}

} // namespace router::ip
