// Shared RFC 8484 DNS message and GET parameter codec. Keeping this logic
// below HTTP/2 and HTTP/3 prevents the two transports from accepting subtly
// different spellings of the same DoH request.
// Source: ietf.doh.rfc8484

#include "router/doh_message.hpp"

#include "router/dns_packet.hpp"

#include <array>

namespace router::doh {
namespace {

std::optional<std::uint8_t> base64url_value(char value) noexcept {
  if (value >= 'A' && value <= 'Z')
    return static_cast<std::uint8_t>(value - 'A');
  if (value >= 'a' && value <= 'z')
    return static_cast<std::uint8_t>(value - 'a' + 26);
  if (value >= '0' && value <= '9')
    return static_cast<std::uint8_t>(value - '0' + 52);
  if (value == '-')
    return 62U;
  if (value == '_')
    return 63U;
  return std::nullopt;
}

} // namespace

bool valid_dns_message(std::span<const std::uint8_t> message) noexcept {
  return message.size() >= packet::dns::header_octets &&
         message.size() <= packet::dns::maximum_message_octets;
}

std::optional<std::string>
encode_query_parameter(std::span<const std::uint8_t> message) noexcept {
  static constexpr std::string_view alphabet{
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"};
  try {
    std::string output;
    output.reserve((message.size() * 4U + 2U) / 3U);
    std::size_t offset{};
    while (message.size() - offset >= 3U) {
      const auto bits =
          (static_cast<std::uint32_t>(message[offset]) << 16U) |
          (static_cast<std::uint32_t>(message[offset + 1U]) << 8U) |
          message[offset + 2U];
      output.push_back(alphabet[(bits >> 18U) & 0x3fU]);
      output.push_back(alphabet[(bits >> 12U) & 0x3fU]);
      output.push_back(alphabet[(bits >> 6U) & 0x3fU]);
      output.push_back(alphabet[bits & 0x3fU]);
      offset += 3U;
    }
    const auto remaining = message.size() - offset;
    if (remaining == 1U) {
      const auto bits = static_cast<std::uint32_t>(message[offset]) << 16U;
      output.push_back(alphabet[(bits >> 18U) & 0x3fU]);
      output.push_back(alphabet[(bits >> 12U) & 0x3fU]);
    } else if (remaining == 2U) {
      const auto bits =
          (static_cast<std::uint32_t>(message[offset]) << 16U) |
          (static_cast<std::uint32_t>(message[offset + 1U]) << 8U);
      output.push_back(alphabet[(bits >> 18U) & 0x3fU]);
      output.push_back(alphabet[(bits >> 12U) & 0x3fU]);
      output.push_back(alphabet[(bits >> 6U) & 0x3fU]);
    }
    return output;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::vector<std::uint8_t>>
decode_query_parameter(std::string_view value) noexcept {
  // A one-character tail cannot encode a complete octet. RFC 4648 padding is
  // deliberately absent from the RFC 8484 URI representation, and '=' is
  // consequently rejected by base64url_value.
  if (value.size() % 4U == 1U)
    return std::nullopt;
  try {
    std::vector<std::uint8_t> output;
    output.reserve(value.size() * 3U / 4U);
    std::size_t offset{};
    while (value.size() - offset >= 4U) {
      std::array<std::uint8_t, 4U> values{};
      for (std::size_t index = 0U; index < values.size(); ++index) {
        const auto decoded = base64url_value(value[offset + index]);
        if (!decoded)
          return std::nullopt;
        values[index] = *decoded;
      }
      const auto bits = (static_cast<std::uint32_t>(values[0U]) << 18U) |
                        (static_cast<std::uint32_t>(values[1U]) << 12U) |
                        (static_cast<std::uint32_t>(values[2U]) << 6U) |
                        values[3U];
      output.push_back(static_cast<std::uint8_t>(bits >> 16U));
      output.push_back(static_cast<std::uint8_t>(bits >> 8U));
      output.push_back(static_cast<std::uint8_t>(bits));
      offset += 4U;
    }
    const auto remaining = value.size() - offset;
    if (remaining != 0U) {
      const auto first = base64url_value(value[offset]);
      const auto second = base64url_value(value[offset + 1U]);
      if (!first || !second)
        return std::nullopt;
      std::uint32_t bits = (static_cast<std::uint32_t>(*first) << 18U) |
                           (static_cast<std::uint32_t>(*second) << 12U);
      // Rejecting non-zero unused bits gives one canonical cache key for one
      // DNS query instead of accepting aliases with the same decoded bytes.
      if (remaining == 2U && (*second & 0x0fU) != 0U)
        return std::nullopt;
      if (remaining == 3U) {
        const auto third = base64url_value(value[offset + 2U]);
        if (!third || (*third & 0x03U) != 0U)
          return std::nullopt;
        bits |= static_cast<std::uint32_t>(*third) << 6U;
      }
      output.push_back(static_cast<std::uint8_t>(bits >> 16U));
      if (remaining == 3U)
        output.push_back(static_cast<std::uint8_t>(bits >> 8U));
    }
    return output;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace router::doh
