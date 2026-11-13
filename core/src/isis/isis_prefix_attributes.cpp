// RFC 5130 and RFC 7794 prefix metadata codecs share bounded TLV framing.
// All state is caller-local. Complete values are staged before append so
// overlap or output refusal cannot publish a partial administrative tag list.

// Source: ietf.isis.prefix_metadata

#include "router/isis_prefix_attributes.hpp"

#include <algorithm>

namespace router::packet::isis {
namespace {
template <typename Value>
bool tags(TlvWriter &writer, std::span<const Value> input) noexcept {
  if (input.empty() || input.size() > 255U / sizeof(Value)) return false;
  std::array<std::uint8_t, 252U> bytes{};
  std::size_t index{};
  for (const auto value : input)
    for (std::size_t octet{}; octet < sizeof(Value); ++octet)
      bytes[index++] = static_cast<std::uint8_t>(value >> ((sizeof(Value) - octet - 1U) * 8U));
  return writer.append(static_cast<std::uint8_t>(sizeof(Value) == 4U ? 1U : 2U), std::span{bytes}.first(index));
}
bool valid_context(const ip::IpPrefix &prefix) noexcept {
  return (prefix.network.family == ip::AddressFamily::ipv4 || prefix.network.family == ip::AddressFamily::ipv6) &&
      prefix.length <= ip::address_bits(prefix.network.family);
}
}
AdministrativeTagCursor::AdministrativeTagCursor(TlvView option) noexcept
    : remaining_(option.value), width_(static_cast<std::uint8_t>(option.code == 1U ? 4U : option.code == 2U ? 8U : 0U)),
      valid_(width_ && !option.value.empty() && option.value.size() <= 255U && option.value.size() % width_ == 0U) {}
std::optional<AdministrativeTag> AdministrativeTagCursor::next() noexcept {
  if (!valid_ || remaining_.empty()) return std::nullopt;
  std::uint64_t value{};
  for (const auto byte : remaining_.first(width_)) value = (value << 8U) | byte;
  remaining_ = remaining_.subspan(width_);
  return AdministrativeTag{value, width_ == 8U};
}
bool encode_administrative_tags(TlvWriter &writer, std::span<const std::uint32_t> input) noexcept { return tags(writer, input); }
bool encode_administrative_tags(TlvWriter &writer, std::span<const std::uint64_t> input) noexcept { return tags(writer, input); }
std::optional<PrefixAttributeFlags> prefix_attribute_flags(TlvView option, const ip::IpPrefix &prefix) noexcept {
  if (option.code != 4U || option.value.size() > 255U || !valid_context(prefix)) return std::nullopt;
  const auto flags = option.value.empty() ? 0U : option.value.front();
  return PrefixAttributeFlags{prefix.network.family == ip::AddressFamily::ipv4 && (flags & 0x80U),
      (flags & 0x40U) != 0U, (flags & 0x20U) && prefix.length == ip::address_bits(prefix.network.family)};
}
bool encode_prefix_attribute_flags(TlvWriter &writer, const ip::IpPrefix &prefix, PrefixAttributeFlags flags) noexcept {
  if (!valid_context(prefix) || (flags.external && prefix.network.family == ip::AddressFamily::ipv6) ||
      (flags.node && prefix.length != ip::address_bits(prefix.network.family))) return false;
  const std::array<std::uint8_t, 1U> value{static_cast<std::uint8_t>(
      (flags.external ? 0x80U : 0U) | (flags.readvertised ? 0x40U : 0U) | (flags.node ? 0x20U : 0U))};
  return writer.append(4U, value);
}
std::optional<ip::IpAddress> prefix_source_router_id(TlvView option) noexcept {
  if (!((option.code == 11U && option.value.size() == 4U) || (option.code == 12U && option.value.size() == 16U)))
    return std::nullopt;
  ip::IpAddress address;
  address.family = option.code == 11U ? ip::AddressFamily::ipv4 : ip::AddressFamily::ipv6;
  std::copy(option.value.begin(), option.value.end(), address.bytes.begin());
  return address;
}
bool encode_prefix_source_router_id(TlvWriter &writer, const ip::IpAddress &address) noexcept {
  if (address.family == ip::AddressFamily::ipv4) {
    if (!std::all_of(address.bytes.begin() + 4U, address.bytes.end(), [](auto byte) { return byte == 0U; })) return false;
    return writer.append(11U, std::span{address.bytes}.first(4U));
  }
  return address.family == ip::AddressFamily::ipv6 && writer.append(12U, address.bytes);
}
std::optional<PrefixMetadata> prefix_metadata(const ip::IpPrefix &prefix,
    std::span<const std::uint8_t> attributes) noexcept {
  if (!valid_context(prefix)) return std::nullopt;
  PrefixMetadata result;
  TlvCursor cursor(attributes);
  while (const auto option = cursor.next()) {
    if (option->code == 4U && !result.flags) result.flags = prefix_attribute_flags(*option, prefix);
    else if (option->code == 11U && !result.source_ipv4) result.source_ipv4 = prefix_source_router_id(*option);
    else if (option->code == 12U && !result.source_ipv6) result.source_ipv6 = prefix_source_router_id(*option);
    else if ((option->code == 1U && !result.first_tag32) || (option->code == 2U && !result.first_tag64)) {
      AdministrativeTagCursor tags(*option);
      if (const auto first = tags.next()) {
        if (first->wide) result.first_tag64 = first->value;
        else result.first_tag32 = static_cast<std::uint32_t>(first->value);
      }
    }
  }
  return cursor.valid() ? std::optional{result} : std::nullopt;
}
} // namespace router::packet::isis
