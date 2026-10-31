// Bounded extended IS and IP reachability codecs. Traversal state is local to
// each cursor; callers own all packet storage and protocol acceptance policy.
// Source: ietf.isis.reachability.rfc5305
// Source: ietf.isis.ipv6.rfc5308

#include "router/isis_reachability.hpp"

#include <algorithm>

namespace router::packet::isis {
namespace {
[[nodiscard]] bool framed(std::span<const std::uint8_t> bytes) noexcept {
  TlvCursor cursor(bytes);
  while (cursor.next()) {}
  return cursor.valid();
}

[[nodiscard]] std::uint32_t read_metric(std::span<const std::uint8_t> bytes,
                                       std::size_t count) noexcept {
  std::uint32_t value{};
  for (std::size_t i = 0U; i < count; ++i)
    value = (value << 8U) | bytes[i];
  return value;
}

void write_metric(std::span<std::uint8_t> bytes, std::uint32_t value) noexcept {
  for (std::size_t i = 0U; i < bytes.size(); ++i)
    bytes[i] = static_cast<std::uint8_t>(value >> ((bytes.size() - i - 1U) * 8U));
}

void mask_tail(ip::IpPrefix &prefix) noexcept {
  const auto octets = static_cast<std::size_t>((prefix.length + 7U) / 8U);
  if (prefix.length % 8U != 0U)
    prefix.network.bytes[octets - 1U] &= static_cast<std::uint8_t>(0xffU << (8U - prefix.length % 8U));
  std::fill(prefix.network.bytes.begin() + octets, prefix.network.bytes.end(), std::uint8_t{});
}
}

ExtendedNeighborCursor::ExtendedNeighborCursor(TlvView tlv) noexcept
    : remaining_(tlv.value), valid_(tlv.code == 22U && tlv.value.size() <= 255U) {}

std::optional<ExtendedNeighbor> ExtendedNeighborCursor::next() noexcept {
  if (!valid_ || remaining_.empty())
    return std::nullopt;
  if (remaining_.size() < 11U || remaining_[10U] > remaining_.size() - 11U) {
    valid_ = false;
    return std::nullopt;
  }
  ExtendedNeighbor result;
  std::copy_n(remaining_.begin(), result.id.size(), result.id.begin());
  result.metric = read_metric(remaining_.subspan(7U), 3U);
  result.sub_tlvs = remaining_.subspan(11U, remaining_[10U]);
  if (!framed(result.sub_tlvs)) {
    valid_ = false;
    return std::nullopt;
  }
  remaining_ = remaining_.subspan(11U + result.sub_tlvs.size());
  return result;
}

ExtendedPrefixCursor::ExtendedPrefixCursor(TlvView tlv) noexcept
    : remaining_(tlv.value),
      family_(tlv.code == 236U ? ip::AddressFamily::ipv6 : ip::AddressFamily::ipv4),
      valid_((tlv.code == 135U || tlv.code == 236U) && tlv.value.size() <= 255U) {}

std::optional<ExtendedPrefix> ExtendedPrefixCursor::next() noexcept {
  if (!valid_ || remaining_.empty())
    return std::nullopt;
  const bool ipv6 = family_ == ip::AddressFamily::ipv6;
  const std::size_t fixed = ipv6 ? 6U : 5U;
  if (remaining_.size() < fixed) {
    valid_ = false;
    return std::nullopt;
  }
  ExtendedPrefix result;
  result.prefix.network.family = family_;
  result.metric = read_metric(remaining_, 4U);
  result.down = (remaining_[4U] & 0x80U) != 0U;
  result.external = ipv6 && (remaining_[4U] & 0x40U) != 0U;
  result.sub_tlvs_present = (remaining_[4U] & (ipv6 ? 0x20U : 0x40U)) != 0U;
  result.prefix.length = ipv6 ? remaining_[5U] : remaining_[4U] & 0x3fU;
  const std::size_t octets = (result.prefix.length + 7U) / 8U;
  if (result.prefix.length > ip::address_bits(family_) || remaining_.size() - fixed < octets) {
    valid_ = false;
    return std::nullopt;
  }
  std::copy_n(remaining_.begin() + fixed, octets, result.prefix.network.bytes.begin());
  // RFC 5305/5308 require unused prefix bits to be ignored on receipt.
  mask_tail(result.prefix);
  std::size_t consumed = fixed + octets;
  if (result.sub_tlvs_present) {
    if (remaining_.size() <= consumed || remaining_[consumed] > remaining_.size() - consumed - 1U) {
      valid_ = false;
      return std::nullopt;
    }
    result.sub_tlvs = remaining_.subspan(consumed + 1U, remaining_[consumed]);
    if (!framed(result.sub_tlvs)) {
      valid_ = false;
      return std::nullopt;
    }
    consumed += 1U + result.sub_tlvs.size();
  }
  remaining_ = remaining_.subspan(consumed);
  return result;
}

bool encode_extended_neighbor(TlvWriter &writer, const ExtendedNeighbor &entry) noexcept {
  if (entry.metric > maximum_link_metric || entry.sub_tlvs.size() > 244U || !framed(entry.sub_tlvs))
    return false;
  std::array<std::uint8_t, 255U> bytes{};
  std::copy(entry.id.begin(), entry.id.end(), bytes.begin());
  write_metric(std::span(bytes).subspan(7U, 3U), entry.metric);
  bytes[10U] = static_cast<std::uint8_t>(entry.sub_tlvs.size());
  std::copy(entry.sub_tlvs.begin(), entry.sub_tlvs.end(), bytes.begin() + 11U);
  return writer.append(22U, std::span(bytes).first(11U + entry.sub_tlvs.size()));
}

bool encode_extended_prefix(TlvWriter &writer, const ExtendedPrefix &entry) noexcept {
  const auto family = entry.prefix.network.family;
  if ((family != ip::AddressFamily::ipv4 && family != ip::AddressFamily::ipv6) ||
      entry.prefix.length > ip::address_bits(family) ||
      (!entry.sub_tlvs_present && !entry.sub_tlvs.empty()) || !framed(entry.sub_tlvs))
    return false;
  auto canonical = entry.prefix;
  mask_tail(canonical);
  if (canonical != entry.prefix)
    return false;
  const bool ipv6 = family == ip::AddressFamily::ipv6;
  if ((!ipv6 && entry.external) ||
      (ipv6 && entry.prefix.network.bytes[0U] == 0xfeU &&
       (entry.prefix.network.bytes[1U] & 0xc0U) == 0x80U && entry.prefix.length >= 10U))
    return false;
  const std::size_t fixed = ipv6 ? 6U : 5U;
  const std::size_t octets = (entry.prefix.length + 7U) / 8U;
  const auto base = fixed + octets + (entry.sub_tlvs_present ? 1U : 0U);
  if (entry.sub_tlvs.size() > 255U - base)
    return false;
  std::array<std::uint8_t, 255U> bytes{};
  write_metric(std::span(bytes).first(4U), entry.metric);
  bytes[4U] = entry.down ? 0x80U : 0U;
  if (ipv6) {
    bytes[4U] |= entry.external ? 0x40U : 0U;
    bytes[4U] |= entry.sub_tlvs_present ? 0x20U : 0U;
    bytes[5U] = entry.prefix.length;
  } else {
    bytes[4U] |= entry.prefix.length;
    bytes[4U] |= entry.sub_tlvs_present ? 0x40U : 0U;
  }
  std::copy_n(entry.prefix.network.bytes.begin(), octets, bytes.begin() + fixed);
  if (entry.sub_tlvs_present) {
    bytes[fixed + octets] = static_cast<std::uint8_t>(entry.sub_tlvs.size());
    std::copy(entry.sub_tlvs.begin(), entry.sub_tlvs.end(), bytes.begin() + base);
  }
  return writer.append(ipv6 ? 236U : 135U, std::span(bytes).first(base + entry.sub_tlvs.size()));
}

} // namespace router::packet::isis
