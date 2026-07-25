// Allocation-free Internet Protocol address values shared by packet, routing
// and management modules. The value types own only canonical network-order
// bytes. Text conversion is a cold-path operation and has no dependency on a
// device, interface, CLI session or browser object.

#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace router::ip {

using Ipv4 = std::array<std::uint8_t, 4>;
using Ipv6 = std::array<std::uint8_t, 16>;
inline constexpr std::uint8_t ipv4_address_bits = 32;
inline constexpr std::uint8_t ipv6_address_bits = 128;

enum class AddressFamily : std::uint8_t { ipv4 = 4U, ipv6 = 6U };

struct IpAddress {
  // The fixed sixteen-octet representation avoids allocation and tagged-union
  // lifetime rules in shared configuration graphs. IPv4 occupies the first
  // four octets and requires the remaining bytes to be zero, so equality and
  // ordering remain deterministic across native and Wasm checkpoint builds.
  AddressFamily family{AddressFamily::ipv4};
  std::array<std::uint8_t, 16> bytes{};

  [[nodiscard]] friend constexpr bool
  operator==(const IpAddress &, const IpAddress &) noexcept = default;
  [[nodiscard]] friend constexpr auto
  operator<=>(const IpAddress &, const IpAddress &) noexcept = default;
};

struct IpPrefix {
  // Network bits after length are always zero. Family is carried by the
  // address because SR OS policy-options prefix lists can contain both IPv4
  // and IPv6 entries in one operator-owned list.
  IpAddress network{};
  std::uint8_t length{};

  [[nodiscard]] friend constexpr bool
  operator==(const IpPrefix &, const IpPrefix &) noexcept = default;
  [[nodiscard]] friend constexpr auto
  operator<=>(const IpPrefix &, const IpPrefix &) noexcept = default;
};

struct Ipv6Prefix {
  // Prefix bytes are always canonical: every bit after length is zero. This
  // invariant lets route keys compare as plain fixed values and prevents two
  // textual spellings from creating different RIB entries.
  Ipv6 network{};
  std::uint8_t length{};

  [[nodiscard]] friend constexpr bool
  operator==(const Ipv6Prefix &, const Ipv6Prefix &) noexcept = default;
};

struct ScopedIpv6Address {
  // RFC 4007 requires a zone for addresses whose meaning is interface-local.
  // The stable interface identifier is stored instead of an array index so a
  // hardware inventory rebuild cannot silently redirect a link-local next hop.
  Ipv6 address{};
  std::uint64_t interface_id{};

  [[nodiscard]] friend constexpr bool
  operator==(const ScopedIpv6Address &,
             const ScopedIpv6Address &) noexcept = default;
};

[[nodiscard]] std::optional<Ipv6> parse_ipv6(std::string_view text) noexcept;
[[nodiscard]] std::optional<Ipv6Prefix>
parse_ipv6_prefix(std::string_view text) noexcept;
[[nodiscard]] std::optional<IpAddress>
parse_ip_address(std::string_view text) noexcept;
[[nodiscard]] std::optional<IpPrefix>
parse_ip_prefix(std::string_view text) noexcept;
[[nodiscard]] std::string format_ipv6(const Ipv6 &address);
[[nodiscard]] std::string format_ipv6_prefix(const Ipv6Prefix &prefix);
[[nodiscard]] std::string format_ip_address(const IpAddress &address);
[[nodiscard]] std::string format_ip_prefix(const IpPrefix &prefix);

[[nodiscard]] constexpr std::uint8_t
address_bits(AddressFamily family) noexcept {
  return family == AddressFamily::ipv6 ? ipv6_address_bits
                                       : ipv4_address_bits;
}

[[nodiscard]] constexpr std::size_t
address_octets(AddressFamily family) noexcept {
  return family == AddressFamily::ipv6 ? 16U : 4U;
}

[[nodiscard]] IpAddress mask(const IpAddress &address,
                             std::uint8_t length) noexcept;
[[nodiscard]] bool contains(const IpPrefix &prefix,
                            const IpAddress &address) noexcept;

[[nodiscard]] constexpr bool is_unspecified(const Ipv6 &address) noexcept {
  // A loop avoids reinterpret_cast and alignment assumptions. Compilers fold
  // this fixed sixteen-byte comparison into the appropriate native sequence.
  for (const auto byte : address)
    if (byte != 0)
      return false;
  return true;
}

[[nodiscard]] constexpr bool is_loopback(const Ipv6 &address) noexcept {
  for (std::size_t index = 0; index < 15; ++index)
    if (address[index] != 0)
      return false;
  return address[15] == 1;
}

[[nodiscard]] constexpr bool is_multicast(const Ipv6 &address) noexcept {
  return address[0] == 0xff;
}

[[nodiscard]] constexpr bool is_multicast(const Ipv4 &address) noexcept {
  // RFC 1112 assigns class-D 224.0.0.0/4 to IPv4 multicast.
  return (address[0] & 0xf0U) == 0xe0U;
}

[[nodiscard]] constexpr bool is_link_local(const Ipv6 &address) noexcept {
  // fe80::/10 is the complete unicast link-local block. Checking only the
  // first byte would incorrectly classify fec0::/10 site-local addresses.
  return address[0] == 0xfe && (address[1] & 0xc0U) == 0x80U;
}

[[nodiscard]] Ipv6 mask(const Ipv6 &address, std::uint8_t length) noexcept;
[[nodiscard]] bool contains(const Ipv6Prefix &prefix,
                            const Ipv6 &address) noexcept;
[[nodiscard]] Ipv6 solicited_node_multicast(const Ipv6 &unicast) noexcept;
// RFC 4291 Appendix A forms the modified EUI-64 identifier from a 48-bit IEEE
// address by inserting ff:fe and complementing the universal/local bit. This
// helper is deterministic address construction only and owns no DAD policy.
[[nodiscard]] Ipv6
link_local_from_mac(const std::array<std::uint8_t, 6> &mac) noexcept;
// SR OS `eui-64` applies a modified EUI-64 interface identifier to a /64
// operator prefix. Invalid prefix lengths are rejected rather than silently
// overwriting network bits that belong to a longer prefix.
[[nodiscard]] std::optional<Ipv6>
address_from_eui64(const Ipv6 &prefix, std::uint8_t prefix_length,
                   const std::array<std::uint8_t, 6> &mac) noexcept;

} // namespace router::ip
