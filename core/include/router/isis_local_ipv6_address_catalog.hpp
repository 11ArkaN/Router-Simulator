// The IS-IS control writer owns address-specific IPv6 advertisement gates.
// Cold candidates and encoded metadata remain local values. Dependencies point
// to address semantics and fragment scratch, never to live forwarding state.
#pragma once
#include "router/isis_local_prefix_catalog.hpp"
namespace router::isis {
struct LocalIpv6Address {
  std::uint64_t interface_id{};
  std::optional<std::uint16_t> physical_port;
  ip::Ipv6 address{};
  std::uint8_t prefix_length{};
  bool preferred{};
  bool operator==(const LocalIpv6Address &) const = default;
};
struct LocalIpv6AddressUnit {
  LocalIpv6Address source;
  std::array<std::uint8_t, 18U> metadata{};
  bool operator==(const LocalIpv6AddressUnit &) const = default;
};
struct LocalIpv6AddressCatalog {
  std::uint32_t version{1U};
  // One instance control writer owns all bytes. Cold admission copies sources;
  // no references cross shards. Readiness edits allocate nothing. Exhaustion
  // refuses the complete cold program, never truncates its candidate set.
  std::vector<LocalIpv6AddressUnit> units;
  bool operator==(const LocalIpv6AddressCatalog &) const = default;
};
// Cold configuration owner. Requires unique interface/address keys, unicast
// IPv6, valid physical ordinals and explicit capacity. Copies encoded TLV232
// metadata into owned units. Invalid input returns no partial catalog; may
// allocate/throw. Link-local candidates are retained only for Hello gating.
[[nodiscard]] std::optional<LocalIpv6AddressCatalog> prepare_local_ipv6_address_catalog(
    std::span<const LocalIpv6Address>, std::size_t maximum_addresses);
// Same control owner. Validates canonical ordering, source keys and exact TLV
// encoding without allocation or mutation. Use before checkpoint admission.
[[nodiscard]] bool valid_local_ipv6_address_catalog(const LocalIpv6AddressCatalog &) noexcept;
// Cold admission also requires every address to match an existing interface
// and its physical binding. No allocation or mutation.
[[nodiscard]] bool valid_local_ipv6_address_catalog(const LocalIpv6AddressCatalog &,
    const LocalPrefixCatalogProgram &) noexcept;
// Same control writer after the enclosing owner validates device/configuration
// generation. The physical binding must match. Returns whether a gate changed;
// unknown keys and repeated values do nothing. No allocation or peer access.
[[nodiscard]] bool set_local_ipv6_address_ready(LocalIpv6AddressCatalog &,
    std::uint64_t interface_id, std::uint16_t port, const ip::Ipv6 &, bool) noexcept;
// Local physical Down clears assignment; Up alone never makes an address ready.
[[nodiscard]] bool clear_local_ipv6_port(LocalIpv6AddressCatalog &, std::uint16_t port) noexcept;
// Validated catalog on its control writer. Prefix query is an OR across assigned
// addresses of one canonical subnet. Carrier availability is applied separately
// by the existing interface owner. Link-local candidates never match a prefix.
[[nodiscard]] bool local_ipv6_prefix_available(const LocalIpv6AddressCatalog &,
    std::uint64_t interface_id, const ip::IpPrefix &) noexcept;
[[nodiscard]] bool local_ipv6_link_local_available(const LocalIpv6AddressCatalog &,
    std::uint64_t interface_id) noexcept;
// The complete configured Hello list must consist of assigned local link-local
// candidates. Empty or partially assigned lists are not ready. Carrier remains
// a separate circuit gate; no allocation, mutation or borrowed view escapes.
[[nodiscard]] bool local_ipv6_hello_available(const LocalIpv6AddressCatalog &,
    std::uint64_t interface_id, std::span<const packet::Ipv6>) noexcept;
// Same owner and validated complete address/interface binding. Adds ordinary
// IPv4 units under existing carrier gates and IPv6 units only when at least one
// corresponding address is assigned. Shared subnets survive independent address
// loss. all_possible bypasses assignment for cold capacity admission.
[[nodiscard]] bool append_local_af_prefixes(OriginFragmentWorkspace &,
    const LocalPrefixCatalogProgram &, const LocalIpv6AddressCatalog &,
    std::size_t level, bool all_possible = false) noexcept;
// Requires validated address and prefix catalogs. Only assigned non-link-local
// values on available interfaces enter TLV232; identical values occur once.
// all_possible reserves the cold superset regardless of current gates. Borrowed
// metadata outlives workspace compose/reset. No allocation or publication.
[[nodiscard]] bool append_local_ipv6_addresses(OriginFragmentWorkspace &,
    const LocalIpv6AddressCatalog &, const LocalPrefixCatalogProgram &,
    bool all_possible = false) noexcept;
}
