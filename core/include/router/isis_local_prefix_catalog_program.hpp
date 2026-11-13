// The configuration owner prepares conditional prefix content before admission.
// Canonical AF inputs borrow only during this call; outputs transfer owned bytes
// to the control shard through its generic prefix catalog contract.
#pragma once
#include "router/isis_local_prefix_program.hpp"
#include "router/isis_local_prefix_catalog.hpp"
namespace router::isis {
enum class LocalPrefixCatalogStatus : std::uint8_t {
  prepared, inactive, invalid_context, conflicting_prefix, capacity,
  unsupported_topology, unresolved_narrow_metric, unresolved_system_metric
};
struct LocalPrefixCatalogResult {
  LocalPrefixCatalogStatus status{LocalPrefixCatalogStatus::invalid_context};
  std::optional<LocalPrefixCatalogProgram> program;
};
// Validated intent and one corresponding binding per borrowed AF source are
// required. Source availability must equal its binding gate. All possible
// carrier states are admitted against explicit per-level prefix budgets.
// Cold, same configuration shard; may allocate/throw. Success owns every byte
// and interface key. Failure publishes nothing and changes no input.
[[nodiscard]] LocalPrefixCatalogResult prepare_local_prefix_catalog(const InstanceIntent &,
    std::span<const LocalPrefixSource>, std::span<const LocalPrefixInterface>,
    std::array<std::size_t, 2U> maximum_prefixes);
struct LocalIpPrefixAddress {
  ip::IpAddress address;
  std::uint8_t prefix_length{};
  // The local AF owner resolves family-specific level metrics. This compiler
  // cannot infer IPv6 costs from IPv4 policy or decide address readiness.
  std::array<std::uint32_t, 2U> metrics{};
};
struct LocalIpPrefixSource {
  std::string_view interface_name;
  LocalPrefixInterface binding;
  // Local AF address candidates. The caller retains DAD, lifetime and interface
  // ownership and must pair unassigned candidates with address-specific gates.
  // Empty input represents no configured AF address.
  std::span<const LocalIpPrefixAddress> addresses;
};
struct LocalIpPrefixCatalogResult {
  LocalPrefixCatalogStatus status{LocalPrefixCatalogStatus::invalid_context};
  std::optional<LocalPrefixCatalogProgram> program;
  std::vector<packet::Ipv4> ipv4_addresses;
  std::vector<packet::Ipv6> ipv6_addresses;
};
// One local source per configured interface, validated unicast AF candidates and
// resolved per-level metrics are required. Canonical masks and deduplication
// share the generic catalog admission. RFC 5308 link-local addresses produce
// neither reachable prefixes nor LSP address metadata. Returned bytes and
// sorted metadata are owned; no borrowed address survives. Invalid family,
// length, IPv4 spare bytes or failed admission returns no partial result.
// Cold configuration shard only; may allocate/throw, publishes nothing.
[[nodiscard]] LocalIpPrefixCatalogResult prepare_local_ip_prefix_catalog(const InstanceIntent &,
    std::span<const LocalIpPrefixSource>, std::array<std::size_t, 2U> maximum_prefixes);
struct LocalIpv4PrefixSource {
  std::string_view interface_name;
  LocalPrefixInterface binding;
  // AF-owned IPv4 value in network bit order, independent of host byte order.
  std::uint32_t address{};
  std::uint8_t prefix_length{};
  bool address_configured{}, system{};
};
struct LocalIpv4PrefixCatalogResult {
  LocalPrefixCatalogStatus status{LocalPrefixCatalogStatus::invalid_context};
  std::optional<LocalPrefixCatalogProgram> program;
  std::vector<packet::Ipv4> addresses;
};
// Validated local Base AF values, actual local availability and complete IS-IS
// bindings are required. IPv4 unnumbered and unresolved System metric overrides
// refuse. Physical prefixes use inherited per-level metrics; System uses /32
// metric zero. Returns owned catalog and sorted unique router address metadata.
// Cold configuration owner only; may allocate/throw, publishes nothing on failure.
[[nodiscard]] LocalIpv4PrefixCatalogResult prepare_local_ipv4_prefix_catalog(const InstanceIntent &,
    std::span<const LocalIpv4PrefixSource>, std::array<std::size_t, 2U> maximum_prefixes);
}
