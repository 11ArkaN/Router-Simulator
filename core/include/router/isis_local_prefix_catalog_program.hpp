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
