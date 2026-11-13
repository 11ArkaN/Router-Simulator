// Canonical IS-IS intent belongs to the router control datastore. Both CLI
// engines edit these values; protocol owners receive separate resolved inputs.
// Dependencies are immutable wire values and generated release facts only.
#pragma once

#include "router/generated_isis_configuration_profile.hpp"
#include "router/isis_neighbor_attributes.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace router::isis {
enum class ConfiguredLevels : std::uint8_t { level1 = 1U, level2 = 2U, both = 3U };
enum class ConfiguredInterfaceType : std::uint8_t { point_to_point, broadcast };
enum class ConfiguredIpv6Routing : std::uint8_t { disabled, native, multi_topology };

struct WaitTimerIntent {
  std::optional<std::uint32_t> maximum, initial, second;
  bool operator==(const WaitTimerIntent &) const = default;
};
struct InterfaceLevelIntent {
  // A YANG list entry can exist with no explicit child leaves. Child values
  // require this flag too; deleting the list restores a fully absent entry.
  bool present{};
  std::optional<std::uint32_t> metric;
  std::optional<std::uint16_t> hello_interval_seconds;
  std::optional<std::uint8_t> hello_multiplier, priority;
  std::optional<bool> passive;
  bool operator==(const InterfaceLevelIntent &) const = default;
};
struct InstanceLevelIntent {
  bool present{};
  std::optional<std::uint32_t> default_metric;
  std::optional<std::uint16_t> lsp_mtu_octets;
  std::optional<std::uint8_t> preference, external_preference;
  std::optional<bool> wide_metrics_only;
  bool operator==(const InstanceLevelIntent &) const = default;
};
struct InterfaceIntent {
  std::string name;
  std::optional<ConfiguredInterfaceType> type;
  std::optional<ConfiguredLevels> levels;
  std::optional<bool> admin_enabled, passive;
  std::optional<std::uint16_t> csnp_interval_seconds, retransmit_interval_seconds,
      lsp_pacing_interval_milliseconds;
  std::array<InterfaceLevelIntent, 2U> level;
  bool operator==(const InterfaceIntent &) const = default;
};
struct InstanceIntent {
  std::uint8_t instance{};
  std::optional<bool> admin_enabled, ipv4_routing;
  std::optional<ConfiguredIpv6Routing> ipv6_routing;
  std::optional<ConfiguredLevels> levels;
  std::optional<packet::isis::SystemId> system_id;
  std::optional<std::uint32_t> router_id;
  std::optional<std::uint16_t> lsp_lifetime_seconds, lsp_mtu_octets;
  std::array<InstanceLevelIntent, 2U> level;
  // Optional values preserve explicit configuration, including an explicit
  // default. Removal restores absence; it must not write another default value.
  std::vector<NeighborArea> areas;
  std::vector<InterfaceIntent> interfaces;
  WaitTimerIntent spf_wait, lsp_wait;
  std::optional<bool> advertise_passive_only, strict_adjacency_check, ignore_attached_bit, suppress_attached_bit;
  bool operator==(const InstanceIntent &) const = default;
};
struct RouterConfiguration {
  std::vector<InstanceIntent> instances;
  bool operator==(const RouterConfiguration &) const = default;
};
enum class ConfigurationError : std::uint8_t {
  none, instance_id, duplicate_instance, levels, ipv6_routing, system_area,
  duplicate_area, interface_name, duplicate_interface, interface_type,
  metric, hello_interval, hello_multiplier, priority, csnp_interval,
  retransmit_interval, lsp_pacing_interval, lsp_lifetime, lsp_mtu,
  context_presence, preference, external_preference, wait_timer
};
// Control-shard synchronous validation of intent only, without allocation or
// mutation. Base-interface references and effective hardware policy belong to
// the enclosing router transaction. Empty areas/interfaces and disjoint level
// capabilities are valid configurations; they do not imply an adjacency.
[[nodiscard]] ConfigurationError validate_configuration(const RouterConfiguration &) noexcept;

// Pure YANG lexical parsing. Refusal returns nullopt and retains no input view.
// System IDs require twelve hex digits in XXXX.XXXX.XXXX form. Area addresses
// retain their exact 1..13-byte extent; no zero padding becomes address content.
[[nodiscard]] std::optional<packet::isis::SystemId> parse_configured_system_id(std::string_view) noexcept;
[[nodiscard]] std::optional<NeighborArea> parse_configured_area(std::string_view) noexcept;
// Pure canonical projections. These allocate returned strings and may throw;
// callers own the result. The area must have a valid length and zero spare bytes.
[[nodiscard]] std::string format_configured_system_id(const packet::isis::SystemId &);
[[nodiscard]] std::string format_configured_area(const NeighborArea &);

struct IdentityContext {
  std::optional<std::uint32_t> base_router_id, system_ipv4;
  // The configuration adapter supplies its source-backed fallback explicitly.
  // Zero means unresolved and cannot produce a usable derived System ID.
  std::uint32_t fallback_router_id{};
};
// Control-owner resolution without mutation or allocation. The configured zero
// System ID selects derivation. Preference is instance router ID, Base router
// ID, system IPv4, then the explicit fallback. IPv4 octets become three decimal
// digits each before those twelve digits form six hexadecimal ID octets.
[[nodiscard]] std::optional<packet::isis::SystemId> resolve_configured_system_id(
    const InstanceIntent &, const IdentityContext &) noexcept;
// Validated intent only. Returns the intersection of the two configured/default
// level masks. Zero is a valid ineffective interface, not an invalid edit.
[[nodiscard]] std::uint8_t configured_level_mask(const InstanceIntent &, const InterfaceIntent &) noexcept;
} // namespace router::isis
