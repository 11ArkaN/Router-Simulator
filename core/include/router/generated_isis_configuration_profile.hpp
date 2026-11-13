// Immutable configuration facts from pinned SR OS 26.7.R1 YANG.
// Generated offline; configuration owners consume values without source I/O.
#pragma once
#include <array>
#include <cstdint>
#include <string_view>
namespace router::isis::configuration_profile {
inline constexpr std::uint32_t instance_minimum = 0;
inline constexpr std::uint32_t instance_maximum = 127;
inline constexpr std::uint32_t metric_minimum = 1;
inline constexpr std::uint32_t metric_maximum = 16777215;
inline constexpr std::uint32_t default_metric_minimum = 1;
inline constexpr std::uint32_t default_metric_maximum = 16777215;
inline constexpr std::uint32_t default_metric_default = 10;
inline constexpr std::uint32_t preference_minimum = 1;
inline constexpr std::uint32_t preference_maximum = 255;
inline constexpr std::uint32_t external_preference_minimum = 1;
inline constexpr std::uint32_t external_preference_maximum = 255;
inline constexpr std::uint32_t hello_interval_seconds_minimum = 1;
inline constexpr std::uint32_t hello_interval_seconds_maximum = 20000;
inline constexpr std::uint32_t hello_interval_seconds_default = 9;
inline constexpr std::uint32_t hello_multiplier_minimum = 2;
inline constexpr std::uint32_t hello_multiplier_maximum = 100;
inline constexpr std::uint32_t hello_multiplier_default = 3;
inline constexpr std::uint32_t priority_minimum = 0;
inline constexpr std::uint32_t priority_maximum = 127;
inline constexpr std::uint32_t priority_default = 64;
inline constexpr std::uint32_t csnp_interval_seconds_minimum = 1;
inline constexpr std::uint32_t csnp_interval_seconds_maximum = 65535;
inline constexpr std::uint32_t csnp_interval_seconds_default = 10;
inline constexpr std::uint32_t lsp_pacing_interval_milliseconds_minimum = 0;
inline constexpr std::uint32_t lsp_pacing_interval_milliseconds_maximum = 65535;
inline constexpr std::uint32_t lsp_pacing_interval_milliseconds_default = 100;
inline constexpr std::uint32_t retransmit_interval_seconds_minimum = 1;
inline constexpr std::uint32_t retransmit_interval_seconds_maximum = 65535;
inline constexpr std::uint32_t retransmit_interval_seconds_default = 5;
inline constexpr std::uint32_t lsp_lifetime_seconds_minimum = 350;
inline constexpr std::uint32_t lsp_lifetime_seconds_maximum = 65535;
inline constexpr std::uint32_t lsp_lifetime_seconds_default = 1200;
inline constexpr std::uint32_t lsp_mtu_octets_minimum = 490;
inline constexpr std::uint32_t lsp_mtu_octets_maximum = 9778;
inline constexpr std::uint32_t lsp_mtu_octets_default = 1492;
inline constexpr std::uint32_t level_lsp_mtu_octets_minimum = 490;
inline constexpr std::uint32_t level_lsp_mtu_octets_maximum = 9778;
inline constexpr std::uint32_t level_lsp_mtu_octets_default = 1492;
inline constexpr std::uint32_t spf_max_wait_milliseconds_minimum = 10;
inline constexpr std::uint32_t spf_max_wait_milliseconds_maximum = 120000;
inline constexpr std::uint32_t spf_max_wait_milliseconds_default = 10000;
inline constexpr std::uint32_t spf_initial_wait_milliseconds_minimum = 10;
inline constexpr std::uint32_t spf_initial_wait_milliseconds_maximum = 100000;
inline constexpr std::uint32_t spf_initial_wait_milliseconds_default = 1000;
inline constexpr std::uint32_t spf_second_wait_milliseconds_minimum = 10;
inline constexpr std::uint32_t spf_second_wait_milliseconds_maximum = 100000;
inline constexpr std::uint32_t spf_second_wait_milliseconds_default = 1000;
inline constexpr std::uint32_t lsp_max_wait_milliseconds_minimum = 10;
inline constexpr std::uint32_t lsp_max_wait_milliseconds_maximum = 120000;
inline constexpr std::uint32_t lsp_max_wait_milliseconds_default = 5000;
inline constexpr std::uint32_t lsp_initial_wait_milliseconds_minimum = 10;
inline constexpr std::uint32_t lsp_initial_wait_milliseconds_maximum = 100000;
inline constexpr std::uint32_t lsp_initial_wait_milliseconds_default = 10;
inline constexpr std::uint32_t lsp_second_wait_milliseconds_minimum = 10;
inline constexpr std::uint32_t lsp_second_wait_milliseconds_maximum = 100000;
inline constexpr std::uint32_t lsp_second_wait_milliseconds_default = 1000;
inline constexpr bool instance_admin_enabled_default = false;
inline constexpr bool interface_admin_enabled_default = true;
inline constexpr bool ipv4_routing_default = true;
inline constexpr bool advertise_passive_only_default = false;
inline constexpr bool strict_adjacency_check_default = false;
inline constexpr bool interface_passive_default = false;
inline constexpr bool interface_level_passive_default = false;
inline constexpr bool wide_metrics_only_default = false;
inline constexpr std::uint8_t level_capability_default = 3;
inline constexpr std::uint32_t area_addresses_maximum = 3;
inline constexpr std::uint32_t interface_name_minimum = 1;
inline constexpr std::uint32_t interface_name_maximum = 32;
inline constexpr std::array<std::string_view, 10> restart_paths{{"/configure/router/isis/igp-shortcut/allow-sr-over-srte", "/configure/router/isis/igp-shortcut/apply-groups", "/configure/router/isis/igp-shortcut/apply-groups-exclude", "/configure/router/isis/igp-shortcut/tunnel-next-hop", "/configure/router/isis/lsp-lifetime", "/configure/router/isis/lsp-mtu-size", "/configure/router/isis/router-id", "/configure/router/isis/segment-routing/prefix-sid-range/max-index", "/configure/router/isis/segment-routing/prefix-sid-range/start-label", "/configure/router/isis/system-id"}};
}
