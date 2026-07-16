#pragma once

// Generated profile projection. This file is the only compile-time source for
// hardware identity, topology, resources, timing and cross-language versions.

#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace router::profile {

inline constexpr char id[] = "7750-sr-7-iom4-e";
inline constexpr char release[] = "26.7.R1";
inline constexpr char chassis[] = "7750 SR-7";
inline constexpr char default_system_name[] = "R1";
inline constexpr char software_version[] = "C-26.7.R1";
inline constexpr char crypto_module_version[] = "N/A";
inline constexpr char configuration_mode[] = "mixed";
inline constexpr std::uint16_t snmp_port = 161;
inline constexpr std::uint16_t config_backup_count = 50;
inline constexpr char dns_resolve_preference[] = "ipv4-only";
inline constexpr char dnssec_response_control[] = "drop";
inline constexpr char control_slot[] = "A";
inline constexpr char control_card_type[] = "cpm5";
inline constexpr char control_initial_state[] = "active-ready";
inline constexpr std::size_t chassis_slots = 5;
inline constexpr std::size_t line_card_slot = 1;
inline constexpr std::size_t line_card_index = line_card_slot - 1U;
inline constexpr std::size_t mda_slot = 1;
inline constexpr std::size_t mda_index = mda_slot - 1U;
inline constexpr std::size_t mda_slots_per_card = 1;
inline constexpr char line_card_type[] = "iom4-e";
inline constexpr char modeled_mda_type[] = "me10-10gb-sfp+";
inline constexpr char line_card_alarm_id[] = "card-1";
inline constexpr char mda_alarm_id[] = "mda-1/1";
inline constexpr std::size_t port_count = 10;
inline constexpr std::size_t endpoint_count = 2;
inline constexpr std::size_t link_direction_count = endpoint_count * 2U;
inline constexpr std::size_t capture_ingress_base = link_direction_count;
inline constexpr std::size_t capture_egress_base = capture_ingress_base + endpoint_count;
inline constexpr std::size_t capture_cpm_index = capture_egress_base + endpoint_count;
inline constexpr std::uint32_t port_speed_mbps = 10000U;
inline constexpr std::uint16_t default_port_mtu = 9212;
inline constexpr std::uint16_t minimum_port_mtu = 512;
inline constexpr std::uint16_t maximum_port_mtu = 9212;
inline constexpr std::size_t static_route_capacity = 8;
inline constexpr std::size_t fib_route_capacity = 18;
inline constexpr std::uint32_t runtime_worker_count = 2U;
inline constexpr std::uint32_t pthread_pool_min = 2U;
inline constexpr std::uint32_t pthread_pool_max = 4U;
inline constexpr std::size_t command_message_bytes = 4096;
inline constexpr std::size_t response_message_bytes = 16384;
inline constexpr std::size_t packet_pool_bytes = 67108864U;
inline constexpr std::size_t capture_memory_bytes = 33554432U;
inline constexpr std::size_t link_queue_capacity = 256;
inline constexpr std::size_t link_inflight_capacity = 2048;
inline constexpr std::size_t adjacency_pending_capacity = 8;
inline constexpr std::size_t command_ring_capacity = 64;
inline constexpr std::size_t response_ring_capacity = 8;
inline constexpr std::size_t forwarding_ring_capacity = 16;
inline constexpr std::size_t cli_input_queue_bytes = 65536U;
inline constexpr std::size_t cli_output_queue_bytes = 1048576U;
inline constexpr std::size_t system_name_bytes = 64;
inline constexpr std::size_t port_description_bytes = 80;
inline constexpr std::size_t host_name_bytes = 64;
inline constexpr std::size_t project_name_bytes = 128;
inline constexpr std::uint32_t default_ping_count = 5U;
inline constexpr std::uint32_t maximum_ping_count = 100000U;
inline constexpr std::uint16_t default_ping_payload_octets = 56U;
inline constexpr std::uint16_t minimum_ping_payload_octets = 12U;
inline constexpr std::uint16_t maximum_ping_payload_octets = 1472U;
inline constexpr std::size_t cli_history_entries = 50;
inline constexpr std::uint32_t runtime_snapshot_abi = 4;
inline constexpr std::uint32_t telemetry_abi = 4;
inline constexpr std::uint32_t runtime_message_abi = 2;
inline constexpr std::uint32_t checkpoint_abi = 4;
inline constexpr std::uint64_t profile_hash = 0xb22da40eb8506cadULL;
inline constexpr std::uint64_t checkpoint_schema_hash = 0xf57d6de68b39429cULL;
inline constexpr std::uint64_t build_hash = 0xa95bfa02f5101d29ULL;

// Hardware initialization values are experimental emulator timing profiles,
// not claims about physical platform boot guarantees.
inline constexpr std::chrono::milliseconds card_initialization{
    2000};
inline constexpr std::chrono::milliseconds mda_initialization{
    1000};
inline constexpr std::chrono::milliseconds ping_timeout{
    2000};
inline constexpr std::chrono::seconds arp_timeout{
    14400};
inline constexpr std::chrono::milliseconds telemetry_interval{
    250};
inline constexpr std::chrono::milliseconds equipment_poll_interval{
    250};
inline constexpr std::chrono::milliseconds worker_shutdown_timeout{
    250};
inline constexpr std::uint64_t port_bits_per_second =
    static_cast<std::uint64_t>(port_speed_mbps) * 1000000ULL;
inline constexpr std::chrono::nanoseconds default_link_propagation{
    100};

inline constexpr std::array<packet::Mac, endpoint_count> host_macs{{
    {0x02, 0x00, 0x00, 0x00, 0x00, 0x0a},
    {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b},
}};
inline constexpr std::array<packet::Ipv4, endpoint_count> host_addresses{{
    {192, 0, 2, 2},
    {198, 51, 100, 2},
}};
inline constexpr std::array<packet::Ipv4, endpoint_count> host_gateways{{
    {192, 0, 2, 1},
    {198, 51, 100, 1},
}};
inline constexpr std::array<std::uint8_t, endpoint_count> host_prefix_lengths{
    30, 30};
inline constexpr std::array<packet::Mac, endpoint_count> router_macs{{
    {0x02, 0x00, 0x00, 0x00, 0x01, 0x01},
    {0x02, 0x00, 0x00, 0x00, 0x01, 0x02},
}};
inline constexpr std::array<packet::Ipv4, endpoint_count> router_addresses{{
    {192, 0, 2, 1},
    {198, 51, 100, 1},
}};
inline constexpr std::array<std::uint32_t, endpoint_count> router_networks{
    0xc0000200U, 0xc6336400U};
inline constexpr std::array<const char*, port_count> port_ids{
    "1/1/1", "1/1/2", "1/1/3", "1/1/4", "1/1/5", "1/1/6", "1/1/7", "1/1/8", "1/1/9", "1/1/10"};
inline constexpr std::array<bool, port_count> initial_port_admin_enabled{
    true, true, false, false, false, false, false, false, false, false};
inline constexpr std::array<const char*, 2> supported_mda_types{
    "me10-10gb-sfp+", "me1-100gb-cfp2"};
inline constexpr std::array<const char*, endpoint_count> host_ids{
    "host-a", "host-b"};
inline constexpr std::array<const char*, endpoint_count> host_names{
    "Host A", "Host B"};
inline constexpr std::array<const char*, endpoint_count> link_ids{
    "host-a-r1", "r1-host-b"};
inline constexpr std::array<std::uint8_t, endpoint_count> link_port_indices{
    0, 1};
inline constexpr std::array<const char*, endpoint_count> interface_names{
    "to-host-a", "to-host-b"};
inline constexpr std::array<const char*, endpoint_count> interface_addresses{
    "192.0.2.1/30", "198.51.100.1/30"};
inline constexpr std::array<const char*, endpoint_count> interface_prefixes{
    "192.0.2.0/30", "198.51.100.0/30"};
inline constexpr std::array<std::uint8_t, endpoint_count> interface_port_indices{
    0, 1};
inline constexpr std::array<bool, endpoint_count> initial_interface_admin_enabled{
    true, true};
inline constexpr std::array<const char*, 9> capture_interface_names{
    "link-host-a-to-router", "link-router-to-host-a", "link-host-b-to-router", "link-router-to-host-b", "router-1/1/1-ingress", "router-1/1/2-ingress", "router-1/1/1-egress", "router-1/1/2-egress", "cpm-punt"};

}  // namespace router::profile
