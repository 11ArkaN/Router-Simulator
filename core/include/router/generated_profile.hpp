#pragma once

// Compile-time projection of the canonical 7750 SR-7 profile. Full-output
// comparison in CI prevents C++ constants from drifting away from the YAML.

#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstdint>

namespace router::profile {

inline constexpr char id[] = "7750-sr-7-iom4-e";
inline constexpr char release[] = "26.7.R1";
inline constexpr char chassis[] = "7750 SR-7";
inline constexpr std::size_t chassis_slots = 5;
inline constexpr std::size_t line_card_slot = 1;
inline constexpr std::size_t mda_slot = 1;
inline constexpr char line_card_type[] = "iom4-e";
inline constexpr char modeled_mda_type[] = "me10-10gb-sfp+";
inline constexpr std::size_t port_count = 10;
inline constexpr std::size_t endpoint_count = 2;
inline constexpr std::uint32_t port_speed_mbps = 10000U;
// These delays are an emulator profile, not a claim about physical SR-7 boot
// time. The YAML marks both values experimental so projections retain source
// status without presenting them as Nokia guarantees.
inline constexpr std::chrono::milliseconds card_initialization{
    2000};
inline constexpr std::chrono::milliseconds mda_initialization{
    1000};
// Ethernet serialization derives from equipped port speed. Propagation belongs
// to each project link and does not alter transmitter throughput.
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
inline constexpr std::array<const char*, 2> supported_mda_types{
    "me10-10gb-sfp+", "me1-100gb-cfp2"};
inline constexpr std::array<const char*, endpoint_count> interface_names{
    "to-host-a", "to-host-b"};
inline constexpr std::array<const char*, endpoint_count> interface_addresses{
    "192.0.2.1/30", "198.51.100.1/30"};
inline constexpr std::array<const char*, endpoint_count> interface_prefixes{
    "192.0.2.0/30", "198.51.100.0/30"};
inline constexpr std::array<const char*, 9> capture_interface_names{
    "link-host-a-to-router", "link-router-to-host-a", "link-host-b-to-router", "link-router-to-host-b", "router-1/1/1-ingress", "router-1/1/2-ingress", "router-1/1/1-egress", "router-1/1/2-egress", "cpm-punt"};

}  // namespace router::profile
