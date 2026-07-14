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
inline constexpr std::size_t port_count = 10;
inline constexpr std::uint32_t port_speed_mbps = 10000U;
// These delays are an emulator profile, not a claim about physical SR-7 boot
// time. The YAML marks both values experimental so UI and snapshots can expose
// their provenance without presenting them as Nokia guarantees.
inline constexpr std::chrono::milliseconds card_initialization{
    2000};
inline constexpr std::chrono::milliseconds mda_initialization{
    1000};
// Ethernet serialization is derived from the equipped port speed. Propagation
// is a default for newly created project links and is never folded into speed.
inline constexpr std::uint64_t port_bits_per_second =
    static_cast<std::uint64_t>(port_speed_mbps) * 1000000ULL;
inline constexpr std::chrono::nanoseconds default_link_propagation{
    100};

inline constexpr std::array<packet::Mac, 2> host_macs{{
    {0x02, 0x00, 0x00, 0x00, 0x00, 0x0a},
    {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b},
}};
inline constexpr std::array<packet::Ipv4, 2> host_addresses{{
    {192, 0, 2, 2},
    {198, 51, 100, 2},
}};
inline constexpr std::array<packet::Ipv4, 2> host_gateways{{
    {192, 0, 2, 1},
    {198, 51, 100, 1},
}};
inline constexpr std::array<std::uint8_t, 2> host_prefix_lengths{30, 30};
inline constexpr std::array<packet::Mac, 2> router_macs{{
    {0x02, 0x00, 0x00, 0x00, 0x01, 0x01},
    {0x02, 0x00, 0x00, 0x00, 0x01, 0x02},
}};
inline constexpr std::array<packet::Ipv4, 2> router_addresses{{
    {192, 0, 2, 1},
    {198, 51, 100, 1},
}};
inline constexpr std::array<std::uint32_t, 2> router_networks{0xc0000200U, 0xc6336400U};
inline constexpr std::array<const char*, 10> port_ids{
    "1/1/1", "1/1/2", "1/1/3", "1/1/4", "1/1/5",
    "1/1/6", "1/1/7", "1/1/8", "1/1/9", "1/1/10"};
inline constexpr std::array<const char*, 2> interface_names{"to-host-a", "to-host-b"};
inline constexpr std::array<const char*, 2> interface_addresses{
    "192.0.2.1/30", "198.51.100.1/30"};
inline constexpr std::array<const char*, 2> interface_prefixes{
    "192.0.2.0/30", "198.51.100.0/30"};
inline constexpr std::array<const char*, 9> capture_interface_names{
    "link-host-a-to-router", "link-router-to-host-a", "link-router-to-host-b", "link-host-b-to-router", "router-1/1/1-ingress", "router-1/1/2-ingress", "router-1/1/1-egress", "router-1/1/2-egress", "cpm-punt"};

}  // namespace router::profile
