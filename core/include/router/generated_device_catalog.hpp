#pragma once

// Generated release hardware catalog. The records contain only immutable
// profile metadata. Device registries own all selected and operational state.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace router::device_catalog {

// One release owns this entire generated catalog. Runtime capability output
// consumes this value instead of repeating the release pin in hand-written C++.
inline constexpr std::string_view release{"26.7.R1"};
inline constexpr std::uint64_t catalog_hash = 0x0fae1ef668260ff9ULL;
inline constexpr std::uint64_t checkpoint_schema_hash = 0x152f7d3524b6caaaULL;
inline constexpr std::uint64_t runtime_protocol_hash = 0x26f06df6429b2878ULL;
inline constexpr std::uint64_t build_hash = 0x28923cb2f23d9285ULL;

inline constexpr std::size_t maximum_routers = 16;
inline constexpr std::size_t maximum_hosts = 16;
inline constexpr std::size_t maximum_links = 64;
inline constexpr std::size_t maximum_sessions_per_router = 4;
inline constexpr std::size_t maximum_ports_per_router = 800;
inline constexpr std::size_t maximum_card_slots = 10;
inline constexpr std::size_t maximum_mda_slots_per_card = 2;
inline constexpr std::size_t maximum_ports_per_mda = 40;
inline constexpr std::size_t maximum_static_routes_per_router = 64;
inline constexpr std::size_t maximum_fib_routes_per_router =
    maximum_ports_per_router + maximum_static_routes_per_router;
inline constexpr std::size_t wasm_initial_memory_bytes = 268435456U;
inline constexpr std::size_t wasm_stack_bytes = 1048576U;
inline constexpr std::size_t packet_pool_bytes = 67108864U;
inline constexpr std::size_t capture_store_bytes = 33554432U;
inline constexpr std::size_t terminal_output_arena_bytes = 16777216U;
inline constexpr std::size_t terminal_result_bytes = 1048576U;
inline constexpr std::size_t runtime_control_reserve_bytes = 33554432U;
inline constexpr std::size_t low_cpu_max = 4;
inline constexpr std::size_t medium_cpu_max = 8;
inline constexpr std::size_t low_control_shards = 1;
inline constexpr std::size_t medium_control_shards = 1;
inline constexpr std::size_t high_control_shards = 2;
inline constexpr std::size_t low_forwarding_shards = 1;
inline constexpr std::size_t medium_forwarding_shards = 2;
inline constexpr std::size_t high_forwarding_shards = 3;
inline constexpr std::size_t low_link_shards = 0;
inline constexpr std::size_t medium_link_shards = 1;
inline constexpr std::size_t high_link_shards = 1;
inline constexpr std::size_t maximum_worker_domains = 6;
inline constexpr std::size_t worker_startup_attempts = 200;
inline constexpr std::chrono::milliseconds worker_startup_poll{
    10};
inline constexpr std::chrono::milliseconds telemetry_publish_interval{
    250};
inline constexpr std::size_t link_queue_capacity = 256;
inline constexpr std::size_t fabric_work_budget_frames = 64;
inline constexpr std::size_t arp_entries_per_router = 4096;
inline constexpr std::size_t pending_ipv4_frames_per_router = 512;
inline constexpr std::size_t network_command_ring_entries = 8;
inline constexpr std::size_t network_result_ring_entries = 32;
inline constexpr std::size_t forwarding_ring_frames = 64;
inline constexpr std::size_t candidate_keys_per_router = 256;
inline constexpr std::size_t candidate_keys_per_session = 128;
inline constexpr std::size_t selected_capture_points = 256;
inline constexpr std::size_t capture_point_name_bytes = 512;
inline constexpr std::uint16_t default_network_mtu = 9212;
inline constexpr std::uint16_t minimum_network_mtu = 512;
inline constexpr std::uint16_t maximum_network_mtu = 9212;
inline constexpr std::uint16_t minimum_host_ipv4_mtu = 68;
inline constexpr std::uint16_t default_host_ipv4_mtu = 1500;
inline constexpr std::chrono::seconds dynamic_arp_timeout{
    14400};
inline constexpr std::size_t default_ping_payload_octets =
    56;
inline constexpr std::size_t minimum_ping_payload_octets =
    12;
inline constexpr std::size_t maximum_ping_payload_octets =
    1472;
inline constexpr std::uint32_t maximum_ping_count =
    100000U;
inline constexpr std::chrono::milliseconds ping_interval{
    1000};
inline constexpr std::chrono::milliseconds ping_timeout{
    5000};

struct PortGroup {
  std::uint8_t count{};
  std::array<std::uint32_t, 2> speeds_mbps{};
};

struct MdaProfile {
  std::string_view type;
  bool ethernet{};
  std::uint8_t port_count{};
  std::uint8_t group_count{};
  std::array<PortGroup, 2> groups{};
};

struct CardProfile {
  std::string_view device_profile;
  std::string_view type;
  bool fixed{};
  std::uint8_t mda_slots{};
  std::uint16_t first_mda{};
  std::uint16_t mda_count{};
};

struct DeviceProfile {
  std::string_view id;
  std::string_view chassis;
  std::string_view release;
  bool fixed{};
  std::uint8_t card_slots{};
  std::uint16_t first_card{};
  std::uint16_t card_count{};
  std::string_view control_slot;
  std::string_view control_type;
  std::string_view default_card;
  std::array<std::string_view, 2> default_mdas{};
  std::uint16_t maximum_ports{};
};

inline constexpr std::array<MdaProfile, 27> mdas{{
    {"isa2-aa", false, 0, 0, {{{0, {{0U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"isa2-bb", false, 0, 0, {{{0, {{0U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"isa2-tunnel", false, 0, 0, {{{0, {{0U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p10-10g-sfp", true, 10, 1, {{{10, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p1-100g-cfp", true, 1, 1, {{{1, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p6-10g-sfp", true, 6, 1, {{{6, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p20-1gb-sfp", true, 20, 1, {{{20, {{1000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"imm24-1gb-xp-sfp", true, 24, 1, {{{24, {{1000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me10-10gb-sfp+", true, 10, 1, {{{10, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me1-100gb-cfp2", true, 1, 1, {{{1, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me12-10/1gb-sfp+", true, 12, 1, {{{12, {{1000U, 10000U}}}, {0, {{0U, 0U}}}}}},
    {"me2-100gb-ms-qsfp28", true, 2, 1, {{{2, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me2-100gb-qsfp28", true, 2, 1, {{{2, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me40-1gb-csfp", true, 40, 1, {{{40, {{1000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me6-10gb-sfp+", true, 6, 1, {{{6, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me8-10/25gb-sfp28", true, 8, 1, {{{8, {{10000U, 25000U}}}, {0, {{0U, 0U}}}}}},
    {"me12-100gb-qsfp28", true, 12, 1, {{{12, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me3-200gb-cfp2-dco", true, 3, 1, {{{3, {{100000U, 200000U}}}, {0, {{0U, 0U}}}}}},
    {"me6-100gb-qsfp28", true, 6, 1, {{{6, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me6-400gb-qsfpdd", true, 6, 1, {{{6, {{400000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me16-25gb-sfp28+2-100gb-qsfp28", true, 18, 2, {{{16, {{10000U, 25000U}}}, {2, {{100000U, 0U}}}}}},
    {"me3-400gb-qsfpdd", true, 3, 1, {{{3, {{400000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me16-25gb-sfp28+2-100gb-qsfp-b", true, 18, 2, {{{16, {{10000U, 25000U}}}, {2, {{100000U, 0U}}}}}},
    {"m5e2-100g-qsfp28+2-800g-qdd", true, 4, 2, {{{2, {{100000U, 0U}}}, {2, {{800000U, 0U}}}}}},
    {"m5e8-100g-sfp112+2-800g-qdd", true, 10, 2, {{{8, {{100000U, 0U}}}, {2, {{800000U, 0U}}}}}},
    {"m5e10-100g-qsfp28", true, 10, 1, {{{10, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"m5e16-100g-sfp112", true, 16, 1, {{{16, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}}
}};

inline constexpr std::array<std::uint16_t, 95> card_mdas{{
    16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 26U, 0U, 1U, 2U, 3U, 4U, 7U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 17U, 18U, 20U, 21U, 22U, 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 17U, 18U, 20U, 21U, 22U
}};

inline constexpr std::array<CardProfile, 13> cards{{
    {"7750-sr-1", "cpm-1", true, 2, 0, 11},
    {"7750-sr-7", "imm-2pac-fp3", false, 2, 11, 5},
    {"7750-sr-7", "imm48-1gb-sfp-c", false, 1, 16, 1},
    {"7750-sr-7", "iom4-e", false, 2, 17, 11},
    {"7750-sr-7", "iom4-e-b", false, 2, 28, 11},
    {"7750-sr-7", "iom4-e-hs", false, 2, 39, 8},
    {"7750-sr-7", "iom5-e", false, 2, 47, 5},
    {"7750-sr-12", "imm-2pac-fp3", false, 2, 52, 7},
    {"7750-sr-12", "imm48-1gb-sfp-c", false, 1, 59, 1},
    {"7750-sr-12", "iom4-e", false, 2, 60, 11},
    {"7750-sr-12", "iom4-e-b", false, 2, 71, 11},
    {"7750-sr-12", "iom4-e-hs", false, 2, 82, 8},
    {"7750-sr-12", "iom5-e", false, 2, 90, 5}
}};

inline constexpr std::array<DeviceProfile, 3> profiles{{
    {"7750-sr-1", "7750 SR-1", "26.7.R1", true, 0, 0, 1, "A", "cpm-1", "cpm-1", {"me6-100gb-qsfp28", "me12-100gb-qsfp28"}, 36},
    {"7750-sr-7", "7750 SR-7", "26.7.R1", false, 5, 1, 6, "A", "cpm5", "iom5-e", {"me6-100gb-qsfp28", ""}, 400},
    {"7750-sr-12", "7750 SR-12", "26.7.R1", false, 10, 7, 6, "A", "cpm5", "iom5-e", {"me6-100gb-qsfp28", ""}, 800}
}};

[[nodiscard]] constexpr const DeviceProfile *find_profile(std::string_view id) noexcept {
  // Bounded generated records are cheaper and easier to validate than a mutable
  // hash index. The returned pointer targets immutable process-lifetime data.
  for (const auto &profile : profiles)
    if (profile.id == id)
      return &profile;
  return nullptr;
}

[[nodiscard]] constexpr const MdaProfile *find_mda(std::string_view type) noexcept {
  // Hardware edits run on the control shard, so a bounded catalog scan keeps
  // the generated representation compact without affecting packet throughput.
  for (const auto &mda : mdas)
    if (mda.type == type)
      return &mda;
  return nullptr;
}

[[nodiscard]] constexpr const CardProfile *
find_card(const DeviceProfile &profile, std::string_view type) noexcept {
  // Cards for a profile occupy one contiguous generated range. Restricting the
  // scan to that range prevents a same-named card from another chassis profile
  // from becoming compatible accidentally.
  for (std::size_t offset = 0; offset < profile.card_count; ++offset) {
    const auto &card = cards[profile.first_card + offset];
    if (card.type == type)
      return &card;
  }
  return nullptr;
}

[[nodiscard]] constexpr bool card_supports_mda(
    const CardProfile &card, std::string_view type) noexcept {
  // card_mdas stores indexes into immutable MDA records. The compact relation
  // is evaluated on hardware edits, never per forwarded packet.
  for (std::size_t offset = 0; offset < card.mda_count; ++offset)
    if (mdas[card_mdas[card.first_mda + offset]].type == type)
      return true;
  return false;
}

} // namespace router::device_catalog
