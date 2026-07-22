// ICMPv6 Neighbor Discovery wire contracts. The codec validates only received
// bytes and owns no neighbor cache, timer, interface or topology state. State
// machines consume these fixed values after the frame has crossed a real link.

#pragma once

#include "router/packet.hpp"

#include <array>
#include <cstddef>
#include <optional>

namespace router::packet::nd {

// ICMPv6 type and Hop Limit values are fixed by RFC 4861. Naming them here
// lets both the decoder and forwarding termination path share one wire contract.
inline constexpr std::uint8_t router_solicitation_type = 133;
inline constexpr std::uint8_t router_advertisement_type = 134;
inline constexpr std::uint8_t neighbor_solicitation_type = 135;
inline constexpr std::uint8_t neighbor_advertisement_type = 136;
inline constexpr std::uint8_t redirect_type = 137;
inline constexpr std::uint8_t required_hop_limit = 255;
inline constexpr Ipv6 all_nodes_multicast{0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                          0,    0,    0, 0, 0, 0, 0, 1};
inline constexpr Ipv6 all_routers_multicast{0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                            0,    0,    0, 0, 0, 0, 0, 2};

// The preference enum represents the RFC 4191 two-bit field after decoding.
// The reserved wire value is normalized to medium as required for receivers,
// so state owners never need to carry an invalid preference forward.
enum class RouterPreference : std::uint8_t { low, medium, high };

struct PrefixInformation {
  ip::Ipv6Prefix prefix{};
  std::uint32_t valid_lifetime_seconds{};
  std::uint32_t preferred_lifetime_seconds{};
  bool on_link{};
  bool autonomous{};

  // Configuration transactions compare complete prefix options. Keeping the
  // comparison on the wire-contract type prevents each owner from inventing
  // a partial equality rule that could hide a changed lifetime or flag.
  bool operator==(const PrefixInformation &) const = default;
};

struct RdnssServer {
  Ipv6 address{};
  std::uint32_t lifetime_seconds{};

  bool operator==(const RdnssServer &) const = default;
};

struct RdnssInformation {
  // Each server owns its received lifetime. Multiple RFC 8106 options in one
  // RA may carry different lifetimes and must not be collapsed into one value.
  std::array<RdnssServer, device_catalog::ipv6_rdnss_servers_per_interface>
      servers{};
  std::uint8_t count{};

  bool operator==(const RdnssInformation &) const = default;
};

struct RouterAdvertisementConfig {
  std::array<PrefixInformation,
             device_catalog::ipv6_ra_prefixes_per_interface>
      prefixes{};
  RdnssInformation rdnss{};
  // SR OS exposes one lifetime for the complete server list. Keeping that
  // scalar even while the list is empty makes leaf application order
  // irrelevant in a model-driven candidate. Received advertisements retain
  // per-option lifetimes in RdnssInformation instead.
  std::uint32_t rdnss_lifetime_seconds{
      device_catalog::ra_infinite_lifetime};
  std::uint32_t reachable_time_milliseconds{};
  std::uint32_t retrans_timer_milliseconds{};
  std::uint32_t max_advertisement_interval_seconds{
      static_cast<std::uint32_t>(
          device_catalog::ra_max_advertisement_interval.count())};
  std::uint32_t min_advertisement_interval_seconds{
      static_cast<std::uint32_t>(
          device_catalog::ra_min_advertisement_interval.count())};
  // SR OS inherits the RFC 4861 AdvDefaultLifetime of three MaxRtrAdvInterval
  // periods. The generated release catalog owns the concrete default so a
  // future release profile can change it without modifying the codec.
  std::uint16_t router_lifetime_seconds{
      static_cast<std::uint16_t>(
          device_catalog::ra_router_lifetime.count())};
  std::uint16_t advertised_mtu{};
  std::uint8_t prefix_count{};
  std::uint8_t current_hop_limit{device_catalog::default_ip_hop_limit};
  RouterPreference preference{RouterPreference::medium};
  bool managed_configuration{};
  bool other_configuration{};
  bool include_source_link_layer{true};

  // Equality covers every advertised field because candidate-versus-running
  // detection must reprogram the forwarding owner when any option changes.
  bool operator==(const RouterAdvertisementConfig &) const = default;
};

struct RouterSolicitationView {
  Ipv6 source{};
  Ipv6 destination{};
  std::optional<Mac> source_link_layer{};
};

struct RouterAdvertisementView {
  Ipv6 source{};
  Ipv6 destination{};
  std::array<PrefixInformation,
             device_catalog::ipv6_ra_prefixes_per_interface>
      prefixes{};
  RdnssInformation rdnss{};
  std::optional<Mac> source_link_layer{};
  std::optional<std::uint32_t> advertised_mtu{};
  std::uint32_t reachable_time_milliseconds{};
  std::uint32_t retrans_timer_milliseconds{};
  std::uint16_t router_lifetime_seconds{};
  std::uint8_t prefix_count{};
  std::uint8_t current_hop_limit{};
  RouterPreference preference{RouterPreference::medium};
  bool managed_configuration{};
  bool other_configuration{};
};

struct NeighborSolicitationView {
  Ipv6 source{};
  Ipv6 destination{};
  Ipv6 target{};
  std::optional<Mac> source_link_layer{};
  bool duplicate_address_detection{};
};

struct NeighborAdvertisementView {
  Ipv6 source{};
  Ipv6 destination{};
  Ipv6 target{};
  std::optional<Mac> target_link_layer{};
  bool router{};
  bool solicited{};
  bool override_flag{};
};

struct RedirectView {
  // The codec validates all context-free RFC 4861 section 8.1 conditions.
  // The receiving host must additionally prove that source is its current
  // first-hop router for destination before changing its Destination Cache.
  Ipv6 source{};
  Ipv6 receiver{};
  Ipv6 target{};
  Ipv6 destination{};
  std::optional<Mac> target_link_layer{};
  bool redirected_header_present{};
};

// Normal address resolution includes Source Link-Layer Address. DAD uses the
// unspecified source and deliberately omits that option as required by RFC
// 4861 and RFC 4862.
[[nodiscard]] Frame neighbor_solicitation(Mac source_mac, Ipv6 source,
                                          Ipv6 target,
                                          bool dad = false) noexcept;
[[nodiscard]] Frame neighbor_unicast_probe(Mac source_mac,
                                           Mac destination_mac, Ipv6 source,
                                           Ipv6 target) noexcept;

[[nodiscard]] Frame neighbor_advertisement(
    Mac source_mac, Mac destination_mac, Ipv6 source, Ipv6 destination,
    Ipv6 target, bool router, bool solicited,
    bool override_flag) noexcept;

// A redirect always includes the invoking IPv6 packet in a Redirected Header
// option, truncated only to the IPv6 minimum MTU. target_link_layer is emitted
// when the redirecting router already owns a usable adjacency for target.
[[nodiscard]] std::optional<Frame> redirect(
    Mac source_mac, Mac receiver_mac, Ipv6 source, Ipv6 receiver,
    Ipv6 target, Ipv6 destination, std::optional<Mac> target_link_layer,
    const Frame &invoking_packet) noexcept;

// An unspecified-source RS omits SLLA. A normal host solicitation includes
// the option so the advertising router may learn the host from received wire
// data. RA encoding fails instead of truncating when a bounded profile or MTU
// contract is violated.
[[nodiscard]] Frame router_solicitation(Mac source_mac, Ipv6 source) noexcept;
[[nodiscard]] std::optional<Frame>
router_advertisement(Mac source_mac, Ipv6 source, Ipv6 destination,
                     const RouterAdvertisementConfig &config) noexcept;

[[nodiscard]] std::optional<NeighborSolicitationView>
parse_neighbor_solicitation(const Frame &frame) noexcept;
[[nodiscard]] std::optional<NeighborAdvertisementView>
parse_neighbor_advertisement(const Frame &frame) noexcept;
[[nodiscard]] std::optional<RedirectView>
parse_redirect(const Frame &frame) noexcept;
[[nodiscard]] std::optional<RouterSolicitationView>
parse_router_solicitation(const Frame &frame) noexcept;
[[nodiscard]] std::optional<RouterAdvertisementView>
parse_router_advertisement(const Frame &frame) noexcept;

} // namespace router::packet::nd
