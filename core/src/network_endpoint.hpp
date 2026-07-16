// Forwarding-owned endpoint IPv4 and ARP stack. It consumes encoded frames and
// returns encoded frames plus probe observations. It cannot inspect router FIB,
// router adjacencies, link queues or another endpoint's mutable state.

#pragma once

#include "router/endpoint_protocol.hpp"

#include <array>
#include <optional>

namespace router::network_detail {

struct EndpointFrames {
  // The current host operation emits the generated default Echo size. At the
  // minimum legal IPv4 MTU it becomes two fragments. One additional slot lets
  // an incoming ARP request be answered before both pending fragments release.
  static constexpr std::size_t minimum_fragment_payload =
      ((device_catalog::minimum_host_ipv4_mtu - 20U) / 8U) * 8U;
  static constexpr std::size_t default_echo_ip_payload =
      8U + device_catalog::default_ping_payload_octets;
  static constexpr std::size_t maximum_pending_fragments =
      (default_echo_ip_payload + minimum_fragment_payload - 1U) /
      minimum_fragment_payload;
  std::array<packet::Frame, maximum_pending_fragments + 1U> frames{};
  std::uint8_t count{};
  bool start_echo_clock{};
  bool echo_reply{};
  bool ttl_expired{};
  bool mtu_exceeded{};
};

class EndpointStack final {
public:
  // configure replaces endpoint identity and clears neighbors when values
  // change. The configuration value is copied and may be discarded by caller.
  void configure(const NetworkEndpointConfiguration &configuration) noexcept;
  // begin_echo either emits ARP or ICMP and retains at most one pending frame.
  // The returned value owns every frame passed to the link fabric.
  [[nodiscard]] EndpointFrames begin_echo(packet::Ipv4 destination,
                                          std::uint16_t sequence,
                                          std::size_t payload_octets =
                                              device_catalog::default_ping_payload_octets,
                                          bool dont_fragment = false) noexcept;
  // receive parses encoded Ethernet. Malformed or unrelated packets produce an
  // empty result and cannot mutate another endpoint or the router adjacency.
  [[nodiscard]] EndpointFrames receive(const packet::Frame &frame,
                                       std::uint16_t expected_sequence,
                                       bool probe_source) noexcept;
  // Link loss clears only this endpoint's learned router neighbor.
  void clear_neighbor() noexcept;
  // Checkpoint restore installs a previously validated exact protocol address.
  void restore_router_neighbor(packet::Ipv4 address, packet::Mac mac) noexcept;
  // Structural checkpoint methods run only on forwarding. They persist local
  // protocol values and encoded frames, never references into another owner.
  void checkpoint(NetworkCheckpointState &state) const;
  [[nodiscard]] bool restore(const NetworkCheckpointState &state) noexcept;

  // Identity accessors expose immutable values copied during configure.
  [[nodiscard]] packet::Ipv4 address() const noexcept { return address_; }
  [[nodiscard]] packet::Mac mac() const noexcept { return mac_; }
  [[nodiscard]] std::uint8_t prefix_length() const noexcept {
    return prefix_length_;
  }
  [[nodiscard]] packet::Ipv4 gateway() const noexcept { return gateway_; }
  [[nodiscard]] std::uint16_t mtu() const noexcept { return mtu_; }

private:
  packet::Mac mac_{};
  packet::Ipv4 address_{};
  // Zero is deliberately unusable until configure installs the project prefix.
  // A protocol-specific /30 default here would make an unconfigured endpoint
  // appear valid and couple the reusable stack to the first sample topology.
  std::uint8_t prefix_length_{};
  packet::Ipv4 gateway_{};
  std::uint16_t mtu_{device_catalog::default_host_ipv4_mtu};
  std::optional<packet::Ipv4> neighbor_address_;
  std::optional<packet::Mac> neighbor_mac_;
  std::array<packet::Frame, EndpointFrames::maximum_pending_fragments>
      pending_frames_{};
  std::uint8_t pending_count_{};
  std::optional<packet::Ipv4> pending_next_hop_;
  struct Reassembly {
    // LinkDirection preserves order, so one bounded contiguous accumulator is
    // sufficient for this single-probe endpoint. A key mismatch discards the
    // incomplete datagram instead of mixing generations or allocating a map.
    bool active{};
    packet::Ipv4 source{};
    packet::Ipv4 destination{};
    std::uint16_t identification{};
    std::uint16_t payload_octets{};
    packet::Frame frame{};
  } reassembly_{};

  [[nodiscard]] std::optional<packet::Frame>
  reassemble(const packet::Frame &fragment,
             const packet::Ipv4View &ip) noexcept;
};

} // namespace router::network_detail
