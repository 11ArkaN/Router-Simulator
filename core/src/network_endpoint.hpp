// Forwarding-owned endpoint IPv4 and ARP stack. It consumes encoded frames and
// returns encoded frames plus probe observations. It cannot inspect router FIB,
// router adjacencies, link queues or another endpoint's mutable state.

#pragma once

#include "router/network.hpp"

#include <array>
#include <optional>

namespace router::network_detail {

struct EndpointFrames {
  // Two frames cover an ARP reply plus release of one pending datagram. Storage
  // is inline and bounded, so endpoint processing never allocates on packet
  // path.
  std::array<packet::Frame, 2> frames{};
  std::uint8_t count{};
  bool start_echo_clock{};
  bool echo_reply{};
  bool ttl_expired{};
};

class EndpointStack final {
public:
  // configure replaces endpoint identity and clears neighbors when values
  // change. The configuration value is copied and may be discarded by caller.
  void configure(const NetworkEndpointConfiguration &configuration) noexcept;
  // begin_echo either emits ARP or ICMP and retains at most one pending frame.
  // The returned value owns every frame passed to the link fabric.
  [[nodiscard]] EndpointFrames begin_echo(packet::Ipv4 destination,
                                          std::uint16_t sequence) noexcept;
  // receive parses encoded Ethernet. Malformed or unrelated packets produce an
  // empty result and cannot mutate another endpoint or the router adjacency.
  [[nodiscard]] EndpointFrames receive(const packet::Frame &frame,
                                       std::uint16_t expected_sequence,
                                       bool probe_source) noexcept;
  // Link loss clears only this endpoint's learned router neighbor.
  void clear_neighbor() noexcept;
  // Checkpoint restore installs a previously validated exact protocol address.
  void restore_router_neighbor(packet::Ipv4 address, packet::Mac mac) noexcept;

  // Identity accessors expose immutable values copied during configure.
  [[nodiscard]] packet::Ipv4 address() const noexcept { return address_; }
  [[nodiscard]] packet::Mac mac() const noexcept { return mac_; }

private:
  packet::Mac mac_{};
  packet::Ipv4 address_{};
  // Zero is deliberately unusable until configure installs the project prefix.
  // A protocol-specific /30 default here would make an unconfigured endpoint
  // appear valid and couple the reusable stack to the first sample topology.
  std::uint8_t prefix_length_{};
  packet::Ipv4 gateway_{};
  std::optional<packet::Ipv4> neighbor_address_;
  std::optional<packet::Mac> neighbor_mac_;
  std::optional<packet::Frame> pending_;
  std::optional<packet::Ipv4> pending_next_hop_;
};

} // namespace router::network_detail
