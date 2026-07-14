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
  void configure(const NetworkEndpointConfiguration &configuration) noexcept;
  [[nodiscard]] EndpointFrames begin_echo(packet::Ipv4 destination,
                                          std::uint16_t sequence) noexcept;
  [[nodiscard]] EndpointFrames receive(const packet::Frame &frame,
                                       std::uint16_t expected_sequence,
                                       bool probe_source) noexcept;
  void clear_neighbor() noexcept;
  void restore_router_neighbor(packet::Ipv4 address, packet::Mac mac) noexcept;

  [[nodiscard]] packet::Ipv4 address() const noexcept { return address_; }
  [[nodiscard]] packet::Mac mac() const noexcept { return mac_; }

private:
  packet::Mac mac_{};
  packet::Ipv4 address_{};
  std::uint8_t prefix_length_{30};
  packet::Ipv4 gateway_{};
  std::optional<packet::Ipv4> neighbor_address_;
  std::optional<packet::Mac> neighbor_mac_;
  std::optional<packet::Frame> pending_;
  std::optional<packet::Ipv4> pending_next_hop_;
};

} // namespace router::network_detail
