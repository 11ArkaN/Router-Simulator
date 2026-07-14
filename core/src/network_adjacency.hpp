// Forwarding-owned IPv4 to MAC adjacency table. It owns learned values and the
// one-request-per-port suppression bit, but never owns pending packet queues or
// emits frames. Resolution users must match the exact protocol address.

#pragma once

#include "router/network.hpp"

#include <array>
#include <optional>

namespace router::network_detail {

struct Adjacency {
  packet::Ipv4 address{};
  packet::Mac mac{};
};

class AdjacencyTable final {
public:
  void learn(std::uint8_t port, packet::Ipv4 address, packet::Mac mac) noexcept;
  void invalidate(std::size_t port) noexcept;
  [[nodiscard]] const Adjacency *exact(std::size_t port,
                                       packet::Ipv4 address) const noexcept;
  [[nodiscard]] const Adjacency *get(std::size_t port) const noexcept;
  [[nodiscard]] bool request_outstanding(std::size_t port) const noexcept;
  void mark_request(std::size_t port) noexcept;
  void complete_request(std::size_t port) noexcept;
  void restore(
      const std::array<NetworkArpEntry, profile::port_count> &entries) noexcept;
  [[nodiscard]] std::array<NetworkArpEntry, profile::port_count>
  projection() const noexcept;

private:
  std::array<std::optional<Adjacency>, profile::port_count> entries_{};
  std::array<bool, profile::port_count> requests_{};
};

} // namespace router::network_detail
