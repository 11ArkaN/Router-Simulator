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
  // Aging uses the forwarding owner's steady clock. Browser clock changes
  // cannot extend or prematurely expire a learned protocol mapping.
  std::chrono::steady_clock::time_point expires_at{};
};

class AdjacencyTable final {
public:
  // All methods require forwarding-shard affinity. Port indices are validated
  // by the caller against profile::port_count before this boundary is crossed.
  // Learning replaces the one protocol address owned by the selected port.
  void learn(std::uint8_t port, packet::Ipv4 address, packet::Mac mac) noexcept;
  // Carrier loss invalidates both the learned entry and request suppression.
  void invalidate(std::size_t port) noexcept;
  // exact is the forwarding lookup. A MAC learned for another protocol address
  // on the same port is never returned as a convenient substitute.
  [[nodiscard]] const Adjacency *exact(std::size_t port,
                                       packet::Ipv4 address) noexcept;
  // get supports operational projection and does not express resolution.
  [[nodiscard]] const Adjacency *get(std::size_t port) const noexcept;
  // Request flags suppress duplicate ARP while a bounded pending frame waits.
  [[nodiscard]] bool request_outstanding(std::size_t port) const noexcept;
  void mark_request(std::size_t port) noexcept;
  void complete_request(std::size_t port) noexcept;
  // Restore accepts value records from a validated checkpoint. It owns no
  // references to the checkpoint image after this call returns.
  void restore(
      const std::array<NetworkArpEntry, profile::port_count> &entries) noexcept;
  // projection copies learned state for control and checkpoint consumers.
  [[nodiscard]] std::array<NetworkArpEntry, profile::port_count>
  projection() const noexcept;
  [[nodiscard]] std::array<bool, profile::port_count>
  request_projection() const noexcept;
  void restore_requests(
      const std::array<bool, profile::port_count> &requests) noexcept;

private:
  std::array<std::optional<Adjacency>, profile::port_count> entries_{};
  std::array<bool, profile::port_count> requests_{};
};

} // namespace router::network_detail
