// Forwarding-owned encoded frame path built from endpoint to port bindings.
// Control supplies immutable configuration values. Mutable queues, links,
// adjacencies and packet handles remain private to one forwarding shard.

#pragma once

#include "router/generated_profile.hpp"
#include "router/packet.hpp"
#include "router/routing.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>

namespace router {

inline constexpr std::size_t network_endpoint_capacity =
    profile::host_macs.size();

enum class PingOrigin : std::uint8_t { router, endpoint };
enum class NetworkDrop : std::uint8_t {
  none,
  ingress_down,
  route_miss,
  queue_full,
  ttl_expired,
  timeout,
  malformed
};

struct NetworkEndpointConfiguration {
  // One value describes both ends of a physical endpoint link. The router port
  // handle selects FIB, adjacency and counters without assuming port 0 or 1.
  bool connected{};
  std::uint8_t router_port{};
  packet::Mac endpoint_mac{};
  packet::Ipv4 endpoint_address{};
  std::uint8_t endpoint_prefix_length{};
  packet::Ipv4 endpoint_gateway{};
  packet::Mac router_mac{};
  packet::Ipv4 router_address{};
  std::chrono::nanoseconds propagation{profile::default_link_propagation};
};

struct NetworkConfiguration {
  // The complete value is applied between forwarding jobs. No caller can
  // expose a partially moved endpoint or one-way propagation update.
  std::array<NetworkEndpointConfiguration, network_endpoint_capacity>
      endpoints{};
};

struct NetworkArpEntry {
  bool valid{};
  packet::Ipv4 address{};
  packet::Mac mac{};
  std::uint8_t port_index{};
};

struct NetworkResult {
  // Results own projections and counter deltas. They never reference live
  // queues, packet storage or link deadlines across the shard boundary.
  bool success{};
  NetworkDrop drop{NetworkDrop::none};
  std::uint8_t reply_ttl{};
  std::uint64_t rtt_us{};
  std::uint32_t transmitted_frames{};
  std::uint32_t captured_frames{};
  std::uint32_t capture_drops{};
  std::array<std::uint64_t, profile::port_count> rx_delta{};
  std::array<std::uint64_t, profile::port_count> tx_delta{};
  std::array<NetworkArpEntry, profile::port_count> router_arp{};
};

using CaptureObserver = bool (*)(void *context, std::uint8_t interface_id,
                                 const packet::Frame &frame,
                                 std::uint64_t timestamp_us);

class LabNetwork final {
public:
  // All methods require forwarding-shard affinity. They allocate no memory
  // after construction. Queue overflow is returned as NetworkDrop::queue_full.
  LabNetwork();
  ~LabNetwork();
  LabNetwork(const LabNetwork &) = delete;
  LabNetwork &operator=(const LabNetwork &) = delete;

  void install_fib(const routing::FibProgram &fib) noexcept;
  void configure(const NetworkConfiguration &configuration) noexcept;
  void restore_adjacencies(
      const std::array<NetworkArpEntry, profile::port_count> &entries) noexcept;
  [[nodiscard]] std::array<NetworkArpEntry, profile::port_count>
  adjacencies() const noexcept;
  [[nodiscard]] NetworkResult ping(PingOrigin origin, std::uint16_t sequence,
                                   CaptureObserver observer,
                                   void *observer_context) noexcept;

private:
  // PIMPL prevents packet pool and queue storage from leaking into runtime
  // headers or being placed on the small WebAssembly entry stack.
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace router
