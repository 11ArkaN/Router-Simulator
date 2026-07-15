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
#include <vector>

namespace router {

inline constexpr std::size_t network_endpoint_capacity =
    profile::host_macs.size();

enum class PingOrigin : std::uint8_t { router, endpoint };
enum class NetworkDrop : std::uint8_t {
  none,
  ingress_down,
  route_miss,
  queue_full,
  mtu_exceeded,
  ttl_expired,
  timeout,
  cancelled,
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
  // This is the IP MTU after control subtracts the untagged Ethernet header
  // from SR OS port Ethernet MTU. Forwarding therefore compares like units and
  // can place the correct next-hop IP MTU in RFC 1191 ICMP errors.
  std::uint16_t router_mtu{
      profile::default_port_mtu - packet::ethernet_header_octets};
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
  // Forwarding exports a duration instead of its process-local time_point.
  // Control converts it to wall time solely for CLI and checkpoint output.
  std::uint32_t remaining_seconds{};
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

enum class NetworkFrameStage : std::uint8_t {
  fabric_tx,
  fabric_in_flight,
  fabric_rx,
  router_pending,
  endpoint_pending,
  endpoint_reassembly
};

struct NetworkStoredFrame {
  // A checkpoint stores wire bytes rather than process-local PacketHandles.
  // direction is a link direction for fabric stages and a port or endpoint
  // index for local queues. remaining_ns applies only to in-flight frames.
  NetworkFrameStage stage{};
  std::uint8_t direction{};
  bool routed{};
  packet::Ipv4 next_hop{};
  std::uint64_t remaining_ns{};
  packet::Frame frame{};
};

struct NetworkEndpointState {
  // Neighbor and pending values belong to one endpoint stack. Reassembly
  // progress is stored as bytes already accepted, not as parser pointers.
  bool neighbor_valid{};
  packet::Ipv4 neighbor_address{};
  packet::Mac neighbor_mac{};
  bool pending_next_hop_valid{};
  packet::Ipv4 pending_next_hop{};
  bool reassembly_active{};
  packet::Ipv4 reassembly_source{};
  packet::Ipv4 reassembly_destination{};
  std::uint16_t reassembly_identification{};
  std::uint16_t reassembly_payload_octets{};
};

struct NetworkCheckpointState {
  // This value is produced and consumed only at a forwarding barrier. Vectors
  // are permitted here because checkpoint export is outside the packet hot
  // path. Runtime transfers ownership through release/acquire mailbox acks.
  std::array<NetworkArpEntry, profile::port_count> adjacencies{};
  std::array<bool, profile::port_count> arp_requests{};
  std::array<NetworkEndpointState, network_endpoint_capacity> endpoints{};
  std::array<std::uint64_t, profile::link_direction_count>
      transmitter_remaining_ns{};
  std::vector<NetworkStoredFrame> frames;
};

using CaptureObserver = bool (*)(void *context, std::uint8_t interface_id,
                                 const packet::Frame &frame,
                                 std::uint64_t timestamp_us);
using CancellationObserver = bool (*)(void *context) noexcept;

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
  // Checkpoint methods require forwarding-shard affinity and quiescence. They
  // translate pool handles into wire values and rebuild fresh ownership on
  // restore. Failure leaves the network empty rather than partially restored.
  [[nodiscard]] NetworkCheckpointState checkpoint() const;
  [[nodiscard]] bool restore(const NetworkCheckpointState &state) noexcept;
  // service executes work already admitted to forwarding-owned queues and the
  // physical medium. It never creates traffic or advances a virtual clock.
  // The forwarding shard calls it after checkpoint restore so a live frame
  // continues at its rebased steady-clock deadline even when no CLI job runs.
  void service() noexcept;
  // The returned deadline belongs to the nearest local LinkDirection. Callers
  // may use it only as a sleep bound and must re-check their mailbox on wake.
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point>
  next_deadline() const noexcept;
  [[nodiscard]] NetworkResult
  ping(PingOrigin origin, std::uint8_t source_endpoint,
       packet::Ipv4 destination, std::uint16_t sequence,
       std::size_t payload_octets, bool dont_fragment,
       CaptureObserver observer, void *observer_context,
       CancellationObserver cancelled = nullptr,
       void *cancellation_context = nullptr) noexcept;

private:
  // PIMPL prevents packet pool and queue storage from leaking into runtime
  // headers or being placed on the small WebAssembly entry stack.
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace router
