// Forwarding-shard network stack and encoded frame path for the starter lab.
// All mutable queues, adjacencies and packet handles remain behind this API.

#pragma once

#include "router/packet.hpp"
#include "router/routing.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>

namespace router {

enum class PingOrigin : std::uint8_t { router, host_a };
// NetworkDrop names the first terminal cause seen by the data-plane owner. It
// is translated to CLI text only after crossing back into control.
enum class NetworkDrop : std::uint8_t {
  none,
  ingress_down,
  route_miss,
  queue_full,
  ttl_expired,
  timeout,
  malformed
};

struct NetworkArpEntry {
  // The forwarding ARP table never crosses as a pointer. This small value copy
  // is enough for operational projection and survives packet pool reuse.
  bool valid{};
  packet::Ipv4 address{};
  packet::Mac mac{};
  std::uint8_t port_index{};
};

struct NetworkResult {
  // NetworkResult is an immutable acknowledgement copied from the forwarding
  // owner to control. It contains projections and deltas, never references to
  // live ARP tables, queues, packet buffers, or link deadlines.
  bool success{};
  NetworkDrop drop{NetworkDrop::none};
  std::uint8_t reply_ttl{};
  std::uint64_t rtt_us{};
  std::uint32_t transmitted_frames{};
  std::uint32_t captured_frames{};
  std::uint32_t capture_drops{};
  std::array<std::uint64_t, 2> rx_delta{};
  std::array<std::uint64_t, 2> tx_delta{};
  std::array<NetworkArpEntry, 2> router_arp{};
};

using CaptureObserver = bool (*)(void* context, std::uint8_t interface_id,
                                 const packet::Frame& frame,
                                 std::uint64_t timestamp_us);
// Returning false means diagnostics overflow only. LabNetwork still transfers
// the frame through its link and receiver queue.

class LabNetwork final {
 public:
  // LabNetwork owns every mutable data-plane object for the vertical slice:
  // endpoint stacks, router adjacencies, packet pool, device queues and four
  // full-duplex link directions. Calls must remain on one forwarding shard.
  LabNetwork();
  ~LabNetwork();
  LabNetwork(const LabNetwork&) = delete;
  LabNetwork& operator=(const LabNetwork&) = delete;

  void install_fib(const routing::FibProgram& fib) noexcept;
  // Host configuration crosses the shard boundary as parsed value types. A
  // configuration change invalidates only the affected learned adjacency.
  void configure_hosts(const std::array<packet::Mac, 2>& macs,
                       const std::array<packet::Ipv4, 2>& addresses,
                       const std::array<std::uint8_t, 2>& prefix_lengths,
                       const std::array<packet::Ipv4, 2>& gateways) noexcept;
  // One value configures both full-duplex directions of the same physical
  // medium. The forwarding owner applies the pair atomically between jobs.
  void configure_links(
      const std::array<std::chrono::nanoseconds, 2>& propagation_delays) noexcept;
  // Checkpoint import occurs only after the control-to-forwarding barrier. The
  // value array rebuilds protocol adjacencies without copying queues, futexes,
  // thread stacks or PacketPool storage.
  void restore_adjacencies(const std::array<NetworkArpEntry, 2>& entries) noexcept;
  [[nodiscard]] std::array<NetworkArpEntry, 2> adjacencies() const noexcept;
  [[nodiscard]] NetworkResult ping(PingOrigin origin, std::uint16_t sequence,
                                   CaptureObserver observer,
                                   void* observer_context) noexcept;

 private:
  // PIMPL keeps packet pool and bounded link queues out of Runtime's header and
  // forces their large storage onto the heap instead of the Wasm entry stack.
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace router
