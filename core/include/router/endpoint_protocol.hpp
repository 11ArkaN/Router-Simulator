// Value contracts for one forwarding-owned host endpoint stack. The endpoint
// has no topology or router access and persists only protocol values and wire
// frames. NetworkPlane is the sole owner that may configure or checkpoint it.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/packet.hpp"

#include <cstdint>
#include <vector>

namespace router {

struct NetworkEndpointConfiguration {
  // Each HostSlot owns exactly one stack, so configuration contains only its
  // protocol identity. Link and router state remain in their respective owners.
  packet::Mac endpoint_mac{};
  packet::Ipv4 endpoint_address{};
  std::uint8_t endpoint_prefix_length{};
  packet::Ipv4 endpoint_gateway{};
  std::uint16_t endpoint_mtu{device_catalog::default_host_ipv4_mtu};
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
  // Checkpoints store encoded bytes, never process-local pool handles. The
  // direction field identifies the endpoint slot in this bounded ABI record.
  NetworkFrameStage stage{};
  std::uint8_t direction{};
  bool routed{};
  packet::Ipv4 next_hop{};
  std::uint64_t remaining_ns{};
  packet::Frame frame{};
};

struct NetworkEndpointState {
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
  // One checkpoint belongs to one HostSlot. Keeping one endpoint value avoids
  // multiplying an obsolete starter-topology array across all sixteen hosts.
  NetworkEndpointState endpoint{};
  std::vector<NetworkStoredFrame> frames;
};

} // namespace router
