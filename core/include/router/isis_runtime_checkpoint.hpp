// One quiescent network coordinator owns the joined IS-IS image. Protocol,
// packet, route and physical transfer owners contribute detached values under
// one acknowledged cohort. No host clock epoch or runtime pointer is persisted.

#pragma once

#include "router/isis_control_checkpoint.hpp"
#include "router/network_transfer_checkpoint.hpp"

namespace router::lab {
struct IsisTransportPortCheckpoint {
  isis::CircuitIdentity identity;
  PortHandle port;
};
struct IsisInstalledRoutesCheckpoint {
  DeviceHandle device;
  std::uint64_t generation{};
  // The RIB owner retains its last accepted candidates independently of the
  // protocol's latest decision and possibly unconsumed installation receipt.
  std::vector<routing::DynamicInput> ipv4;
  std::vector<routing::Ipv6DynamicInput> ipv6;
};
struct IsisRuntimeCheckpoint {
  std::uint32_t version{1U};
  isis::ControlWorkerCheckpoint control;
  std::vector<protocol::PacketChannel<device_catalog::isis_packet_ring_frames>::Checkpoint> ingress;
  std::vector<IsisCheckpointEgress::Checkpoint> egress;
  ::router::routing::RoutePublication::Checkpoint routes;
  // Empty in the combined forwarding/link layout. Otherwise exactly one entry
  // per forwarding shard retains its physical transfer and completion FIFOs.
  std::vector<ForwardShardTransferCheckpoint> forwarding;
  std::vector<IsisTransportPortCheckpoint> ports;
  std::vector<IsisInstalledRoutesCheckpoint> installed;
};
// Coordinator only after both sides of every channel acknowledge quiescence.
// Child owner preparation separately validates configuration and mutable state.
// This join checks cohorts, transport credits, exact pending receipt identities,
// encoded LSP/SNP reservations and route generations without allocation or
// publication. Canceled stale queued generations remain ordinary deferred work.
[[nodiscard]] bool valid_isis_runtime_links(const IsisRuntimeCheckpoint &saved) noexcept;
} // namespace router::lab
