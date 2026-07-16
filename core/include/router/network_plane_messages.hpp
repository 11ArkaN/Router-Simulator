// Versioned control-to-network and network-to-control messages. Both directions
// use one known producer and one known consumer and therefore require SPSC only.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/network_plane.hpp"
#include "router/spsc_ring.hpp"

#include <cstdint>

namespace router::lab {

inline constexpr std::uint32_t network_plane_message_version = 1;

enum class NetworkCommandKind : std::uint8_t {
  add_router,
  remove_router,
  add_host,
  remove_host,
  configure_port,
  remove_port,
  program_fib,
  configure_host,
  configure_link,
  remove_link,
  router_ping,
  host_ping,
  router_ping_status,
  host_ping_status,
  active_link_count,
  configure_capture_point,
  prepare_capture,
  capture_frame_count,
  capture_drop_count,
  packet_drop_count,
  prepare_router_checkpoint,
  prepare_checkpoint,
  restore_checkpoint,
  shutdown
};

struct NetworkCommand {
  // Producer: assigned control shard. Consumer: combined forwarding and link
  // shard. The fixed payload is copied into shared memory with release ordering.
  std::uint32_t version{network_plane_message_version};
  std::uint64_t id{};
  NetworkCommandKind kind{};
  DeviceHandle device{};
  HostHandle host{};
  LinkHandle link{};
  ForwardPort port{};
  routing::FibProgram fib{};
  HostNetworkProgram host_program{};
  NetworkLinkProgram link_program{};
  CapturePointProgram capture_program{};
  std::uint32_t destination{};
  packet::Ipv4 host_destination{};
  std::uint16_t sequence{};
  std::uint16_t payload_octets{56};
  bool dont_fragment{};
};

struct NetworkResult {
  // Producer: combined forwarding and link shard. Consumer: control shard.
  // Ring overflow is never ignored; the worker stops accepting another command
  // until the prior result can be published.
  std::uint32_t version{network_plane_message_version};
  std::uint64_t id{};
  NetworkCommandKind kind{};
  bool success{};
  // Query commands publish their scalar value here while success continues to
  // describe command validity. This avoids overloading false as both an absent
  // reply and a stale handle error.
  std::uint64_t value{};
};

struct NetworkPlaneChannels {
  // Capacity includes one deliberately unused SpscRing slot. Generated values
  // are emulator resources and not protocol or vendor scaling claims.
  SpscRing<NetworkCommand, device_catalog::network_command_ring_entries>
      commands;
  SpscRing<NetworkResult, device_catalog::network_result_ring_entries> results;
};

} // namespace router::lab
