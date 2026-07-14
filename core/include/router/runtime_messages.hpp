// Versioned bounded messages exchanged by the runtime bridge and shard owners.
// Producers publish complete values through SPSC rings with release ordering;
// consumers acquire them and never receive pointers to another shard's state.

#pragma once

#include "router/network.hpp"
#include "router/routing.hpp"

#include <array>
#include <cstdint>

namespace router {

inline constexpr std::uint32_t runtime_message_version = 1;

struct CommandMessage {
  // Producer: browser bridge. Consumer: control shard. Overflow causes command
  // submission to wait, so accepted commands are never silently discarded.
  std::uint64_t id{};
  std::array<char, 1024> text{};
};

struct ResponseMessage {
  // Producer: control shard. Consumer: browser bridge. Capacity covers the
  // bounded multi-ping response without allocating across pthread ownership.
  std::uint64_t id{};
  std::array<char, 16384> text{};
};

enum class ForwardJobKind : std::uint8_t {
  router_ping,
  endpoint_ping,
  program_fib,
  configure_network,
  export_capture,
  checkpoint_barrier,
  restore_adjacencies
};

struct ForwardJob {
  // Producer: control shard. Consumer: forwarding shard. Unused payloads remain
  // zero initialized. Fixed capacities bound copy time and shared-memory use.
  std::uint64_t id{};
  ForwardJobKind kind{};
  routing::FibProgram fib{};
  NetworkConfiguration network{};
  std::array<NetworkArpEntry, profile::port_count> restored_arp{};
};

struct ForwardResult {
  // Producer: forwarding shard. Consumer: control shard. One acknowledgement
  // is published for every accepted job, including explicit failure details.
  std::uint64_t id{};
  bool success{};
  std::uint32_t captured_frames{};
  std::uint32_t capture_drops{};
  std::uint8_t reply_ttl{};
  std::uint64_t rtt_us{};
  NetworkDrop drop_reason{NetworkDrop::none};
  std::array<NetworkArpEntry, profile::port_count> arp{};
  std::array<std::uint64_t, profile::port_count> rx_delta{};
  std::array<std::uint64_t, profile::port_count> tx_delta{};
};

} // namespace router
