// Versioned bounded messages exchanged by the runtime bridge and shard owners.
// Producers publish complete values through SPSC rings with release ordering;
// consumers acquire them and never receive pointers to another shard's state.

#pragma once

#include "router/network.hpp"
#include "router/routing.hpp"

#include <array>
#include <cstdint>

namespace router {

inline constexpr std::uint32_t runtime_message_version =
    profile::runtime_message_abi;

struct CommandMessage {
  // Producer: browser bridge. Consumer: control shard. Overflow causes command
  // submission to wait, so accepted commands are never silently discarded.
  std::uint64_t id{};
  // Capacity is generated with the shared-memory profile. Overflow is rejected
  // before enqueue and never truncates a management operation silently.
  std::array<char, profile::command_message_bytes> text{};
};

struct ResponseMessage {
  // Producer: control shard. Consumer: browser bridge. A response may consist
  // of several ordered chunks with the same id. `more` is published in the
  // same release operation as the bytes, so the consumer never observes a
  // terminal marker before its corresponding payload.
  std::uint64_t id{};
  bool more{};
  std::array<char, profile::response_message_bytes> text{};
};

enum class ForwardJobKind : std::uint8_t {
  router_ping,
  endpoint_ping,
  program_fib,
  configure_network,
  export_capture,
  checkpoint_barrier,
  restore_checkpoint,
  restore_adjacencies
};

struct ForwardJob {
  // Producer: control shard. Consumer: forwarding shard. Unused payloads remain
  // zero initialized. Fixed capacities bound copy time and shared-memory use.
  std::uint64_t id{};
  ForwardJobKind kind{};
  packet::Ipv4 destination{};
  std::uint8_t source_endpoint{};
  // Ping options are values selected by the CLI owner. Forwarding receives
  // them with the probe job so neither the packet codec nor the UI invents a
  // release default. The fixed-width payload keeps the mailbox ABI bounded.
  std::uint16_t payload_octets{profile::default_ping_payload_octets};
  bool dont_fragment{};
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
