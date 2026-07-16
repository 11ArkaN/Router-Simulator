// Forwarding-shard IPv4 pipeline for one router. It owns the installed FIB,
// port projection, ARP cache, pending resolution frames and forwarding counters.
// Every egress result remains an encoded Ethernet frame.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/multi_device_routing.hpp"
#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace router::lab {

enum class ForwardDrop : std::uint8_t {
  none,
  malformed,
  not_for_router,
  no_route,
  port_down,
  arp_pending_full,
  egress_queue_full,
  mtu_exceeded
};

struct ForwardPort {
  bool configured{};
  bool operational{};
  std::uint16_t ordinal{};
  std::uint16_t mtu{device_catalog::default_network_mtu};
  std::uint32_t address{};
  std::uint32_t network{};
  std::uint32_t speed_mbps{};
  std::uint8_t prefix_length{};
  packet::Mac mac{};
};

struct ForwarderAdjacencyCheckpoint {
  // Relative lifetime is clamped at zero during export. Restore anchors it to
  // the destination worker's current steady clock and never persists epochs.
  std::uint16_t port_ordinal{};
  std::uint32_t address{};
  packet::Mac mac{};
  std::int64_t remaining_nanoseconds{};
};

struct ForwarderPendingCheckpoint {
  // Pending packets retain exact encoded bytes and whether TTL processing has
  // already begun. No PacketPool handle crosses the checkpoint boundary.
  bool transit{};
  std::uint16_t port_ordinal{};
  std::uint32_t next_hop{};
  packet::Frame frame{};
};

struct RouterForwarderCheckpoint {
  std::vector<ForwardPort> ports;
  routing::FibProgram fib{};
  std::vector<ForwarderAdjacencyCheckpoint> adjacencies;
  std::vector<ForwarderPendingCheckpoint> pending;
  std::uint64_t forwarded_frames{};
  std::uint64_t dropped_frames{};
  ForwardDrop last_drop{ForwardDrop::none};
  std::uint16_t echo_reply_sequence{};
  bool echo_reply_valid{};
};

class RouterForwarder final {
public:
  using Clock = std::chrono::steady_clock;
  // Producer: this forwarding owner. Consumer: forwarding-to-link bounded
  // queue. false applies explicit tail drop without a direct delivery fallback.
  using EgressSink = bool (*)(void *context, std::uint16_t port_ordinal,
                              const packet::Frame &frame);
  using PuntObserver = void (*)(void *context, std::uint16_t ingress_port,
                                const packet::Frame &frame);

  [[nodiscard]] bool configure_port(const ForwardPort &port) noexcept;
  void remove_port(std::uint16_t ordinal) noexcept;
  [[nodiscard]] bool
  program_fib(const routing::FibProgram &program) noexcept;
  [[nodiscard]] bool originate_echo(std::uint32_t destination,
                                    std::uint16_t sequence, void *context,
                                    EgressSink sink,
                                    Clock::time_point now = Clock::now(),
                                    std::uint16_t payload_octets = 56,
                                    bool dont_fragment = false) noexcept;
  void receive(std::uint16_t ingress_port, const packet::Frame &frame,
               void *context, EgressSink sink,
               Clock::time_point now = Clock::now(),
               void *punt_context = nullptr,
               PuntObserver punt_observer = nullptr) noexcept;
  void expire(Clock::time_point now = Clock::now()) noexcept;

  // These cold-path operations require forwarding-shard affinity and a
  // quiesced owner turn. checkpoint returns values only. restore validates the
  // complete image before changing any live field and retains no input memory.
  [[nodiscard]] RouterForwarderCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const RouterForwarderCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const RouterForwarderCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] std::uint64_t forwarded_frames() const noexcept {
    return forwarded_frames_;
  }
  [[nodiscard]] std::uint64_t dropped_frames() const noexcept {
    return dropped_frames_;
  }
  [[nodiscard]] ForwardDrop last_drop() const noexcept { return last_drop_; }
  [[nodiscard]] std::size_t arp_entries() const noexcept;
  [[nodiscard]] std::size_t pending_frames() const noexcept;
  [[nodiscard]] bool received_echo_reply(std::uint16_t sequence) const noexcept {
    return echo_reply_valid_ && echo_reply_sequence_ == sequence;
  }

private:
  struct Adjacency {
    bool valid{};
    std::uint16_t port_ordinal{};
    std::uint32_t address{};
    packet::Mac mac{};
    Clock::time_point expires{};
  };

  struct Pending {
    // The original IPv4 frame is retained until ARP resolves. Transit frames
    // have not yet decremented TTL, ensuring one decrement at actual forwarding.
    bool valid{};
    bool transit{};
    std::uint16_t port_ordinal{};
    std::uint32_t next_hop{};
    packet::Frame frame{};
  };

  [[nodiscard]] const ForwardPort *port(std::uint16_t ordinal) const noexcept;
  [[nodiscard]] ForwardPort *port(std::uint16_t ordinal) noexcept;
  [[nodiscard]] Adjacency *find_adjacency(std::uint16_t port_ordinal,
                                         std::uint32_t address,
                                         Clock::time_point now) noexcept;
  void learn(std::uint16_t port_ordinal, std::uint32_t address, packet::Mac mac,
             Clock::time_point now) noexcept;
  void flush_pending(std::uint16_t port_ordinal, std::uint32_t address,
                     packet::Mac mac, void *context, EgressSink sink,
                     Clock::time_point now) noexcept;
  void send(packet::Frame frame, std::uint32_t destination, bool transit,
            void *context, EgressSink sink, Clock::time_point now) noexcept;
  void send_resolved(const packet::Frame &input, const ForwardPort &egress,
                     packet::Mac destination_mac, bool transit, void *context,
                     EgressSink sink, Clock::time_point now) noexcept;
  void send_time_exceeded(const packet::Frame &original,
                          const packet::Ipv4View &ip, void *context,
                          EgressSink sink, Clock::time_point now) noexcept;
  void send_fragmentation_needed(const packet::Frame &original,
                                 const packet::Ipv4View &ip,
                                 std::uint16_t next_hop_mtu, void *context,
                                 EgressSink sink,
                                 Clock::time_point now) noexcept;
  [[nodiscard]] bool may_send_icmp_error(
      const packet::Frame &original,
      const packet::Ipv4View &ip) const noexcept;
  [[nodiscard]] bool emit(std::uint16_t port_ordinal,
                          const packet::Frame &frame, void *context,
                          EgressSink sink) noexcept;
  void drop(ForwardDrop reason) noexcept;

  std::array<ForwardPort, device_catalog::maximum_ports_per_router> ports_{};
  routing::FibProgram fib_{};
  std::array<Adjacency, device_catalog::arp_entries_per_router> adjacencies_{};
  std::array<Pending, device_catalog::pending_ipv4_frames_per_router> pending_{};
  std::uint64_t forwarded_frames_{};
  std::uint64_t dropped_frames_{};
  ForwardDrop last_drop_{ForwardDrop::none};
  std::uint16_t echo_reply_sequence_{};
  bool echo_reply_valid_{};
};

} // namespace router::lab
