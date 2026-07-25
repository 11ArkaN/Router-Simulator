// Vendor-neutral IEEE 802.1D learning bridge for one untagged broadcast
// domain. The link shard is the sole mutable owner of port state, FDB records,
// egress queues and aging deadlines. It receives complete Ethernet frames and
// returns complete frame handles only through physical egress ports.

#pragma once

#include "router/bounded_queue.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/packet_pool.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

struct SwitchPortConfiguration {
  std::uint32_t speed_mbps{};
  std::uint16_t mtu{};
  bool admin_enabled{};
  bool carrier{};
  bool operator==(const SwitchPortConfiguration &) const = default;
};

struct SwitchForwardResult {
  std::uint16_t admitted_egresses{};
  std::uint16_t congested_egresses{};
  bool learned_source{};
  bool malformed{};
};

struct SwitchFdbCheckpointEntry {
  packet::Mac address{};
  std::int64_t remaining_nanoseconds{};
  std::uint16_t port{};
};

struct SwitchQueuedFrameCheckpoint {
  packet::Frame frame{};
  std::uint16_t port{};
};

struct SwitchPortCheckpoint {
  SwitchPortConfiguration configuration{};
  bool configured{};
};

struct EthernetSwitchCheckpoint {
  std::vector<SwitchPortCheckpoint> ports;
  std::vector<SwitchFdbCheckpointEntry> fdb;
  std::vector<SwitchQueuedFrameCheckpoint> egress;
};

class EthernetSwitch final {
public:
  using Clock = std::chrono::steady_clock;

  struct BorrowedFrame {
    PacketHandle handle{};
    const packet::Frame *frame{};
  };

  // profile points into immutable generated storage. pool has the same link
  // shard owner and must outlive the switch, allowing multicast replication to
  // retain one immutable packet image instead of copying it per egress.
  EthernetSwitch(const device_catalog::EthernetSwitchProfile &profile,
                 PacketPool &pool);
  ~EthernetSwitch();

  [[nodiscard]] bool configure_port(
      std::uint16_t port,
      const SwitchPortConfiguration &configuration) noexcept;
  // The link owner reads this immutable snapshot only while applying a
  // carrier transition. Returning by value prevents callers from mutating the
  // switch-owned port state without validation and FDB flushing.
  [[nodiscard]] std::optional<SwitchPortConfiguration>
  port_configuration(std::uint16_t port) const noexcept;

  // ingress validates the complete Ethernet header before learning. A full
  // egress queue drops only that egress copy and does not undo learning or
  // delivery to uncongested ports, matching independent bridge port queues.
  [[nodiscard]] SwitchForwardResult
  ingress(std::uint16_t port, const packet::Frame &frame,
          Clock::time_point now = Clock::now()) noexcept;

  // The returned frame remains pool-owned until release(handle). Dequeue never
  // copies bytes and preserves FIFO ordering within one egress port.
  [[nodiscard]] std::optional<BorrowedFrame>
  dequeue(std::uint16_t port) noexcept;
  void release(PacketHandle handle) noexcept { pool_.release(handle); }

  // age removes only dynamic records whose monotonic deadline expired. Port
  // disable and carrier loss flush records learned on that port immediately.
  void age(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point>
  next_deadline() const noexcept;
  [[nodiscard]] std::size_t learned_addresses() const noexcept {
    return fdb_.size();
  }
  // Checkpoint access runs at the link-shard barrier. Remaining durations
  // preserve monotonic FDB aging across browser suspension without persisting
  // host steady_clock epochs.
  [[nodiscard]] EthernetSwitchCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      const device_catalog::EthernetSwitchProfile &profile,
      const EthernetSwitchCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const EthernetSwitchCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  struct FdbEntry {
    packet::Mac address{};
    Clock::time_point expires{};
    std::uint16_t port{};
  };

  struct Port {
    BoundedQueue<PacketHandle,
                 device_catalog::maximum_switch_queue_frames>
        egress;
    SwitchPortConfiguration configuration{};
    bool configured{};
  };

  [[nodiscard]] bool active(std::uint16_t port) const noexcept;
  void flush_port(std::uint16_t port) noexcept;

  const device_catalog::EthernetSwitchProfile &profile_;
  PacketPool &pool_;
  std::vector<Port> ports_;
  std::vector<FdbEntry> fdb_;
};

} // namespace router::lab
