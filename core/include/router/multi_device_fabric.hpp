// Global point-to-point Ethernet medium for the multi-device laboratory.
// The link shard is the sole mutable-state owner. Forwarding shards submit
// encoded frames through bounded rings before calling this owner-facing API.

#pragma once

#include "router/bounded_queue.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/lab_registry.hpp"
#include "router/packet_pool.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace router::lab {

struct FabricFrameCheckpoint {
  packet::Frame frame{};
  // Zero for TX and RX stages. In-flight entries carry their remaining
  // delivery interval relative to the checkpoint barrier.
  std::int64_t delivery_remaining_nanoseconds{};
};

struct FabricDirectionCheckpoint {
  std::uint64_t bits_per_second{};
  std::int64_t propagation_nanoseconds{};
  std::int64_t transmitter_remaining_nanoseconds{};
  std::vector<FabricFrameCheckpoint> transmit;
  std::vector<FabricFrameCheckpoint> in_flight;
  std::vector<FabricFrameCheckpoint> receive;
};

struct FabricLinkCheckpoint {
  LinkHandle link{};
  std::array<PortHandle, 2> endpoints{};
  bool carrier{};
  std::array<FabricDirectionCheckpoint, 2> directions;
};

struct MultiDeviceFabricCheckpoint {
  std::vector<FabricLinkCheckpoint> links;
  std::uint64_t dropped_frames{};
};

class MultiDeviceFabric final {
public:
  using Clock = std::chrono::steady_clock;

  enum class DropReason : std::uint8_t {
    none,
    stale_link,
    carrier_down,
    packet_pool_full,
    transmit_queue_full
  };

  struct Delivery {
    // Delivery is a borrowed callback value. The frame reference remains valid
    // only during the callback because pool ownership is released immediately
    // afterwards. Consumers must copy or parse all required bytes synchronously.
    LinkHandle link;
    PortHandle source;
    PortHandle destination;
    const packet::Frame &frame;
  };

  using DeliveryObserver = void (*)(void *context, const Delivery &delivery);

  MultiDeviceFabric() noexcept;
  MultiDeviceFabric(const MultiDeviceFabric &) = delete;
  MultiDeviceFabric &operator=(const MultiDeviceFabric &) = delete;

  // configure publishes one full-duplex physical link only after both live
  // ports, rate and propagation are valid. Reconfiguration of the same handle
  // first drops its old medium-owned frames under the documented removal rule.
  [[nodiscard]] bool configure(LinkHandle link, PortHandle first,
                               PortHandle second,
                               std::uint64_t bits_per_second,
                               std::chrono::nanoseconds propagation,
                               bool carrier = false) noexcept;
  // remove invalidates the live medium but not TopologyRegistry intent. Every
  // queued or in-flight handle is released exactly once and counted as a drop.
  [[nodiscard]] bool remove(LinkHandle link) noexcept;
  // Carrier is independent from topology existence. A down transition drains
  // frames because an Ethernet link reset does not preserve transmitter state.
  [[nodiscard]] bool set_carrier(LinkHandle link, bool up) noexcept;

  // endpoint is zero for the first configured port and one for the second.
  // The method copies bytes into the shared pool and never calls a peer device.
  [[nodiscard]] DropReason enqueue(LinkHandle link, std::uint8_t endpoint,
                                   const packet::Frame &frame) noexcept;
  // enqueue_shared transfers an additional reference to the TX queue without
  // copying frame bytes. The caller and fabric must share this exact pool and
  // the caller retains its own reference until this method returns.
  [[nodiscard]] DropReason enqueue_shared(LinkHandle link,
                                          std::uint8_t endpoint,
                                          PacketHandle frame) noexcept;
  // The link owner may preflight all fragments from one source datagram. This
  // does not reserve medium capacity for a remote thread. It is used only in
  // combined owner mode, where no mutation can occur before the matching
  // enqueue sequence completes.
  [[nodiscard]] bool can_enqueue(LinkHandle link, std::uint8_t endpoint,
                                 std::size_t frames) const noexcept;
  // These pump methods run only on the link owner. The explicit time argument
  // supports deterministic native unit tests; production passes steady_clock.
  void pump_transmit(Clock::time_point now = Clock::now()) noexcept;
  void pump_delivery(void *context, DeliveryObserver observer,
                     Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_delivery() const noexcept;

  // Export and restore run only at a link-shard barrier. Queue order, encoded
  // bytes and relative deadlines are retained while pool handles remain local.
  [[nodiscard]] MultiDeviceFabricCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const MultiDeviceFabricCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const MultiDeviceFabricCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] std::size_t active_links() const noexcept {
    return active_links_;
  }
  [[nodiscard]] std::uint64_t dropped_frames() const noexcept {
    return dropped_frames_;
  }
  [[nodiscard]] std::size_t available_packets() const noexcept {
    return pool_.available();
  }
  // Switches are link-shard components and therefore share the medium pool.
  // This owner-only accessor must never be retained by control or forwarding
  // shards; it exists solely to make broadcast replication zero-copy.
  [[nodiscard]] PacketPool &packet_pool() noexcept { return pool_; }
  [[nodiscard]] std::size_t in_flight_frames() const noexcept {
    return PacketPool::capacity - free_in_flight_count_;
  }

private:
  static constexpr std::uint32_t no_in_flight = 0xffffffffU;

  struct Direction {
    // Ownership flow is TX queue -> global in-flight slab -> RX queue ->
    // callback. The direction owns only its linked-list head and transmitter
    // deadline, so 128 directions do not each reserve a worst-case frame list.
    BoundedQueue<PacketHandle, device_catalog::link_queue_capacity> tx;
    BoundedQueue<PacketHandle, device_catalog::link_queue_capacity> rx;
    std::uint64_t bits_per_second{};
    std::chrono::nanoseconds propagation{};
    Clock::time_point transmitter_available{};
    std::uint32_t in_flight_head{no_in_flight};
    std::uint32_t in_flight_tail{no_in_flight};
  };

  struct InFlightNode {
    // Nodes are globally shared but belong to exactly one direction while in
    // use. The direction-local linked list preserves Ethernet FIFO ordering.
    PacketHandle packet{};
    Clock::time_point delivered{};
    std::uint32_t next{no_in_flight};
  };

  struct Slot {
    // Slot index equals LinkHandle index, while generation rejects delayed work
    // after TopologyRegistry reuses the stable bounded storage location.
    std::uint16_t generation{};
    bool active{};
    bool carrier{};
    std::array<PortHandle, 2> endpoints{};
    std::array<Direction, 2> directions{};
  };

  [[nodiscard]] Slot *find(LinkHandle link) noexcept;
  [[nodiscard]] const Slot *find(LinkHandle link) const noexcept;
  void drain(Slot &slot, Clock::time_point now) noexcept;
  [[nodiscard]] std::optional<std::uint32_t>
  allocate_in_flight() noexcept;
  void release_in_flight(std::uint32_t index) noexcept;
  [[nodiscard]] std::chrono::nanoseconds
  serialization_time(std::uint64_t bits,
                     std::uint64_t bits_per_second) const noexcept;
  [[nodiscard]] DropReason enqueue_owned_reference(
      LinkHandle link, std::uint8_t endpoint, PacketHandle frame) noexcept;

  // One packet pool is shared by all 64 links. This makes laboratory-wide
  // memory pressure explicit instead of reserving 64 independent 64 MiB pools.
  PacketPool pool_;
  // The slab has one metadata node per possible packet-pool frame. It cannot
  // become the first exhausted resource, so there is no artificial 2048-frame
  // laboratory ceiling independent from the configured 64 MiB packet budget.
  std::array<InFlightNode, PacketPool::capacity> in_flight_{};
  std::array<std::uint32_t, PacketPool::capacity> free_in_flight_{};
  std::size_t free_in_flight_count_{PacketPool::capacity};
  std::array<Slot, device_catalog::maximum_links> slots_{};
  // Cursors are scheduler state, not modeled network state. Each owner turn
  // resumes after the last visited slot so a low stable handle has no priority.
  std::size_t transmit_cursor_{};
  std::size_t delivery_cursor_{};
  std::size_t active_links_{};
  std::uint64_t dropped_frames_{};
};

} // namespace router::lab
