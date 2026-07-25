// Shared-memory packet-buffer channel between one forwarding shard producer
// and one OSPF control shard consumer. Handles cross two SPSC rings while frame
// storage remains in fixed shared slots. No pointer, vector or postMessage copy
// crosses the ownership boundary.

#pragma once

#include "router/lab_registry.hpp"
#include "router/packet.hpp"
#include "router/spsc_ring.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace router::ospf {

template <std::size_t Capacity> class PacketChannel final {
  static_assert(Capacity > 0U);

public:
  using Handle = std::uint32_t;

  struct Metadata {
    lab::DeviceHandle device{};
    std::uint64_t interface_id{};
    std::uint16_t physical_port_ordinal{};
  };

  struct Borrowed {
    Handle handle{};
    Metadata metadata{};
    const packet::Frame *frame{};
  };

  PacketChannel() noexcept : available_count_(Capacity) {
    // Producer owns available_ and available_count_. Reverse order makes the
    // first acquired slot zero and gives deterministic tests and diagnostics.
    for (std::size_t index{}; index < Capacity; ++index)
      available_[index] =
          static_cast<Handle>(Capacity - index - 1U);
  }

  // Producer: exactly one forwarding shard. Consumer: exactly one OSPF control
  // shard. Ordering is FIFO. Full behavior is explicit packet backpressure:
  // false leaves the frame with the producer and changes no protocol state.
  [[nodiscard]] bool try_send(const Metadata &metadata,
                              const packet::Frame &frame) noexcept {
    reclaim();
    if (available_count_ == 0U)
      return false;
    const auto handle = available_[--available_count_];
    auto &slot = slots_[handle];
    slot.metadata = metadata;
    packet::copy_frame(slot.frame, frame);
    if (!ready_.try_push(handle)) {
      available_[available_count_++] = handle;
      return false;
    }
    return true;
  }

  // The borrowed frame remains immutable until release(handle). The consumer
  // must decode or copy retained protocol state before returning the handle.
  [[nodiscard]] std::optional<Borrowed> try_receive() noexcept {
    Handle handle{};
    if (!ready_.try_pop(handle))
      return std::nullopt;
    const auto &slot = slots_[handle];
    return Borrowed{.handle = handle,
                    .metadata = slot.metadata,
                    .frame = &slot.frame};
  }

  // Consumer returns exactly one handle after processing. A failure indicates
  // an ownership bug because the return ring has one slot for every possible
  // borrowed packet plus the SpscRing sentinel slot.
  [[nodiscard]] bool release(Handle handle) noexcept {
    return handle < Capacity && returned_.try_push(handle);
  }

  [[nodiscard]] std::size_t producer_available() noexcept {
    reclaim();
    return available_count_;
  }

private:
  struct Slot {
    Metadata metadata{};
    packet::Frame frame{};
  };

  void reclaim() noexcept {
    Handle returned{};
    while (returned_.try_pop(returned))
      available_[available_count_++] = returned;
  }

  std::array<Slot, Capacity> slots_{};
  // SpscRing reserves one element to distinguish full from empty.
  SpscRing<Handle, Capacity + 1U> ready_;
  SpscRing<Handle, Capacity + 1U> returned_;
  std::array<Handle, Capacity> available_{};
  std::size_t available_count_{};
};

} // namespace router::ospf
