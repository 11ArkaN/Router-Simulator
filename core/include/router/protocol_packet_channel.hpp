// Shared-memory frame channel between one producer shard and one consumer
// shard. Each instance has one fixed direction, selected by its owner aggregate.
// Handles cross two SPSC rings while storage remains in fixed shared slots.
// No pointer, vector or postMessage copy crosses the ownership boundary.

#pragma once

#include "router/lab_registry.hpp"
#include "router/packet.hpp"
#include "router/spsc_ring.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace router::protocol {

template <std::size_t Capacity, bool WithCompletions = false> class PacketChannel final {
  static_assert(Capacity > 0U);
  static_assert(Capacity <= std::numeric_limits<std::uint32_t>::max());

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

  struct Completion {
    Metadata metadata{};
    const packet::Frame *frame{};
    bool enqueued{};
  };

  PacketChannel() noexcept : available_count_(Capacity) {
    // Producer owns available_ and available_count_. Reverse order makes the
    // first acquired slot zero and gives deterministic tests and diagnostics.
    for (std::size_t index{}; index < Capacity; ++index)
      available_[index] =
          static_cast<Handle>(Capacity - index - 1U);
  }

  // Producer: exactly one sending shard. Consumer: exactly one receiving
  // shard. Ordering is FIFO. Full behavior is explicit packet backpressure:
  // false leaves the frame with the producer and changes no protocol state.
  [[nodiscard]] bool try_send(const Metadata &metadata,
                              const packet::Frame &frame) noexcept {
    if (frame.size() > frame.bytes.size()) return false;
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
    borrowed_[handle] = true;
    return Borrowed{.handle = handle,
                    .metadata = slot.metadata,
                    .frame = &slot.frame};
  }

  // Consumer returns exactly one handle after processing. A failure indicates
  // an ownership bug because the return ring has one slot for every possible
  // borrowed packet plus the SpscRing sentinel slot.
  [[nodiscard]] bool release(Handle handle) noexcept requires (!WithCompletions) {
    return release_slot(handle, handle);
  }

  // Completion-enabled egress requires the consumer's actual port-queue
  // enqueue result. Publishing into this channel is not physical transmission.
  // The returned handle and result share one release/acquire SPSC operation.
  [[nodiscard]] bool release(Handle handle, bool enqueued) noexcept requires WithCompletions {
    return release_slot(handle, Returned{handle, enqueued});
  }

  // Producer consumes each egress result before its slot can be reused. The
  // borrowed wire view remains valid until the next try_send on this channel;
  // process it before sending again. This call reclaims the slot and needs no
  // further release. No pointer crosses a ring: the producer derives this view
  // from its own fixed storage after acquiring the returned handle.
  [[nodiscard]] std::optional<Completion> try_completion() noexcept requires WithCompletions {
    Returned result{};
    if (!returned_.try_pop(result)) return std::nullopt;
    const auto &slot = slots_[result.handle];
    available_[available_count_++] = result.handle;
    return Completion{slot.metadata, &slot.frame, result.enqueued};
  }

  // Completion-enabled channels apply backpressure until the producer has
  // consumed the corresponding result, even when the consumer returned a slot.
  [[nodiscard]] std::size_t producer_available() noexcept {
    reclaim();
    return available_count_;
  }

private:
  struct Returned {
    Handle handle{};
    bool enqueued{};
  };
  using ReturnValue = std::conditional_t<WithCompletions, Returned, Handle>;
  struct Slot {
    Metadata metadata{};
    packet::Frame frame{};
  };

  [[nodiscard]] bool release_slot(Handle handle, ReturnValue value) noexcept {
    if (handle >= Capacity || !borrowed_[handle] || !returned_.try_push(value)) return false;
    borrowed_[handle] = false;
    return true;
  }

  void reclaim() noexcept {
    if constexpr (!WithCompletions) {
      Handle returned{};
      while (returned_.try_pop(returned)) available_[available_count_++] = returned;
    }
  }

  std::array<Slot, Capacity> slots_{};
  // Producer publishes initialized metadata/frame bytes with release ordering;
  // consumer acquires the ready handle before reading them. The return ring
  // release/acquire pair prevents slot reuse until the consumer is done.
  // Each direction has Capacity usable entries and preserves FIFO order.
  // SpscRing reserves one element to distinguish full from empty.
  SpscRing<Handle, Capacity + 1U> ready_;
  SpscRing<ReturnValue, Capacity + 1U> returned_;
  std::array<Handle, Capacity> available_{};
  std::size_t available_count_{};
  // Consumer alone tracks borrowed slots. Rejecting an unknown or duplicate
  // return prevents producer free-list corruption without another atomic.
  std::array<bool, Capacity> borrowed_{};
};

} // namespace router::protocol
