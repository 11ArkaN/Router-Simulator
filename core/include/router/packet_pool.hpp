#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/packet.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace router {

using PacketHandle = std::uint32_t;

class PacketPool final {
public:
  // The budget is fixed at startup because shared Wasm memory does not grow in
  // the initial ABI. Exhaustion is reported as packet admission failure.
  // The size_t first operand also keeps larger future profiles from performing
  // the multiplication in 32 bits before widening the result.
  static constexpr std::size_t bytes = device_catalog::packet_pool_bytes;
  // Every pool slot can be in exactly one stage: a device queue, a link queue,
  // the physical medium or a receiver queue. Shared stage metadata therefore
  // never needs more entries than this exact frame capacity.
  static constexpr std::size_t capacity = bytes / sizeof(packet::Frame);

  PacketPool()
      : slots_(capacity), free_(slots_.size()),
        references_(slots_.size()),
        free_count_(slots_.size()) {
    // The free-list vector is sized, not merely reserved. Allocation and
    // release therefore mutate an index and never call the heap on the packet
    // path. Reverse fill makes the first returned handle zero.
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      free_[i] = static_cast<PacketHandle>(slots_.size() - i - 1U);
    }
  }

  [[nodiscard]] std::optional<PacketHandle>
  allocate(const packet::Frame &frame) noexcept {
    // Copying into pool-owned storage severs the lifetime dependency on the
    // stack frame used by a packet encoder or parser.
    if (free_count_ == 0)
      return std::nullopt;
    const auto handle = free_[--free_count_];
    packet::copy_frame(slots_[handle], frame);
    references_[handle] = 1U;
    return handle;
  }

  [[nodiscard]] const packet::Frame &get(PacketHandle handle) const noexcept {
    // Handles are validated by ownership discipline rather than a branch on
    // every access. Only handles returned by allocate may reach this method.
    return slots_[handle];
  }

  // retain adds one immutable consumer before a shared frame handle is copied
  // into another queue. The 16-bit counter exceeds the maximum generated
  // switch fanout while avoiding an atomic operation: one link/switch shard is
  // the sole owner of this pool and all references remain in its local queues.
  [[nodiscard]] bool retain(PacketHandle handle) noexcept {
    if (handle >= references_.size() || references_[handle] == 0U ||
        references_[handle] ==
            std::numeric_limits<std::uint16_t>::max())
      return false;
    ++references_[handle];
    return true;
  }

  // release removes one consumer reference. Only the last release returns the
  // slot to the pre-sized free list, so switch flooding shares one immutable
  // frame image without copying its jumbo envelope for every egress.
  void release(PacketHandle handle) noexcept {
    assert(handle < references_.size() && references_[handle] != 0U);
    if (--references_[handle] != 0U)
      return;
    assert(free_count_ < free_.size());
    free_[free_count_++] = handle;
  }
  [[nodiscard]] std::size_t available() const noexcept { return free_count_; }

private:
  // The forwarding shard is the only owner. Handles cross device queues, but
  // pointers never enter shared ABI or persisted state.
  std::vector<packet::Frame> slots_;
  std::vector<PacketHandle> free_;
  std::vector<std::uint16_t> references_;
  std::size_t free_count_{};
};

} // namespace router
