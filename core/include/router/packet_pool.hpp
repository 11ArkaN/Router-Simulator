#pragma once

#include "router/generated_profile.hpp"
#include "router/packet.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
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
  static constexpr std::size_t bytes = profile::packet_pool_bytes;

  PacketPool()
      : slots_(bytes / sizeof(packet::Frame)), free_(slots_.size()),
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
    slots_[handle] = frame;
    return handle;
  }

  [[nodiscard]] const packet::Frame &get(PacketHandle handle) const noexcept {
    // Handles are validated by ownership discipline rather than a branch on
    // every access. Only handles returned by allocate may reach this method.
    return slots_[handle];
  }

  // release must be called exactly once after the final owning queue pops the
  // handle. A pre-sized free list makes the noexcept contract real instead of
  // relying on std::vector capacity as an undocumented allocation invariant.
  void release(PacketHandle handle) noexcept {
    assert(free_count_ < free_.size());
    free_[free_count_++] = handle;
  }
  [[nodiscard]] std::size_t available() const noexcept { return free_count_; }

private:
  // The forwarding shard is the only owner. Handles cross device queues, but
  // pointers never enter shared ABI or persisted state.
  std::vector<packet::Frame> slots_;
  std::vector<PacketHandle> free_;
  std::size_t free_count_{};
};

} // namespace router
