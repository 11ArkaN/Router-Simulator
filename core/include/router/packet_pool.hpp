#pragma once

#include "router/packet.hpp"

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
  static constexpr std::size_t bytes = 64U * 1024U * 1024U;

  PacketPool() : slots_(bytes / sizeof(packet::Frame)), free_() {
    // Reserving both vectors removes allocator activity from the steady-state
    // forwarding path. Reverse fill lets pop_back return low handles first.
    free_.reserve(slots_.size());
    for (std::size_t i = slots_.size(); i > 0; --i) {
      free_.push_back(static_cast<PacketHandle>(i - 1));
    }
  }

  [[nodiscard]] std::optional<PacketHandle> allocate(const packet::Frame& frame) noexcept {
    // Copying into pool-owned storage severs the lifetime dependency on the
    // stack frame used by a packet encoder or parser.
    if (free_.empty()) return std::nullopt;
    const auto handle = free_.back();
    free_.pop_back();
    slots_[handle] = frame;
    return handle;
  }

  [[nodiscard]] const packet::Frame& get(PacketHandle handle) const noexcept {
    // Handles are validated by ownership discipline rather than a branch on
    // every access. Only handles returned by allocate may reach this method.
    return slots_[handle];
  }

  // release must be called exactly once after the final owning queue pops the
  // handle. Tests compare available() before and after complete packet paths.
  void release(PacketHandle handle) noexcept { free_.push_back(handle); }
  [[nodiscard]] std::size_t available() const noexcept { return free_.size(); }

 private:
  // The forwarding shard is the only owner. Handles cross device queues, but
  // pointers never enter shared ABI or persisted state.
  std::vector<packet::Frame> slots_;
  std::vector<PacketHandle> free_;
};

}  // namespace router
