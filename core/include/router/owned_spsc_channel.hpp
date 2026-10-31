// Local control values move between one producer and one consumer. Each
// owner accesses a slot only during its lease. The two SPSC rings carry fixed
// handles; no pointer or container representation crosses a ring.

#pragma once

#include "router/spsc_ring.hpp"

#include <limits>
#include <optional>
#include <utility>

namespace router::protocol {

template <typename Value, std::size_t Capacity> class OwnedSpscChannel final {
  static_assert(Capacity > 0U && Capacity <= std::numeric_limits<std::uint32_t>::max());
  static_assert(std::is_nothrow_default_constructible_v<Value> && std::is_nothrow_move_assignable_v<Value>);
public:
  using Handle = std::uint32_t;
  struct Lease { Handle handle{}; Value *value{}; };
  OwnedSpscChannel() noexcept : available_count_(Capacity) {
    for (std::size_t index{}; index < Capacity; ++index)
      available_[index] = static_cast<Handle>(Capacity - index - 1U);
  }
  // Producer reserves exclusive edit ownership until publish or cancel.
  // Full applies backpressure without changing configuration. Reclamation
  // destroys consumed values only after acquiring their returned handles.
  [[nodiscard]] std::optional<Lease> acquire() noexcept {
    Handle handle{};
    while (returned_.try_pop(handle)) {
      values_[handle] = Value{};
      available_[available_count_++] = handle;
    }
    if (!available_count_) return std::nullopt;
    handle = available_[--available_count_];
    editing_[handle] = true;
    return Lease{handle, &values_[handle]};
  }
  // Producer release-publishes all value-owned allocations. Its lease ends
  // on success; it cannot inspect or modify that value until a later acquire.
  [[nodiscard]] bool publish(Handle handle) noexcept {
    if (handle >= Capacity || !editing_[handle] || !ready_.try_push(handle)) return false;
    editing_[handle] = false;
    return true;
  }
  // Producer cancels an unpublished edit, destroying its owned allocations.
  [[nodiscard]] bool cancel(Handle handle) noexcept {
    if (handle >= Capacity || !editing_[handle]) return false;
    values_[handle] = Value{};
    editing_[handle] = false;
    available_[available_count_++] = handle;
    return true;
  }
  // Consumer acquire-observes exclusive mutable ownership. It may move fields
  // into its state before release. Values own their data; external borrowed
  // references cannot outlive publication or create another mutable owner.
  [[nodiscard]] std::optional<Lease> receive() noexcept {
    Handle handle{};
    if (!ready_.try_pop(handle)) return std::nullopt;
    borrowed_[handle] = true;
    return Lease{handle, &values_[handle]};
  }
  // Consumer release-publishes the return before producer reuse. Sensitive
  // plaintext must be erased before this call. Duplicate/unknown returns
  // reject without corrupting credits. Nothing may access the released lease.
  [[nodiscard]] bool release(Handle handle) noexcept {
    if (handle >= Capacity || !borrowed_[handle] || !returned_.try_push(handle)) return false;
    borrowed_[handle] = false;
    return true;
  }
  [[nodiscard]] bool empty() const noexcept { return ready_.empty(); }

private:
  std::array<Value, Capacity> values_{};
  // Capacity usable FIFO entries plus one sentinel per ring. Roles reverse
  // for returned_. Both directions use release/acquire publication. Overflow
  // rejects work and never overwrites a live control value.
  SpscRing<Handle, Capacity + 1U> ready_;
  SpscRing<Handle, Capacity + 1U> returned_;
  std::array<Handle, Capacity> available_{};
  std::size_t available_count_{};
  std::array<bool, Capacity> editing_{}; // producer only
  std::array<bool, Capacity> borrowed_{}; // consumer only
};

} // namespace router::protocol
