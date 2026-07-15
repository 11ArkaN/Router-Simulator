// Fixed-capacity forwarding queue with explicit tail-drop semantics. One shard
// owns every instance; cross-thread traffic uses SpscRing instead.

#pragma once

#include <array>
#include <cstddef>
#include <type_traits>

namespace router {

// This queue belongs to one forwarding shard, so atomics would only add cost.
// Cross-thread queues use SpscRing. A full device queue rejects the packet and
// leaves the existing order intact.
template <typename T, std::size_t Capacity> class BoundedQueue final {
  // Trivial elements make queue movement deterministic and keep packet handles
  // free from hidden allocation, reference counting, or destructor work.
  static_assert(Capacity > 0);
  static_assert(std::is_trivially_copyable_v<T>);

public:
  [[nodiscard]] bool try_push(T value) noexcept {
    // Tail drop preserves every packet already admitted to the device queue.
    // Overwriting the oldest slot would hide congestion and reorder traffic.
    if (size_ == Capacity)
      return false;
    slots_[tail_] = value;
    tail_ = (tail_ + 1) % Capacity;
    ++size_;
    return true;
  }

  [[nodiscard]] bool try_pop(T &value) noexcept {
    // The caller owns value, so a successful pop transfers the handle without
    // extending the lifetime of the packet stored in the pool.
    if (!size_)
      return false;
    value = slots_[head_];
    head_ = (head_ + 1) % Capacity;
    --size_;
    return true;
  }

  [[nodiscard]] bool try_peek(T &value) const noexcept {
    // A link owner must verify downstream admission before transferring a
    // packet handle. Peeking keeps FIFO order when the in-flight list is full.
    if (!size_)
      return false;
    value = slots_[head_];
    return true;
  }

  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] bool full() const noexcept { return size_ == Capacity; }

  [[nodiscard]] bool copy_at(std::size_t offset, T &value) const noexcept {
    // Structural checkpoints inspect FIFO order without popping live handles.
    // The caller receives a value copy and cannot mutate queue storage.
    if (offset >= size_)
      return false;
    value = slots_[(head_ + offset) % Capacity];
    return true;
  }

  void clear() noexcept {
    // Clearing is legal only for the sole owner after it has released any
    // resources referenced by elements. This type cannot know handle policy.
    head_ = 0;
    tail_ = 0;
    size_ = 0;
  }

private:
  // Capacity is part of the type. Queue memory is therefore allocated once
  // with its owning shard and cannot grow during a packet burst.
  std::array<T, Capacity> slots_{};
  std::size_t head_{};
  std::size_t tail_{};
  std::size_t size_{};
};

} // namespace router
