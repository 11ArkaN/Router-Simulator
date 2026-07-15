#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <type_traits>

namespace router {

// The producer alone writes head and the consumer alone writes tail. Release on
// publication and acquire on observation make the copied slot visible without a
// lock. A full ring rejects work instead of overwriting network or CLI state.
template <typename T, std::size_t Capacity> class SpscRing {
  // One slot remains unused so equality of indices has one meaning: empty.
  // This avoids a shared count atomic on every enqueue and dequeue.
  static_assert(Capacity > 1);
  static_assert(std::is_trivially_copyable_v<T>);

public:
  [[nodiscard]] bool try_push(const T &value) noexcept {
    // Only the producer mutates head. Its own previous value needs no fence.
    const auto head = head_.load(std::memory_order_relaxed);
    const auto next = increment(head);
    if (next == tail_.load(std::memory_order_acquire))
      return false;
    slots_[head] = value;
    // Release publishes all slot bytes before the consumer can observe head.
    head_.store(next, std::memory_order_release);
    return true;
  }

  [[nodiscard]] bool try_pop(T &value) noexcept {
    // Acquire pairs with producer release and makes the complete slot visible.
    const auto tail = tail_.load(std::memory_order_relaxed);
    if (tail == head_.load(std::memory_order_acquire))
      return false;
    value = slots_[tail];
    // Publishing tail permits reuse only after the slot copy has completed.
    tail_.store(increment(tail), std::memory_order_release);
    return true;
  }

private:
  static constexpr std::size_t increment(std::size_t value) noexcept {
    return (value + 1) % Capacity;
  }

  std::array<T, Capacity> slots_{};
  // Cache line separation prevents producer and consumer indices from causing
  // avoidable cache ownership traffic on two physical pthreads.
  alignas(64) std::atomic_size_t head_{0};
  alignas(64) std::atomic_size_t tail_{0};
};

} // namespace router
