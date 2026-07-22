#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace router {

// The default is a trivial value copy. Packet-bearing message types may add an
// ADL overload that copies only their live frame prefix while preserving the
// same trivially-copyable shared-memory representation.
template <typename T> void spsc_copy(T &destination, const T &source) noexcept {
  destination = source;
}

// Sensitive control records use an explicit consuming pop. Volatile byte
// stores prevent an optimizer from leaving a project key in a released shared
// slot. Ordinary packet and command rings avoid this O(sizeof(T)) erase cost.
template <typename T> void spsc_secure_clear(T &value) noexcept {
  auto *bytes = reinterpret_cast<volatile std::uint8_t *>(&value);
  for (std::size_t index{}; index < sizeof(T); ++index)
    bytes[index] = 0U;
}

// The producer alone writes head and the consumer alone writes tail. Release on
// publication and acquire on observation make the copied slot visible without a
// lock. A full ring rejects work instead of overwriting network or CLI state.
template <typename T, std::size_t Capacity> class SpscRing {
  // One slot remains unused so equality of indices has one meaning: empty.
  // This avoids a shared count atomic on every enqueue and dequeue.
  static_assert(Capacity > 1);
  static_assert(std::is_trivially_copyable_v<T>);

public:
  [[nodiscard]] bool empty() const noexcept {
    // The consumer owns tail and uses acquire on producer-owned head. This is
    // a readiness hint for a condition-variable predicate, never a pop or an
    // additional ownership path for the slot bytes.
    return tail_.load(std::memory_order_relaxed) ==
           head_.load(std::memory_order_acquire);
  }

  [[nodiscard]] bool full() const noexcept {
    // The producer owns head and reads the consumer tail with acquire. This is
    // used only to sleep under result backpressure, while try_push remains the
    // authoritative admission operation after wakeup.
    const auto head = head_.load(std::memory_order_relaxed);
    return increment(head) == tail_.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::size_t producer_available() const noexcept {
    // Only the producer may use this admission snapshot. Its private head is
    // relaxed, while acquire observes all slots the consumer has released.
    // The consumer can only increase availability before subsequent pushes,
    // so one producer may safely preflight an indivisible packet batch.
    const auto head = head_.load(std::memory_order_relaxed);
    const auto tail = tail_.load(std::memory_order_acquire);
    return tail > head ? tail - head - 1U : Capacity - head + tail - 1U;
  }

  [[nodiscard]] bool try_push(const T &value) noexcept {
    // Only the producer mutates head. Its own previous value needs no fence.
    const auto head = head_.load(std::memory_order_relaxed);
    const auto next = increment(head);
    if (next == tail_.load(std::memory_order_acquire))
      return false;
    spsc_copy(slots_[head], value);
    // Release publishes all slot bytes before the consumer can observe head.
    head_.store(next, std::memory_order_release);
    return true;
  }

  [[nodiscard]] bool try_pop(T &value) noexcept {
    // Acquire pairs with producer release and makes the complete slot visible.
    const auto tail = tail_.load(std::memory_order_relaxed);
    if (tail == head_.load(std::memory_order_acquire))
      return false;
    spsc_copy(value, slots_[tail]);
    // Publishing tail permits reuse only after the slot copy has completed.
    tail_.store(increment(tail), std::memory_order_release);
    return true;
  }

  [[nodiscard]] bool try_pop_and_clear(T &value) noexcept {
    // The consumer clears the slot before release-publishing tail, so the
    // producer can never race a new write with the erasure of the old secret.
    const auto tail = tail_.load(std::memory_order_relaxed);
    if (tail == head_.load(std::memory_order_acquire))
      return false;
    spsc_copy(value, slots_[tail]);
    spsc_secure_clear(slots_[tail]);
    tail_.store(increment(tail), std::memory_order_release);
    return true;
  }

private:
  static constexpr std::size_t increment(std::size_t value) noexcept {
    // Wrap without a shared size counter. Capacity is compile-time data and
    // one deliberately unused slot distinguishes full from empty.
    return (value + 1) % Capacity;
  }

  std::array<T, Capacity> slots_{};
  // Cache line separation prevents producer and consumer indices from causing
  // avoidable cache ownership traffic on two physical pthreads.
  alignas(64) std::atomic_size_t head_{0};
  alignas(64) std::atomic_size_t tail_{0};
};

} // namespace router
