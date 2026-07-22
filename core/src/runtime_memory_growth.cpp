// Runtime allocator-owner implementation. This module knows no Emscripten API
// and can therefore be tested natively. wasm_api.cpp supplies the platform
// callback while this owner enforces ordering, step size and checkpoint rules.

#include "router/runtime_memory_growth.hpp"

#include <algorithm>
#include <limits>

namespace router::lab {

RuntimeMemoryGrowth::RuntimeMemoryGrowth(
    std::size_t initial_size, std::size_t maximum_size,
    std::size_t linear_step, MemoryResizeFunction resize_function,
    void *resize_context) noexcept
    : owner_(std::this_thread::get_id()), maximum_size_(maximum_size),
      linear_step_(linear_step), resize_function_(resize_function),
      resize_context_(resize_context), size_(initial_size) {}

bool RuntimeMemoryGrowth::is_owner() const noexcept {
  // std::thread::id is used only by the owner-affine control boundary. It is
  // never placed in shared Wasm memory or treated as a portable checkpoint ID.
  return std::this_thread::get_id() == owner_;
}

MemoryReserveResult
RuntimeMemoryGrowth::publish_size(std::size_t actual_size) noexcept {
  const auto previous = size_.load(std::memory_order_acquire);
  if (actual_size < previous || actual_size > maximum_size_)
    return MemoryReserveResult::invalid_observation;
  if (actual_size == previous)
    return MemoryReserveResult::unchanged;

  // Release publication makes the new extent visible before JavaScript can
  // observe its epoch. Wasm offsets remain valid; only external typed-array
  // views are rebuilt by the Worker bridge.
  size_.store(actual_size, std::memory_order_release);
  epoch_.fetch_add(1U, std::memory_order_acq_rel);
  return MemoryReserveResult::grown;
}

MemoryReserveResult
RuntimeMemoryGrowth::reserve(std::size_t minimum_size) noexcept {
  if (!is_owner())
    return MemoryReserveResult::owner_violation;

  const auto current = size_.load(std::memory_order_acquire);
  if (minimum_size <= current)
    return MemoryReserveResult::unchanged;
  if (!linear_step_ || !resize_function_ || minimum_size > maximum_size_)
    return minimum_size > maximum_size_
               ? MemoryReserveResult::maximum_exceeded
               : MemoryReserveResult::growth_failed;

  auto expected = Phase::idle;
  if (!phase_.compare_exchange_strong(expected, Phase::growing,
                                      std::memory_order_acq_rel,
                                      std::memory_order_acquire))
    return expected == Phase::checkpoint
               ? MemoryReserveResult::checkpoint_active
               : MemoryReserveResult::growth_failed;

  auto result = MemoryReserveResult::unchanged;
  while (size_.load(std::memory_order_acquire) < minimum_size) {
    const auto before = size_.load(std::memory_order_acquire);
    // Saturating addition prevents an overflowing request from wrapping below
    // the current extent. The maximum is a generated wasm32 platform limit.
    const auto room = maximum_size_ - before;
    const auto target = before + std::min(linear_step_, room);
    if (target == before) {
      result = MemoryReserveResult::maximum_exceeded;
      break;
    }

    std::size_t actual = before;
    if (!resize_function_(target, actual, resize_context_) || actual < target) {
      result = MemoryReserveResult::growth_failed;
      break;
    }
    const auto published = publish_size(actual);
    if (published != MemoryReserveResult::grown) {
      result = published == MemoryReserveResult::unchanged
                   ? MemoryReserveResult::growth_failed
                   : published;
      break;
    }
    result = MemoryReserveResult::grown;
  }

  // Release ends the transaction only after the extent and epoch have been
  // published. A later checkpoint acquire can therefore never observe a
  // committed buffer with the preceding generation number.
  phase_.store(Phase::idle, std::memory_order_release);
  return result;
}

bool RuntimeMemoryGrowth::begin_checkpoint() noexcept {
  if (!is_owner())
    return false;
  auto expected = Phase::idle;
  return phase_.compare_exchange_strong(expected, Phase::checkpoint,
                                        std::memory_order_acq_rel,
                                        std::memory_order_acquire);
}

void RuntimeMemoryGrowth::end_checkpoint() noexcept {
  if (!is_owner())
    return;
  auto expected = Phase::checkpoint;
  static_cast<void>(phase_.compare_exchange_strong(
      expected, Phase::idle, std::memory_order_release,
      std::memory_order_relaxed));
}

MemoryReserveResult RuntimeMemoryGrowth::observe_owner_allocation(
    std::size_t actual_size) noexcept {
  if (!is_owner())
    return MemoryReserveResult::owner_violation;
  return publish_size(actual_size);
}

std::size_t RuntimeMemoryGrowth::size() const noexcept {
  return size_.load(std::memory_order_acquire);
}

std::uint32_t RuntimeMemoryGrowth::epoch() const noexcept {
  return epoch_.load(std::memory_order_acquire);
}

bool RuntimeMemoryGrowth::growth_in_progress() const noexcept {
  return phase_.load(std::memory_order_acquire) == Phase::growing;
}

} // namespace router::lab
