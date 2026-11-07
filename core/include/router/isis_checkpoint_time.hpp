// IS-IS owners translate local monotonic points to exact relative nanoseconds.
// Inputs and returned values belong to the caller; no clock is read or shared.
// Checked integer arithmetic refuses unrepresentable capture/restore epochs.

#pragma once

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <ratio>

namespace router::isis::checkpoint_time {
using Clock = std::chrono::steady_clock;
// Both supported native/Wasm clocks use integer nanoseconds. A different
// toolchain must provide an exact checked conversion before sharing this ABI.
static_assert(std::ratio_equal_v<Clock::period, std::nano> &&
    std::numeric_limits<Clock::rep>::is_signed && sizeof(Clock::rep) == sizeof(std::int64_t));

// Same owner. Returns point-origin without signed overflow, or nullopt when
// their distance cannot fit the signed checkpoint field. No mutation occurs.
[[nodiscard]] inline std::optional<std::int64_t> offset(Clock::time_point point,
    Clock::time_point origin) noexcept {
  const auto a = point.time_since_epoch().count(), b = origin.time_since_epoch().count();
  const auto limit = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  if (a >= b) {
    const auto distance = static_cast<std::uint64_t>(a) - static_cast<std::uint64_t>(b);
    return distance <= limit ? std::optional{static_cast<std::int64_t>(distance)} : std::nullopt;
  }
  const auto distance = static_cast<std::uint64_t>(b) - static_cast<std::uint64_t>(a);
  if (distance > limit + 1U) return std::nullopt;
  return distance == limit + 1U ? std::numeric_limits<std::int64_t>::min() : -static_cast<std::int64_t>(distance);
}
// Same owner. Returns a point at origin+relative without changing either input;
// nullopt rejects an epoch shift beyond the host clock's representable range.
[[nodiscard]] inline std::optional<Clock::time_point> restore(std::int64_t relative,
    Clock::time_point origin) noexcept {
  const auto base = origin.time_since_epoch().count();
  if ((relative > 0 && base > std::numeric_limits<std::int64_t>::max() - relative) ||
      (relative < 0 && base < std::numeric_limits<std::int64_t>::min() - relative)) return std::nullopt;
  return Clock::time_point{Clock::duration{base + relative}};
}
} // namespace router::isis::checkpoint_time
