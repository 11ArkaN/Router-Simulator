// A protocol producer attaches an expiry budget to its own encoded frame.
// Queue owners copy this value through release/acquire channels. Only the final
// transmitter mutates its exclusively owned bytes. Relative checkpoint age
// excludes time while the application is stopped and retains subsecond age.

#pragma once

#include "router/packet.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>

namespace router::protocol {
struct FrameExpiryCheckpoint {
  // Zero offset disables the descriptor. Otherwise this is a big-endian u16
  // lifetime field whose protocol permits mutation without reauthentication.
  std::uint16_t offset{};
  std::uint16_t prepaid_transit_seconds{};
  std::int64_t holding_nanoseconds{};
};
struct FrameExpiry {
  using Clock = std::chrono::steady_clock;
  static_assert(Clock::period::num == 1 && Clock::period::den == 1'000'000'000 &&
      std::numeric_limits<Clock::rep>::is_signed && sizeof(Clock::rep) == sizeof(std::int64_t));
  std::uint16_t offset{};
  std::uint16_t prepaid_transit_seconds{};
  std::int64_t prior_holding_nanoseconds{};
  Clock::time_point prepared{};

  // The current owner supplies its monotonic sample. Saturation means expired,
  // never wraparound. A future anchor refuses instead of inventing elapsed age.
  [[nodiscard]] std::optional<FrameExpiryCheckpoint> checkpoint(Clock::time_point now) const noexcept {
    if (!offset) return prepaid_transit_seconds || prior_holding_nanoseconds || prepared != Clock::time_point{}
        ? std::nullopt : std::optional{FrameExpiryCheckpoint{}};
    if (!prepaid_transit_seconds || prior_holding_nanoseconds < 0 || now < prepared) return std::nullopt;
    const auto elapsed = static_cast<std::uint64_t>(now.time_since_epoch().count()) -
        static_cast<std::uint64_t>(prepared.time_since_epoch().count());
    const auto limit = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    const auto prior = static_cast<std::uint64_t>(prior_holding_nanoseconds);
    const auto held = elapsed > limit - prior ? limit : elapsed + prior;
    return FrameExpiryCheckpoint{offset, prepaid_transit_seconds, static_cast<std::int64_t>(held)};
  }
  // Detached image validation precedes installation. No host clock epoch is
  // persisted. Caller must also validate offset against its actual wire image.
  [[nodiscard]] static std::optional<FrameExpiry> restore(const FrameExpiryCheckpoint &saved,
      Clock::time_point now) noexcept {
    if (saved.holding_nanoseconds < 0 || (!saved.offset &&
        (saved.prepaid_transit_seconds || saved.holding_nanoseconds)) ||
        (saved.offset && !saved.prepaid_transit_seconds)) return std::nullopt;
    return saved.offset ? FrameExpiry{saved.offset, saved.prepaid_transit_seconds,
        saved.holding_nanoseconds, now} : FrameExpiry{};
  }
  // Sole transmitter, exclusively owned frame, once before physical admission.
  // False leaves bytes unchanged and requires dropping the expired/invalid
  // frame. A zero wire lifetime is never manufactured from a live descriptor.
  [[nodiscard]] bool apply(packet::Frame &frame, Clock::time_point now,
      std::chrono::nanoseconds estimated_transit) const noexcept {
    const auto saved = checkpoint(now);
    if (!saved || estimated_transit.count() < 0) return false;
    if (!offset) return true;
    if (static_cast<std::size_t>(offset) + 1U >= frame.size()) return false;
    constexpr std::int64_t second = 1'000'000'000;
    const auto transit = estimated_transit.count() / second + (estimated_transit.count() % second != 0);
    const auto extra = std::max<std::int64_t>(0, transit - prepaid_transit_seconds);
    const auto decrement = saved->holding_nanoseconds / second + extra;
    const auto remaining = static_cast<std::uint16_t>((static_cast<std::uint16_t>(frame.bytes[offset]) << 8U) |
        frame.bytes[offset + 1U]);
    if (decrement >= remaining) return false;
    const auto aged = static_cast<std::uint16_t>(remaining - decrement);
    frame.bytes[offset] = static_cast<std::uint8_t>(aged >> 8U);
    frame.bytes[offset + 1U] = static_cast<std::uint8_t>(aged);
    return true;
  }
};
} // namespace router::protocol
