// ISO periodic-transmission jitter. The circuit/process owner retains the
// nonzero PRNG state and its own deadlines; this helper owns no clock or queue.
// Dependencies are standard duration and fixed-width value types only.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace router::isis {

// ISO 10589 10.1: uniformly choose a period between 75% and 100% of base,
// with microsecond resolution. PRNG state is advanced on every draw and must
// be retained in the owning process's checkpoint. Zero state or nonpositive
// base returns nullopt without changing state. No allocation, on any owner.
// The caller anchors its next deadline before performing expiration work.
// Protocol-specific minimum spacing and the unjittered DIS Hello exception
// remain with the circuit scheduler, rather than being hidden in this helper.
[[nodiscard]] std::optional<std::chrono::microseconds> jittered_interval(
    std::chrono::microseconds base, std::uint64_t &random_state) noexcept;

} // namespace router::isis
