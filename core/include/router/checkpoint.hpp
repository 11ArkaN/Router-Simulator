// Structural checkpoint codec for control-owned state. The format contains
// values only and deliberately excludes pthreads, queues, packet handles,
// condition variables and absolute steady-clock timestamps.

#pragma once

#include "router/device.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::checkpoint {

struct Image {
  // Image owns all decoded values. Remaining durations are relative and become
  // new steady-clock deadlines only after Runtime accepts the whole image.
  DeviceState device{};
  CliSession session{};
  std::uint64_t fib_generation{};
  std::array<std::uint64_t, profile::chassis_slots> card_remaining_ns{};
  std::array<std::uint64_t,
             profile::chassis_slots * profile::mda_slots_per_card>
      mda_remaining_ns{};
};

// Preconditions: called by control while forwarding is quiescent and now is a
// steady-clock sample from the same process. The returned vector owns its
// bytes.
[[nodiscard]] std::vector<std::uint8_t>
encode(const DeviceState &device, const CliSession &session,
       std::uint64_t fib_generation, std::chrono::steady_clock::time_point now);
// Decode validates family magic, ABI, profile and schema hashes, bounds and the
// terminal offset. Failure returns nullopt and exposes no partially decoded
// state.
[[nodiscard]] std::optional<Image> decode(std::span<const std::uint8_t> bytes);

} // namespace router::checkpoint
