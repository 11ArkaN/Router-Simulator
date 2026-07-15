// Structural checkpoint codec for control and forwarding values. Queue stages
// and wire bytes are persisted, while pthreads, packet handles, condition
// variables and absolute steady-clock timestamps are deliberately excluded.

#pragma once

#include "router/device.hpp"
#include "router/network.hpp"

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
  NetworkCheckpointState forwarding{};
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
       std::uint64_t fib_generation, const NetworkCheckpointState &forwarding,
       std::chrono::steady_clock::time_point now);
// Decode validates family magic, ABI, profile and schema hashes, bounds and the
// terminal offset. Failure returns nullopt and exposes no partially decoded
// state.
[[nodiscard]] std::optional<Image>
decode(std::span<const std::uint8_t> bytes,
       std::chrono::steady_clock::time_point now);

} // namespace router::checkpoint
