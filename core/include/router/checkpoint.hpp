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
  DeviceState device{};
  CliSession session{};
  std::uint64_t fib_generation{};
  std::uint64_t card_remaining_ns{};
  std::uint64_t mda_remaining_ns{};
};

[[nodiscard]] std::vector<std::uint8_t>
encode(const DeviceState &device, const CliSession &session,
       std::uint64_t fib_generation, std::chrono::steady_clock::time_point now);
[[nodiscard]] std::optional<Image> decode(std::span<const std::uint8_t> bytes);

} // namespace router::checkpoint
