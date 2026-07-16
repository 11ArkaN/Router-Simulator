// Secondary control-shard owner for high-CPU hosts. The primary control owner
// publishes immutable per-device port facts. This worker owns the derived
// operational projection for its stable device partition and never borrows
// RouterHardwareInventory across threads.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/spsc_ring.hpp"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>
#include <type_traits>

namespace router::lab {

struct ControlPortProjectionInput {
  // Bit zero means the generated physical port exists. The remaining bits are
  // owner snapshots of independently configured administration and carrier.
  // A byte value avoids C++ bit-field ABI differences in shared Wasm memory.
  static constexpr std::uint8_t present = 1U;
  static constexpr std::uint8_t admin_enabled = 2U;
  static constexpr std::uint8_t link_signal = 4U;
  std::uint8_t flags{};
};

struct ControlProjectionCommand {
  // Producer: browser control Worker. Consumer: secondary control pthread.
  // Capacity is generated and overflow blocks the low-frequency snapshot
  // publisher instead of dropping an operational state update.
  std::uint64_t id{};
  std::uint16_t device_index{};
  std::uint16_t device_generation{};
  std::array<ControlPortProjectionInput,
             device_catalog::maximum_ports_per_router>
      ports{};
};

struct ControlProjectionResult {
  // Producer: secondary control pthread. Consumer: browser control Worker.
  // Result order equals command order because both directions are SPSC FIFO.
  std::uint64_t id{};
  std::uint16_t device_index{};
  std::uint16_t device_generation{};
  std::uint32_t inventory_ports{};
  std::uint32_t operational_ports{};
  std::array<std::uint8_t,
             (device_catalog::maximum_ports_per_router + 7U) / 8U>
      operational_bitset{};
};

static_assert(std::is_trivially_copyable_v<ControlProjectionCommand>);
static_assert(std::is_trivially_copyable_v<ControlProjectionResult>);

class ControlProjectionWorker final {
public:
  ControlProjectionWorker();
  ~ControlProjectionWorker();
  ControlProjectionWorker(const ControlProjectionWorker &) = delete;
  ControlProjectionWorker &operator=(const ControlProjectionWorker &) = delete;

  // submit and read are called only by the primary control owner. false means
  // the bounded ring currently applies backpressure; no partial value crossed.
  [[nodiscard]] bool submit(const ControlProjectionCommand &command) noexcept;
  [[nodiscard]] bool read(ControlProjectionResult &result) noexcept;
  [[nodiscard]] std::uint64_t thread_id() const noexcept {
    return thread_id_.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::uint64_t turns() const noexcept {
    return turns_.load(std::memory_order_acquire);
  }

private:
  void notify() noexcept;
  void run() noexcept;

  SpscRing<ControlProjectionCommand,
           device_catalog::network_command_ring_entries>
      commands_;
  SpscRing<ControlProjectionResult,
           device_catalog::network_result_ring_entries>
      results_;
  std::thread thread_;
  std::mutex wait_mutex_;
  std::condition_variable wait_condition_;
  std::atomic_bool stop_requested_{};
  std::atomic_uint64_t thread_id_{};
  std::atomic_uint64_t turns_{};
};

} // namespace router::lab
