// Stable shared page between the runtime and browser terminal. Runtime owns
// every telemetry field. The browser may atomically write only the documented
// CLI cancellation word, which carries intent rather than device state.

#pragma once

#include "router/generated_profile.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace router {

struct alignas(64) TelemetryPageV1 {
  // Writer protocol: make sequence odd with release, write scalar fields, then
  // publish the next even value with release. Reader protocol: acquire-load an
  // even sequence before and after copying and retry if either value differs.
  // There is one producer and any number of UI readers. Overflow wraps modulo
  // 2^32 and remains safe because only equality and oddness are tested.
  std::uint32_t sequence{};
  std::uint32_t abi_version{profile::telemetry_abi};
  std::uint32_t byte_size{};
  std::uint32_t status{1};
  std::uint32_t worker_count{profile::runtime_worker_count};
  std::uint32_t inventory_ports{};
  std::uint32_t operational_ports{};
  std::uint32_t port_oper_bitmap{};
  std::uint32_t fib_generation{};
  std::uint64_t control_thread_id{};
  std::uint64_t forwarding_thread_id{};
  std::uint64_t control_wakeups{};
  std::uint64_t forwarding_wakeups{};
  std::uint64_t max_scheduling_lag_ns{};
  std::uint64_t captured_frames{};
  std::uint64_t capture_dropped{};
  std::uint64_t dropped_packets{};
  // Producer: browser terminal. Consumers: control and forwarding shards.
  // Zero means continue and one means cancel the active CLI operation. JS uses
  // Atomics.store/notify and C++ uses atomic_ref acquire loads. The word is not
  // covered by the telemetry seqlock because the runtime publisher never
  // writes it while an operation is active.
  alignas(4) std::uint32_t cli_cancel_requested{};
};

static_assert(std::is_standard_layout_v<TelemetryPageV1>);

} // namespace router
