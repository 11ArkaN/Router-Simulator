// Stable shared page between the runtime and browser terminal. Runtime owns
// every telemetry field. The browser may atomically write only the documented
// CLI cancellation word, which carries intent rather than device state.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/generated_profile.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace router {

// The ABI number belongs beside the shared memory layout it identifies. Both
// the page initializer and capability serializers consume this constant so a
// layout revision cannot leave a stale hand-written version in another module.
inline constexpr std::uint32_t telemetry_page_v6_abi =
    profile::telemetry_abi;

struct alignas(64) DeviceTelemetryV6 {
  // Each device block has an independent writer sequence. A busy router cannot
  // force the browser to reject stable observations from unrelated devices.
  std::uint32_t sequence{};
  std::uint16_t device_index{0xffffU};
  std::uint16_t device_generation{};
  std::uint32_t status{};
  std::uint32_t inventory_ports{};
  std::uint32_t operational_ports{};
  std::uint32_t fib_generation{};
  std::uint32_t port_bitset_offset{};
  std::uint32_t port_bitset_bytes{};
  std::uint64_t received_packets{};
  std::uint64_t transmitted_packets{};
  std::uint64_t dropped_packets{};
};

struct alignas(32) SessionTelemetryV6 {
  // Session cancellation has one browser producer and one control consumer.
  // It is intentionally outside device seqlocks because it carries input
  // intent, not a projection of router state.
  std::uint16_t session_index{0xffffU};
  std::uint16_t session_generation{};
  std::uint16_t device_index{0xffffU};
  std::uint16_t device_generation{};
  std::uint8_t candidate_mode{};
  std::uint8_t engine{};
  std::uint8_t active{};
  std::uint8_t reserved{};
  alignas(4) std::uint32_t cancel_requested{};
};

enum class WorkerRoleV6 : std::uint8_t {
  control = 1,
  forwarding = 2,
  link = 3,
  forwarding_link = 4,
  ospf = 5
};

struct alignas(32) WorkerTelemetryV6 {
  // One runtime owner publishes each health record through the page seqlock.
  // thread_id is process-local and diagnostic only; it never enters a project
  // or checkpoint and may change after a complete runtime replacement.
  std::uint8_t role{};
  std::uint8_t shard_index{};
  std::uint8_t running{};
  std::uint8_t reserved{};
  std::uint32_t status{};
  std::uint64_t thread_id{};
  std::uint64_t turns{};
};

struct alignas(64) TelemetryPageV6 {
  // Writer protocol: make sequence odd with release, write scalar fields, then
  // publish the next even value with release. Reader protocol: acquire-load an
  // even sequence before and after copying and retry if either value differs.
  // There is one producer and any number of UI readers. Overflow wraps modulo
  // 2^32 and remains safe because only equality and oddness are tested.
  std::uint32_t sequence{};
  std::uint32_t abi_version{telemetry_page_v6_abi};
  std::uint32_t byte_size{};
  std::uint32_t status{1};
  std::uint32_t worker_count{};
  std::uint32_t inventory_ports{};
  std::uint32_t operational_ports{};
  std::uint32_t port_oper_bitmap{};
  std::uint32_t fib_generation{};
  std::uint64_t captured_frames{};
  std::uint64_t capture_dropped{};
  std::uint64_t dropped_packets{};
  // Producer: browser terminal. Consumers: control and forwarding shards.
  // Zero means continue and one means cancel the active CLI operation. JS uses
  // Atomics.store/notify and C++ uses atomic_ref acquire loads. The word is not
  // covered by the telemetry seqlock because the runtime publisher never
  // writes it while an operation is active.
  alignas(4) std::uint32_t cli_cancel_requested{};
  std::uint32_t device_count{};
  std::uint32_t session_count{};
  std::uint32_t device_directory_offset{};
  std::uint32_t session_directory_offset{};
  std::uint32_t worker_directory_offset{};
  std::uint32_t port_bitsets_offset{};
  std::uint32_t port_bitset_bytes_per_device{};

  static constexpr std::size_t port_bitset_bytes =
      (device_catalog::maximum_ports_per_router + 7U) / 8U;
  std::array<DeviceTelemetryV6, device_catalog::maximum_routers> devices{};
  std::array<SessionTelemetryV6,
             device_catalog::maximum_routers *
                 device_catalog::maximum_sessions_per_router>
      sessions{};
  std::array<WorkerTelemetryV6, device_catalog::maximum_worker_domains>
      workers{};
  std::array<std::array<std::uint8_t, port_bitset_bytes>,
             device_catalog::maximum_routers>
      port_oper_bitsets{};
};

static_assert(std::is_standard_layout_v<DeviceTelemetryV6>);
static_assert(std::is_standard_layout_v<SessionTelemetryV6>);
static_assert(std::is_standard_layout_v<WorkerTelemetryV6>);
static_assert(std::is_standard_layout_v<TelemetryPageV6>);

} // namespace router
