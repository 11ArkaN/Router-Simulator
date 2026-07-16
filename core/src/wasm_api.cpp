// Stable C ABI for the current multi-device laboratory. One Web Worker owns
// one LabRuntime. Every returned pointer borrows runtime-owned immutable bytes
// until the next prepare call or lab_close, and no legacy runtime can coexist.

#include "router/generated_device_catalog.hpp"
#include "router/generated_lab_runtime_protocol.hpp"
#include "router/lab_checkpoint.hpp"
#include "router/lab_runtime.hpp"
#include "router/telemetry.hpp"

#include <cstddef>
#include <cstdint>
#include <array>
#include <algorithm>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define RS_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define RS_EXPORT
#endif

namespace {
// Only the Worker thread reads or replaces these values. RuntimeSupervisor
// internally owns its control and forwarding shards and joins them on reset.
std::unique_ptr<router::lab::LabRuntime> runtime;
// The browser Worker is the sole producer and JavaScript copies the returned
// UTF-8 bytes before submitting another command. One fixed process-lifetime
// arena therefore serves every router session without per-response heap growth
// or 64 per-session reservations. The network pthread never accesses it.
std::array<char, router::device_catalog::terminal_output_arena_bytes>
    terminal_output_arena{};
std::size_t terminal_output_size{};

const char *publish_response(std::string_view value) noexcept {
  // A single result has a smaller limit than the shared arena. Crossing it is
  // explicit backpressure at the synchronous ABI boundary, never truncation.
  constexpr std::string_view exhausted{
      "ERROR: terminal result exceeds the configured 1 MiB output limit"};
  if (value.size() > router::device_catalog::terminal_result_bytes)
    value = exhausted;
  if (value.size() + 1U > terminal_output_arena.size())
    value = "ERROR: terminal output arena is exhausted";
  std::copy(value.begin(), value.end(), terminal_output_arena.begin());
  terminal_output_size = value.size();
  terminal_output_arena[terminal_output_size] = '\0';
  return terminal_output_arena.data();
}
} // namespace

extern "C" {

RS_EXPORT int runtime_initialize() {
  // Startup retries are idempotent. They never allocate a second packet pool,
  // registry set or pthread domain inside the fixed shared Wasm memory.
  if (!runtime)
    runtime = std::make_unique<router::lab::LabRuntime>();
  return 1;
}

RS_EXPORT const char *runtime_capabilities() {
  // Values come from generated schemas and the compiled shared layout. The UI
  // may reject an incompatible artifact before it submits a project operation.
  std::ostringstream out;
  out << "{\"abiVersion\":" << router::telemetry_page_v5_abi
      << ",\"protocolVersion\":" << router::lab_runtime_protocol::version
      << ",\"threads\":true"
      << ",\"sharedTelemetry\":true,\"checkpoint\":"
      << router::lab::checkpoint_v5::abi << ",\"release\":\""
      << router::device_catalog::release << '"'
      << ",\"maximumRouters\":" << router::device_catalog::maximum_routers
      << '}';
  return publish_response(out.str());
}

RS_EXPORT void lab_close() {
  // Destruction joins runtime threads before any shared state is released.
  runtime.reset();
  terminal_output_size = 0;
  terminal_output_arena[0] = '\0';
}

RS_EXPORT const char *lab_submit_command(const char *command) {
  return publish_response(runtime
                              ? runtime->command(command ? command : "")
                              : "ERROR: multi-router runtime is not initialized");
}

RS_EXPORT const router::TelemetryPageV5 *telemetry_get_page() {
  return runtime ? &runtime->telemetry_page() : nullptr;
}

RS_EXPORT std::size_t telemetry_get_page_size() {
  return runtime ? sizeof(router::TelemetryPageV5) : 0U;
}

RS_EXPORT void telemetry_publish() {
  // The JavaScript Worker is the single caller, preserving LabRuntime control
  // affinity while pthread owners continue to publish through their mailboxes.
  if (runtime)
    runtime->refresh_telemetry();
}

RS_EXPORT const char *telemetry_get_layout() {
  // offsetof is evaluated by the compiler that produced the Wasm memory, so
  // JavaScript never reconstructs C++ alignment or padding assumptions.
  std::ostringstream out;
  out << "{\"abi\":" << router::telemetry_page_v5_abi
      << ",\"size\":" << sizeof(router::TelemetryPageV5)
      << ",\"sequence\":" << offsetof(router::TelemetryPageV5, sequence)
      << ",\"abiVersion\":" << offsetof(router::TelemetryPageV5, abi_version)
      << ",\"workerCount\":" << offsetof(router::TelemetryPageV5, worker_count)
      << ",\"workerDirectory\":" << offsetof(router::TelemetryPageV5, workers)
      << ",\"workerBlockSize\":" << sizeof(router::WorkerTelemetryV5)
      << ",\"workerRole\":" << offsetof(router::WorkerTelemetryV5, role)
      << ",\"workerRunning\":" << offsetof(router::WorkerTelemetryV5, running)
      << ",\"workerThreadId\":" << offsetof(router::WorkerTelemetryV5, thread_id)
      << ",\"workerTurns\":" << offsetof(router::WorkerTelemetryV5, turns)
      << ",\"capturedFrames\":" << offsetof(router::TelemetryPageV5, captured_frames)
      << ",\"captureDropped\":" << offsetof(router::TelemetryPageV5, capture_dropped)
      << ",\"droppedPackets\":" << offsetof(router::TelemetryPageV5, dropped_packets)
      << ",\"deviceCount\":" << offsetof(router::TelemetryPageV5, device_count)
      << ",\"sessionCount\":" << offsetof(router::TelemetryPageV5, session_count)
      << ",\"deviceDirectory\":" << offsetof(router::TelemetryPageV5, devices)
      << ",\"deviceBlockSize\":" << sizeof(router::DeviceTelemetryV5)
      << ",\"deviceSequence\":" << offsetof(router::DeviceTelemetryV5, sequence)
      << ",\"deviceIndex\":" << offsetof(router::DeviceTelemetryV5, device_index)
      << ",\"deviceGeneration\":" << offsetof(router::DeviceTelemetryV5, device_generation)
      << ",\"deviceOperationalPorts\":" << offsetof(router::DeviceTelemetryV5, operational_ports)
      << ",\"deviceFibGeneration\":" << offsetof(router::DeviceTelemetryV5, fib_generation)
      << ",\"deviceReceivedPackets\":" << offsetof(router::DeviceTelemetryV5, received_packets)
      << ",\"deviceTransmittedPackets\":" << offsetof(router::DeviceTelemetryV5, transmitted_packets)
      << ",\"deviceDroppedPackets\":" << offsetof(router::DeviceTelemetryV5, dropped_packets)
      << ",\"sessionDirectory\":" << offsetof(router::TelemetryPageV5, sessions)
      << ",\"sessionBlockSize\":" << sizeof(router::SessionTelemetryV5)
      << ",\"portBitsets\":" << offsetof(router::TelemetryPageV5, port_oper_bitsets)
      << ",\"portBitsetBytes\":" << router::TelemetryPageV5::port_bitset_bytes << '}';
  return publish_response(out.str());
}

RS_EXPORT const std::uint8_t *capture_export_pcapng() {
  if (!runtime)
    return nullptr;
  const auto bytes = runtime->prepare_capture();
  return bytes.empty() ? nullptr : bytes.data();
}

RS_EXPORT std::size_t capture_export_size() {
  return runtime ? runtime->prepared_capture().size() : 0U;
}

RS_EXPORT const std::uint8_t *checkpoint_export() {
  if (!runtime)
    return nullptr;
  const auto bytes = runtime->export_checkpoint();
  return bytes.empty() ? nullptr : bytes.data();
}

RS_EXPORT std::size_t checkpoint_export_size() {
  return runtime ? runtime->prepared_checkpoint().size() : 0U;
}

RS_EXPORT int checkpoint_import(const std::uint8_t *bytes, std::size_t size) {
  // The decoder stages a complete replacement and swaps only after every
  // registry, queue and device relationship passes validation.
  return runtime && bytes && size && runtime->import_checkpoint({bytes, size}) ? 1 : 0;
}

}
