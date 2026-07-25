// Stable C ABI for the current multi-device laboratory. One Web Worker owns
// one LabRuntime. Every returned pointer borrows runtime-owned immutable bytes
// until the next prepare call or lab_close, and no legacy runtime can coexist.

#include "router/generated_device_catalog.hpp"
#include "router/generated_lab_runtime_protocol.hpp"
#include "router/lab_checkpoint.hpp"
#include "router/lab_runtime.hpp"
#include "router/runtime_memory_growth.hpp"
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
#include <emscripten/heap.h>
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
// The Emscripten module's primary Worker owns page requests. Forwarding and
// protocol pthreads use startup-sized bounded arenas and never receive this
// object. The coordinator serializes growth against checkpoint preparation
// while leaving those already allocated packet paths running.
std::unique_ptr<router::lab::RuntimeMemoryGrowth> memory_growth;
// The Worker is the sole checkpoint ABI caller. This flag protects the
// borrowed prepared buffer from being published when a concurrent protocol
// allocation grew shared memory while the snapshot was being assembled.
bool prepared_checkpoint_valid{};

std::size_t platform_memory_size() noexcept {
#ifdef __EMSCRIPTEN__
  return emscripten_get_heap_size();
#else
  return router::device_catalog::wasm_initial_memory_bytes;
#endif
}

bool resize_platform_memory(std::size_t requested_size,
                            std::size_t &resulting_size,
                            void *) noexcept {
#ifdef __EMSCRIPTEN__
  // The generated Emscripten setting applies the fixed 64 MiB linear step.
  // This function is reachable only through RuntimeMemoryGrowth on the module
  // Worker, so no forwarding pthread can directly request WebAssembly pages.
  const bool resized = emscripten_resize_heap(requested_size);
  resulting_size = emscripten_get_heap_size();
  return resized || resulting_size >= requested_size;
#else
  // Native builds have no shared WebAssembly memory to resize. Unit tests use
  // the coordinator's injected fake rather than pretending native malloc is
  // the browser memory contract.
  resulting_size = platform_memory_size();
  return resulting_size >= requested_size;
#endif
}

std::uint32_t observe_memory_epoch() noexcept {
  if (!memory_growth)
    return 0U;
  // Standard-library allocations made by this same owner can consume an
  // already committed extension. Observing at every ABI projection publishes
  // any resulting extent before JavaScript constructs a new typed-array view.
  static_cast<void>(
      memory_growth->observe_owner_allocation(platform_memory_size()));
  return memory_growth->epoch();
}

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
  if (!memory_growth) {
    const auto initial = platform_memory_size();
    memory_growth = std::make_unique<router::lab::RuntimeMemoryGrowth>(
        initial, router::device_catalog::wasm_maximum_memory_bytes,
        router::device_catalog::wasm_growth_step_bytes,
        resize_platform_memory, nullptr);
  }
  if (!runtime)
    runtime = std::make_unique<router::lab::LabRuntime>();
  static_cast<void>(observe_memory_epoch());
  return 1;
}

RS_EXPORT int secret_vault_initialize(const std::uint8_t *wrapping_key,
                                      std::size_t wrapping_key_size,
                                      const std::uint8_t *context,
                                      std::size_t context_size) {
  // JavaScript owns allocation and erasure of the transient input. The C++
  // boundary rejects null and empty views before constructing std::span.
  if (!runtime || !wrapping_key || wrapping_key_size != 32U || !context ||
      !context_size)
    return 0;
  return runtime->initialize_secret_vault(
             {wrapping_key, wrapping_key_size}, {context, context_size})
             ? 1
             : 0;
}

RS_EXPORT std::uint32_t memory_epoch() {
  // Calling this function is an observation, not a barrier. Packet workers do
  // not stop and no owner relinquishes state while JavaScript refreshes views.
  return observe_memory_epoch();
}

RS_EXPORT std::size_t memory_size() {
  static_cast<void>(observe_memory_epoch());
  return memory_growth ? memory_growth->size() : platform_memory_size();
}

RS_EXPORT int memory_reserve(std::size_t minimum_total_size) {
  if (!memory_growth)
    return 0;
  const auto result = memory_growth->reserve(minimum_total_size);
  using enum router::lab::MemoryReserveResult;
  return result == unchanged || result == grown ? 1 : 0;
}

RS_EXPORT const char *runtime_capabilities() {
  // Values come from generated schemas and the compiled shared layout. The UI
  // may reject an incompatible artifact before it submits a project operation.
  std::ostringstream out;
  out << "{\"abiVersion\":" << router::telemetry_page_v6_abi
      << ",\"protocolVersion\":" << router::lab_runtime_protocol::version
      << ",\"threads\":true"
      << ",\"sharedTelemetry\":true,\"checkpoint\":"
      << router::lab::checkpoint_v7::abi << ",\"release\":\""
      << router::device_catalog::release << '"'
      << ",\"maximumRouters\":" << router::device_catalog::maximum_routers
      << ",\"memoryInitial\":"
      << router::device_catalog::wasm_initial_memory_bytes
      << ",\"memoryMaximum\":"
      << router::device_catalog::wasm_maximum_memory_bytes
      << ",\"memoryGrowthStep\":"
      << router::device_catalog::wasm_growth_step_bytes
      << '}';
  return publish_response(out.str());
}

RS_EXPORT void lab_close() {
  // Destruction joins runtime threads before any shared state is released.
  runtime.reset();
  terminal_output_size = 0;
  terminal_output_arena[0] = '\0';
  prepared_checkpoint_valid = false;
}

RS_EXPORT const char *lab_submit_command(const char *command) {
  return publish_response(runtime
                              ? runtime->command(command ? command : "")
                              : "ERROR: multi-router runtime is not initialized");
}

RS_EXPORT const router::TelemetryPageV6 *telemetry_get_page() {
  return runtime ? &runtime->telemetry_page() : nullptr;
}

RS_EXPORT std::size_t telemetry_get_page_size() {
  return runtime ? sizeof(router::TelemetryPageV6) : 0U;
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
  out << "{\"abi\":" << router::telemetry_page_v6_abi
      << ",\"size\":" << sizeof(router::TelemetryPageV6)
      << ",\"sequence\":" << offsetof(router::TelemetryPageV6, sequence)
      << ",\"abiVersion\":" << offsetof(router::TelemetryPageV6, abi_version)
      << ",\"workerCount\":" << offsetof(router::TelemetryPageV6, worker_count)
      << ",\"workerDirectory\":" << offsetof(router::TelemetryPageV6, workers)
      << ",\"workerBlockSize\":" << sizeof(router::WorkerTelemetryV6)
      << ",\"workerRole\":" << offsetof(router::WorkerTelemetryV6, role)
      << ",\"workerRunning\":" << offsetof(router::WorkerTelemetryV6, running)
      << ",\"workerThreadId\":" << offsetof(router::WorkerTelemetryV6, thread_id)
      << ",\"workerTurns\":" << offsetof(router::WorkerTelemetryV6, turns)
      << ",\"capturedFrames\":" << offsetof(router::TelemetryPageV6, captured_frames)
      << ",\"captureDropped\":" << offsetof(router::TelemetryPageV6, capture_dropped)
      << ",\"droppedPackets\":" << offsetof(router::TelemetryPageV6, dropped_packets)
      << ",\"deviceCount\":" << offsetof(router::TelemetryPageV6, device_count)
      << ",\"sessionCount\":" << offsetof(router::TelemetryPageV6, session_count)
      << ",\"deviceDirectory\":" << offsetof(router::TelemetryPageV6, devices)
      << ",\"deviceBlockSize\":" << sizeof(router::DeviceTelemetryV6)
      << ",\"deviceSequence\":" << offsetof(router::DeviceTelemetryV6, sequence)
      << ",\"deviceIndex\":" << offsetof(router::DeviceTelemetryV6, device_index)
      << ",\"deviceGeneration\":" << offsetof(router::DeviceTelemetryV6, device_generation)
      << ",\"deviceOperationalPorts\":" << offsetof(router::DeviceTelemetryV6, operational_ports)
      << ",\"deviceFibGeneration\":" << offsetof(router::DeviceTelemetryV6, fib_generation)
      << ",\"deviceReceivedPackets\":" << offsetof(router::DeviceTelemetryV6, received_packets)
      << ",\"deviceTransmittedPackets\":" << offsetof(router::DeviceTelemetryV6, transmitted_packets)
      << ",\"deviceDroppedPackets\":" << offsetof(router::DeviceTelemetryV6, dropped_packets)
      << ",\"sessionDirectory\":" << offsetof(router::TelemetryPageV6, sessions)
      << ",\"sessionBlockSize\":" << sizeof(router::SessionTelemetryV6)
      << ",\"portBitsets\":" << offsetof(router::TelemetryPageV6, port_oper_bitsets)
      << ",\"portBitsetBytes\":" << router::TelemetryPageV6::port_bitset_bytes << '}';
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

RS_EXPORT int capture_clear() {
  return runtime && runtime->clear_capture() ? 1 : 0;
}

RS_EXPORT const std::uint8_t *checkpoint_export() {
  if (!runtime)
    return nullptr;
  prepared_checkpoint_valid = false;
  if (!memory_growth || !memory_growth->begin_checkpoint())
    return nullptr;
  const auto bytes = runtime->export_checkpoint();
  // Encoding may use pages previously committed by this same owner. Publish a
  // new generation before ending the lease if the allocator extended memory;
  // no independent growth transaction could start during the preparation.
  static_cast<void>(
      memory_growth->observe_owner_allocation(platform_memory_size()));
  memory_growth->end_checkpoint();
  prepared_checkpoint_valid = !bytes.empty();
  return prepared_checkpoint_valid ? bytes.data() : nullptr;
}

RS_EXPORT std::size_t checkpoint_export_size() {
  return runtime && prepared_checkpoint_valid
             ? runtime->prepared_checkpoint().size()
             : 0U;
}

RS_EXPORT int checkpoint_import(const std::uint8_t *bytes, std::size_t size) {
  // The decoder stages a complete replacement and swaps only after every
  // registry, queue and device relationship passes validation.
  prepared_checkpoint_valid = false;
  return runtime && bytes && size && runtime->import_checkpoint({bytes, size}) ? 1 : 0;
}

}
