// Stable C ABI between Emscripten Worker code and the C++ runtime supervisor.
// Borrowed buffers remain valid under the explicit prepare/read contracts.

#include "router/generated_runtime_protocol.hpp"
#include "router/runtime.hpp"

#include <cstddef>
#include <memory>
#include <sstream>
#include <string>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define RS_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define RS_EXPORT
#endif

namespace {
// The Web Worker owns the singleton runtime. It is never accessed from the DOM
// thread directly, and rs_shutdown destroys it before the worker terminates.
std::unique_ptr<router::Runtime> runtime;
// Emscripten callers receive a borrowed pointer. Thread-local storage keeps the
// previous command result valid until the next API call on the same worker.
thread_local std::string response;
} // namespace

extern "C" {

RS_EXPORT int rs_create() {
  // Idempotent creation simplifies worker boot retries without starting another
  // pair of control and forwarding pthreads.
  if (runtime)
    return 0;
  runtime = std::make_unique<router::Runtime>();
  return 1;
}

RS_EXPORT const char *rs_command(const char *command) {
  // Text is a low-frequency management ABI only. Packet bytes never cross this
  // boundary through JSON or postMessage.
  response = runtime ? runtime->command(command ? command : "")
                     : "ERROR: runtime is not initialized";
  return response.c_str();
}

RS_EXPORT int rs_capture_prepare() {
  // Preparing first creates an immutable contiguous PCAPNG projection. The next
  // two calls borrow its address and length without copying into JavaScript.
  if (!runtime)
    return 0;
  response = runtime->command(router::runtime_protocol::capture_prepare);
  return response.rfind("capture ready:", 0) == 0 ? 1 : 0;
}

RS_EXPORT const std::uint8_t *rs_capture_data() {
  // The pointer borrows CaptureStore's prepared vector and remains stable until
  // another prepare call or runtime destruction.
  const auto capture =
      runtime ? runtime->prepared_capture() : std::span<const std::uint8_t>{};
  return capture.empty() ? nullptr : capture.data();
}

RS_EXPORT std::size_t rs_capture_size() {
  // Size is read from the same prepared vector as rs_capture_data.
  return runtime ? runtime->prepared_capture().size() : 0;
}

// Destruction joins both pthread owners before releasing shared runtime state.
RS_EXPORT void rs_shutdown() { runtime.reset(); }

// The names below are the versioned product ABI. rs_* remains as a
// compatibility shim for the initial browser client. Preconditions, errors and
// ownership are identical to the delegated function and no wrapper exposes a
// C++ object. Versioned product entry point delegates to the compatibility
// constructor.
RS_EXPORT int runtime_initialize() { return rs_create(); }

RS_EXPORT const char *runtime_capabilities() {
  // Capabilities expose generated ABI and profile values, not implementation
  // guesses assembled by the Worker.
  response = "{\"abiVersion\":" +
             std::to_string(router::profile::runtime_snapshot_abi) +
             ",\"threads\":true,\"sharedTelemetry\":true,\"checkpoint\":" +
             std::to_string(router::profile::checkpoint_abi) +
             ",\"pthreadPoolMin\":" +
             std::to_string(router::profile::pthread_pool_min) +
             ",\"pthreadPoolMax\":" +
             std::to_string(router::profile::pthread_pool_max) +
             ",\"profile\":\"" + router::profile::id + "\"}";
  return response.c_str();
}

// Opening is idempotent from the product API while rs_create reports
// duplicates.
RS_EXPORT int lab_open() { return runtime ? 1 : rs_create(); }
// Closing delegates to the join-guaranteeing runtime shutdown.
RS_EXPORT void lab_close() { rs_shutdown(); }
// Lab commands retain the same bounded control mailbox contract as rs_command.
RS_EXPORT const char *lab_submit_command(const char *command) {
  return rs_command(command);
}
// The first milestone owns one persistent router CLI session inside Runtime.
RS_EXPORT int cli_open_session() { return runtime ? 1 : 0; }

RS_EXPORT const char *cli_push_input(const char *input) {
  // This compatibility call submits a complete line. Byte-level editing and
  // history remain in the terminal adapter until the dedicated stream ABI
  // lands.
  response = runtime
                 ? runtime->command(
                       std::string{router::runtime_protocol::terminal_execute} +
                       (input ? input : ""))
                 : "ERROR: runtime is not initialized";
  return response.c_str();
}

// Output borrows the last thread-local response produced on this Worker.
RS_EXPORT const char *cli_read_output() { return response.c_str(); }

RS_EXPORT const router::TelemetryPageV1 *telemetry_get_page() {
  // The page address is stable for Runtime lifetime and must be read by
  // seqlock.
  return runtime ? &runtime->telemetry_page() : nullptr;
}

RS_EXPORT std::size_t telemetry_get_page_size() {
  // Size and layout are queried from the same compiled C++ type.
  return runtime ? sizeof(router::TelemetryPageV1) : 0U;
}

RS_EXPORT const char *telemetry_get_layout() {
  // offsetof is evaluated by the same compiler that lays out shared memory.
  // JavaScript never duplicates alignment or padding assumptions.
  std::ostringstream out;
  out << "{\"abi\":" << router::profile::telemetry_abi
      << ",\"size\":" << sizeof(router::TelemetryPageV1)
      << ",\"sequence\":" << offsetof(router::TelemetryPageV1, sequence)
      << ",\"abiVersion\":" << offsetof(router::TelemetryPageV1, abi_version)
      << ",\"workerCount\":" << offsetof(router::TelemetryPageV1, worker_count)
      << ",\"portBitmap\":"
      << offsetof(router::TelemetryPageV1, port_oper_bitmap)
      << ",\"controlThreadId\":"
      << offsetof(router::TelemetryPageV1, control_thread_id)
      << ",\"forwardingThreadId\":"
      << offsetof(router::TelemetryPageV1, forwarding_thread_id)
      << ",\"capturedFrames\":"
      << offsetof(router::TelemetryPageV1, captured_frames)
      << ",\"captureDropped\":"
      << offsetof(router::TelemetryPageV1, capture_dropped)
      << ",\"droppedPackets\":"
      << offsetof(router::TelemetryPageV1, dropped_packets)
      << ",\"cliCancelRequested\":"
      << offsetof(router::TelemetryPageV1, cli_cancel_requested) << '}';
  response = out.str();
  return response.c_str();
}

RS_EXPORT int capture_start() {
  // Capture state changes through control so command ordering remains visible.
  if (!runtime)
    return 0;
  response = runtime->command(router::runtime_protocol::capture_start);
  return 1;
}

RS_EXPORT int capture_stop() {
  // Stopping observation never stops packet forwarding or link deadlines.
  if (!runtime)
    return 0;
  response = runtime->command(router::runtime_protocol::capture_stop);
  return 1;
}

// Product export prepares the same immutable PCAPNG buffer as the compatibility
// ABI.
RS_EXPORT int capture_export_pcapng() { return rs_capture_prepare(); }

RS_EXPORT const std::uint8_t *checkpoint_export() {
  // Borrow a structurally encoded checkpoint only after its forwarding barrier.
  if (!runtime)
    return nullptr;
  const auto bytes = runtime->export_checkpoint();
  return bytes.empty() ? nullptr : bytes.data();
}

RS_EXPORT std::size_t checkpoint_export_size() {
  // The size pairs with checkpoint_export's borrowed pointer.
  return runtime ? runtime->prepared_checkpoint().size() : 0U;
}

RS_EXPORT int checkpoint_import(const std::uint8_t *bytes, std::size_t size) {
  // Input bytes are borrowed only until Runtime stages its private copy.
  return runtime && bytes && runtime->import_checkpoint({bytes, size}) ? 1 : 0;
}

RS_EXPORT const char *project_export() {
  // Project export returns a validated operational snapshot, not shared memory.
  response = runtime ? runtime->command(router::runtime_protocol::snapshot)
                     : "ERROR: runtime is not initialized";
  return response.c_str();
}

RS_EXPORT int project_import(const char *project_command) {
  // Structured browser code creates this versioned project operation. The core
  // repeats semantic validation and reports failure without partial mutation.
  if (!runtime || !project_command)
    return 0;
  response = runtime->command(project_command);
  return response.rfind("ERROR:", 0) == 0 ? 0 : 1;
}
}
