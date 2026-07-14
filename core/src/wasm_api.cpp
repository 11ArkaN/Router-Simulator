// Stable C ABI between Emscripten Worker code and the C++ runtime supervisor.
// Borrowed buffers remain valid under the explicit prepare/read contracts.

#include "router/runtime.hpp"

#include <memory>
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
}

extern "C" {

RS_EXPORT int rs_create() {
  // Idempotent creation simplifies worker boot retries without starting another
  // pair of control and forwarding pthreads.
  if (runtime) return 0;
  runtime = std::make_unique<router::Runtime>();
  return 1;
}

RS_EXPORT const char* rs_command(const char* command) {
  // Text is a low-frequency management ABI only. Packet bytes never cross this
  // boundary through JSON or postMessage.
  response = runtime ? runtime->command(command ? command : "") : "ERROR: runtime is not initialized";
  return response.c_str();
}

RS_EXPORT int rs_capture_prepare() {
  // Preparing first creates an immutable contiguous PCAPNG projection. The next
  // two calls borrow its address and length without copying into JavaScript.
  if (!runtime) return 0;
  response = runtime->command("capture:prepare");
  return response.rfind("capture ready:", 0) == 0 ? 1 : 0;
}

RS_EXPORT const std::uint8_t* rs_capture_data() {
  const auto capture = runtime ? runtime->prepared_capture() : std::span<const std::uint8_t>{};
  return capture.empty() ? nullptr : capture.data();
}

RS_EXPORT std::size_t rs_capture_size() {
  return runtime ? runtime->prepared_capture().size() : 0;
}

RS_EXPORT void rs_shutdown() { runtime.reset(); }

// The names below are the versioned product ABI. rs_* remains as a compatibility
// shim for the initial browser client. Preconditions, errors and ownership are
// identical to the delegated function and no wrapper exposes a C++ object.
RS_EXPORT int runtime_initialize() { return rs_create(); }

RS_EXPORT const char* runtime_capabilities() {
  response = "{\"abiVersion\":3,\"threads\":true,\"sharedTelemetry\":true,"
             "\"checkpoint\":\"quiescent-v1\",\"profile\":\"7750-sr-7-iom4-e\"}";
  return response.c_str();
}

RS_EXPORT int lab_open() { return runtime ? 1 : rs_create(); }
RS_EXPORT void lab_close() { rs_shutdown(); }
RS_EXPORT const char* lab_submit_command(const char* command) { return rs_command(command); }
RS_EXPORT int cli_open_session() { return runtime ? 1 : 0; }

RS_EXPORT const char* cli_push_input(const char* input) {
  response = runtime ? runtime->command(std::string{"terminal:"} + (input ? input : ""))
                     : "ERROR: runtime is not initialized";
  return response.c_str();
}

RS_EXPORT const char* cli_read_output() { return response.c_str(); }

RS_EXPORT const router::TelemetryPageV1* telemetry_get_page() {
  return runtime ? &runtime->telemetry_page() : nullptr;
}

RS_EXPORT std::size_t telemetry_get_page_size() {
  return runtime ? sizeof(router::TelemetryPageV1) : 0U;
}

RS_EXPORT int capture_start() {
  if (!runtime) return 0;
  response = runtime->command("capture:start");
  return 1;
}

RS_EXPORT int capture_stop() {
  if (!runtime) return 0;
  response = runtime->command("capture:stop");
  return 1;
}

RS_EXPORT int capture_export_pcapng() { return rs_capture_prepare(); }

RS_EXPORT const std::uint8_t* checkpoint_export() {
  if (!runtime) return nullptr;
  const auto bytes = runtime->export_checkpoint();
  return bytes.empty() ? nullptr : bytes.data();
}

RS_EXPORT std::size_t checkpoint_export_size() {
  return runtime ? runtime->prepared_checkpoint().size() : 0U;
}

RS_EXPORT int checkpoint_import(const std::uint8_t* bytes, std::size_t size) {
  return runtime && bytes && runtime->import_checkpoint({bytes, size}) ? 1 : 0;
}

RS_EXPORT const char* project_export() {
  response = runtime ? runtime->command("snapshot") : "ERROR: runtime is not initialized";
  return response.c_str();
}

RS_EXPORT int project_import(const char* project_command) {
  if (!runtime || !project_command) return 0;
  response = runtime->command(project_command);
  return response.rfind("ERROR:", 0) == 0 ? 0 : 1;
}

}
