// Browser ABI checkpoint tests exercise memory-epoch publication at the same
// boundary used by runtime.worker.ts. The C++ runtime and all mutable protocol
// owners remain behind the exported functions, so this test retains no native
// pointer after another ABI call.

#include "router/generated_device_catalog.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>

extern "C" {
int runtime_initialize();
std::uint32_t memory_epoch();
std::size_t memory_size();
int memory_reserve(std::size_t minimum_total_size);
void lab_close();
const std::uint8_t *checkpoint_export();
std::size_t checkpoint_export_size();
}

void wasm_api_tests() {
  using namespace router;
  if (!runtime_initialize())
    throw std::runtime_error("Wasm ABI could not initialize its runtime owner");

  // The test executable may start above the production initial size, but it
  // must remain inside the generated maximum and publish a stable epoch while
  // no allocation grows the heap.
  const auto before = memory_epoch();
  const auto bytes = memory_size();
  if (bytes < device_catalog::wasm_initial_memory_bytes ||
      bytes > device_catalog::wasm_maximum_memory_bytes ||
      memory_epoch() != before) {
    lab_close();
    throw std::runtime_error("Wasm memory epoch changed without heap growth");
  }

#ifdef __EMSCRIPTEN__
  // Force a real shared-memory grow in the linked Emscripten runtime. The
  // request is one byte beyond the current extent, but the generated linear
  // policy must commit a complete 64 MiB step and publish exactly one epoch.
  if (!memory_reserve(bytes + 1U)) {
    lab_close();
    throw std::runtime_error("allocator owner rejected an in-profile grow");
  }
  const auto grown_bytes = memory_size();
  if (grown_bytes != bytes + device_catalog::wasm_growth_step_bytes ||
      memory_epoch() != before + 1U) {
    lab_close();
    throw std::runtime_error("real Wasm growth violated step or epoch policy");
  }
#endif

  // A successful export publishes pointer and size as one generation. The
  // second size read remains valid until another prepare/import/close call.
  const auto *checkpoint = checkpoint_export();
  const auto checkpoint_size = checkpoint_export_size();
  if (!checkpoint || !checkpoint_size ||
      checkpoint_export_size() != checkpoint_size) {
    lab_close();
    throw std::runtime_error(
        "checkpoint ABI published a partial memory generation");
  }
  lab_close();
  if (checkpoint_export_size() != 0U)
    throw std::runtime_error("closed runtime retained a checkpoint view");
}
