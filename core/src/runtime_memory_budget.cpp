// Build-time fixed-memory proof for the maximum multi-router laboratory. This
// translation unit owns no runtime state. It depends on the concrete bounded
// owner types so a layout change that exceeds 256 MiB fails compilation.

#include "router/capture_store.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/lab_runtime.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/packet_pool.hpp"
#include "router/router_forwarder.hpp"

#include <cstddef>

namespace router::lab::memory_budget {
namespace {

// PacketPool's Frame vector consumes the declared 64 MiB slab and its
// pre-sized free list consumes one handle per frame. MultiDeviceFabric embeds
// matching in-flight metadata in sizeof(MultiDeviceFabric).
constexpr std::size_t packet_pool_handles =
    PacketPool::capacity * sizeof(PacketHandle);

// Each possible SR-12 forwarding instance owns the maximum generated port,
// FIB, adjacency and unresolved-frame arrays. Smaller router profiles use the
// same bounded implementation and therefore require no separate estimate.
constexpr std::size_t router_forwarding_arenas =
    device_catalog::maximum_routers * sizeof(RouterForwarder);

// LabRuntime contains all fixed control registries, hardware inventory slots,
// telemetry and channel objects. Heap allocations with variable standard
// library overhead are covered by the explicit generated control reserve.
constexpr std::size_t maximum_live_storage =
    device_catalog::packet_pool_bytes + packet_pool_handles +
    device_catalog::capture_store_bytes +
    device_catalog::terminal_output_arena_bytes +
    device_catalog::runtime_control_reserve_bytes +
    router_forwarding_arenas + sizeof(MultiDeviceFabric) +
    sizeof(CaptureStore) + sizeof(LabRuntime) + device_catalog::wasm_stack_bytes;

static_assert(device_catalog::terminal_result_bytes <=
                  device_catalog::terminal_output_arena_bytes,
              "one terminal result cannot exceed its shared arena");
static_assert(maximum_live_storage <= device_catalog::wasm_initial_memory_bytes,
              "maximum 16-router storage exceeds fixed WebAssembly memory");

} // namespace
} // namespace router::lab::memory_budget
