// Build-time memory-envelope proof for the maximum multi-router laboratory.
// Baseline arenas fit the initial allocation; later protocol-owned dynamic
// state may request fixed-step growth without changing any existing offset.

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
// UdpEndpoint keeps its payload blocks in one vector allocation that sizeof
// cannot observe. Every router may run a relay or later router-local service,
// so the initial-memory proof budgets the complete arena for all sixteen.
constexpr std::size_t router_udp_payload_arenas =
    device_catalog::maximum_routers *
    transport::UdpEndpoint::payload_arena_allocation_bytes;

// LabRuntime contains all fixed control registries, hardware inventory slots,
// telemetry and channel objects. Heap allocations with variable standard
// library overhead are covered by the explicit generated control reserve.
constexpr std::size_t maximum_live_storage =
    device_catalog::packet_pool_bytes + packet_pool_handles +
    device_catalog::capture_store_bytes +
    device_catalog::terminal_output_arena_bytes +
    device_catalog::runtime_control_reserve_bytes +
    router_forwarding_arenas + router_udp_payload_arenas +
    sizeof(MultiDeviceFabric) +
    sizeof(CaptureStore) + sizeof(LabRuntime) + device_catalog::wasm_stack_bytes;

static_assert(device_catalog::terminal_result_bytes <=
                  device_catalog::terminal_output_arena_bytes,
              "one terminal result cannot exceed its shared arena");
static_assert(maximum_live_storage <= device_catalog::wasm_initial_memory_bytes,
              "baseline 16-router arenas exceed initial WebAssembly memory");
static_assert(device_catalog::wasm_initial_memory_bytes <=
                  device_catalog::wasm_maximum_memory_bytes,
              "initial WebAssembly memory exceeds its growth ceiling");
static_assert(device_catalog::wasm_growth_step_bytes % (64U * 1024U) == 0U,
              "WebAssembly memory growth step must contain complete pages");

} // namespace
} // namespace router::lab::memory_budget
