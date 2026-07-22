// Independent benchmark for SPSC, packet pool, FIB lookup and telemetry page.
// Isolation keeps these loops small enough for stable Wasm tiering and avoids
// changing the established packet-codec baseline when new structures are added.

#include "router/packet_pool.hpp"
#include "router/multi_device_routing.hpp"
#include "router/ipv6_neighbor_cache.hpp"
#include "router/spsc_ring.hpp"
#include "router/telemetry.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>

int main() {
  // One million iterations amortize steady_clock calls and Wasm warmup while
  // retaining a short enough runtime for the mandatory verification command.
  constexpr std::uint32_t iterations = 1000000;
  std::uint64_t sink{};

  // Push and pop on one thread measure ring mechanics only. Cross-thread wakeup
  // policy belongs to the runtime benchmark and would obscure atomic overhead.
  router::SpscRing<std::uint32_t, 1024> ring;
  const auto ring_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    std::uint32_t value{};
    if (!ring.try_push(index) || !ring.try_pop(value))
      return 2;
    sink += value & 1U;
  }
  const auto ring_elapsed = std::chrono::steady_clock::now() - ring_started;

  // The pool loop verifies that allocation reuses fixed slots. Packet length is
  // nonzero so get() also exercises the handle to span projection.
  auto pool = std::make_unique<router::PacketPool>();
  router::packet::Frame frame;
  frame.length = 60;
  const auto pool_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    const auto handle = pool->allocate(frame);
    if (!handle)
      return 3;
    sink += pool->get(*handle).size();
    pool->release(*handle);
  }
  const auto pool_elapsed = std::chrono::steady_clock::now() - pool_started;

  // Alternating two prefixes prevents a compiler from folding the lookup to a
  // single constant result while keeping branch distribution reproducible.
  router::lab::routing::FibProgram fib{.generation = 1, .routes = {}, .count = 2};
  fib.routes[0] = {0xc0000200U, 0, 0, 24};
  fib.routes[1] = {0xc6336400U, 0, 1, 24};
  const auto fib_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    router::lab::routing::Route route;
    if (!router::lab::routing::lookup(
            fib, index & 1U ? 0xc0000202U : 0xc6336402U, route))
      return 4;
    sink += route.port_ordinal;
  }
  const auto fib_elapsed = std::chrono::steady_clock::now() - fib_started;

  // Preload enough neighbors to expose a linear-scan implementation while
  // keeping setup outside the measured interval. Lookups alternate across the
  // table and therefore exercise hashing and full-key verification rather than
  // repeatedly hitting one cache line.
  constexpr std::uint32_t neighbor_count{32768U};
  // Zero represents the absence of an interface throughout the forwarding
  // contract. The benchmark uses one ordinary logical interface identity so
  // every admitted entry satisfies the same scope validation as live ND.
  constexpr std::uint64_t neighbor_interface_id{1U};
  router::lab::Ipv6NeighborCache neighbors;
  const router::packet::Mac neighbor_mac{0x02U, 0U, 0U, 0U, 0U, 1U};
  const auto neighbor_now = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0U; index < neighbor_count; ++index) {
    router::ip::Ipv6 address{0x20U, 0x01U, 0x0dU, 0xb8U};
    address[12U] = static_cast<std::uint8_t>(index >> 24U);
    address[13U] = static_cast<std::uint8_t>(index >> 16U);
    address[14U] = static_cast<std::uint8_t>(index >> 8U);
    address[15U] = static_cast<std::uint8_t>(index);
    if (!neighbors.learn_stale(neighbor_interface_id, address, neighbor_mac, false,
                               neighbor_now))
      return 5;
  }
  const auto neighbor_started = std::chrono::steady_clock::now();
  for (std::uint32_t iteration = 0U; iteration < iterations; ++iteration) {
    const auto index =
        (iteration * 2654435761U) & (neighbor_count - 1U);
    router::ip::Ipv6 address{0x20U, 0x01U, 0x0dU, 0xb8U};
    address[12U] = static_cast<std::uint8_t>(index >> 24U);
    address[13U] = static_cast<std::uint8_t>(index >> 16U);
    address[14U] = static_cast<std::uint8_t>(index >> 8U);
    address[15U] = static_cast<std::uint8_t>(index);
    const auto found = neighbors.find(neighbor_interface_id, address);
    if (!found)
      return 6;
    sink += found->mac[5U];
  }
  const auto neighbor_elapsed =
      std::chrono::steady_clock::now() - neighbor_started;

  // Telemetry uses the same odd/even seqlock publication sequence as Runtime.
  // atomic_ref targets the ABI field without changing its plain-data layout.
  router::TelemetryPageV6 page;
  const auto telemetry_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    std::atomic_ref<std::uint32_t> sequence(page.sequence);
    sequence.store(index * 2U + 1U, std::memory_order_release);
    page.captured_frames = index;
    sequence.store(index * 2U + 2U, std::memory_order_release);
    sink += page.captured_frames & 1U;
  }
  const auto telemetry_elapsed =
      std::chrono::steady_clock::now() - telemetry_started;

  // Convert once after each measured loop. No formatting or floating-point work
  // is included in the reported nanoseconds per operation.
  const auto ns = [](auto duration) {
    return static_cast<double>(
               std::chrono::duration_cast<std::chrono::nanoseconds>(duration)
                   .count()) /
           iterations;
  };

  // sink makes every loaded value observable and blocks dead-code elimination.
  std::cout << "{\"ringNsPerRoundTrip\":" << ns(ring_elapsed)
            << ",\"packetPoolNsPerRoundTrip\":" << ns(pool_elapsed)
            << ",\"fibLookupNs\":" << ns(fib_elapsed)
            << ",\"ipv6NeighborLookupNs\":" << ns(neighbor_elapsed)
            << ",\"telemetryPublishNs\":" << ns(telemetry_elapsed)
            << ",\"sink\":" << sink << "}\n";
}
