// Independent benchmark for SPSC, packet pool, FIB lookup and telemetry page.
// Isolation keeps these loops small enough for stable Wasm tiering and avoids
// changing the established packet-codec baseline when new structures are added.

#include "router/packet_pool.hpp"
#include "router/routing.hpp"
#include "router/spsc_ring.hpp"
#include "router/telemetry.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>

int main() {
  constexpr std::uint32_t iterations = 1000000;
  std::uint64_t sink{};
  router::SpscRing<std::uint32_t, 1024> ring;
  const auto ring_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    std::uint32_t value{};
    if (!ring.try_push(index) || !ring.try_pop(value)) return 2;
    sink += value & 1U;
  }
  const auto ring_elapsed = std::chrono::steady_clock::now() - ring_started;

  auto pool = std::make_unique<router::PacketPool>();
  router::packet::Frame frame;
  frame.length = 60;
  const auto pool_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    const auto handle = pool->allocate(frame);
    if (!handle) return 3;
    sink += pool->get(*handle).size();
    pool->release(*handle);
  }
  const auto pool_elapsed = std::chrono::steady_clock::now() - pool_started;

  router::routing::FibProgram fib{.generation = 1, .count = 2};
  fib.entries[0] = {0xc0000200U, 24, 0, 0};
  fib.entries[1] = {0xc6336400U, 24, 1, 0};
  const auto fib_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    std::uint8_t port{};
    if (!router::routing::lookup(fib, index & 1U ? 0xc0000202U : 0xc6336402U, port)) return 4;
    sink += port;
  }
  const auto fib_elapsed = std::chrono::steady_clock::now() - fib_started;

  router::TelemetryPageV1 page;
  const auto telemetry_started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    std::atomic_ref<std::uint32_t> sequence(page.sequence);
    sequence.store(index * 2U + 1U, std::memory_order_release);
    page.captured_frames = index;
    sequence.store(index * 2U + 2U, std::memory_order_release);
    sink += page.captured_frames & 1U;
  }
  const auto telemetry_elapsed = std::chrono::steady_clock::now() - telemetry_started;
  const auto ns = [](auto duration) {
    return static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count()) / iterations;
  };
  std::cout << "{\"ringNsPerRoundTrip\":" << ns(ring_elapsed)
            << ",\"packetPoolNsPerRoundTrip\":" << ns(pool_elapsed)
            << ",\"fibLookupNs\":" << ns(fib_elapsed)
            << ",\"telemetryPublishNs\":" << ns(telemetry_elapsed)
            << ",\"sink\":" << sink << "}\n";
}
