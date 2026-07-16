// Worker tests verify real thread startup, SPSC overflow and ordered results.

#include "router/network_plane_worker.hpp"

#include <chrono>
#include <memory>
#include <stdexcept>
#include <thread>

void network_plane_worker_tests() {
  using namespace router::lab;
  {
    auto idle_channels = std::make_unique<NetworkPlaneChannels>();
    NetworkPlaneWorker idle{*idle_channels};
    idle.start();
    const auto startup_deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds{1};
    while (!idle.running() && std::chrono::steady_clock::now() < startup_deadline)
      std::this_thread::yield();
    const auto before = idle.owner_turns();
    std::this_thread::sleep_for(std::chrono::milliseconds{35});
    const auto after = idle.owner_turns();
    // One spurious condition-variable wake is tolerated. A 10 ms poll would
    // produce at least three turns in this interval and fails this contract.
    if (!idle.running() || after - before > 1U)
      throw std::runtime_error("idle network owner is polling without work");
    idle.stop();
  }
  // A command can carry a complete, generation-stamped FIB replacement. The
  // ring is consequently a persistent shared-memory arena, not call-local
  // scratch storage. Heap ownership in this test mirrors production and keeps
  // the fixed arena away from WebAssembly's intentionally small call stack.
  auto channels = std::make_unique<NetworkPlaneChannels>();
  NetworkPlaneWorker worker{*channels};
  // Capacity eight deliberately exposes seven usable SPSC entries. Filling it
  // before worker startup makes overflow deterministic and scheduler-independent.
  constexpr auto usable = router::device_catalog::network_command_ring_entries - 1U;
  for (std::uint16_t index = 0; index < usable; ++index) {
    NetworkCommand command;
    command.id = index + 1U;
    command.kind = NetworkCommandKind::add_router;
    command.device = {index, 1};
    if (!worker.submit(command))
      throw std::runtime_error("network command ring rejected an in-bound entry");
  }
  NetworkCommand overflow;
  overflow.id = router::device_catalog::network_command_ring_entries;
  overflow.kind = NetworkCommandKind::add_router;
  overflow.device = {static_cast<std::uint16_t>(usable), 1};
  if (worker.submit(overflow))
    throw std::runtime_error("network command ring hid bounded overflow");

  worker.start();
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds{2};
  std::uint64_t expected = 1;
  while (expected <= usable && std::chrono::steady_clock::now() < deadline) {
    NetworkResult result;
    if (!worker.read(result)) {
      std::this_thread::yield();
      continue;
    }
    if (!result.success || result.id != expected++)
      throw std::runtime_error("network worker reordered or rejected a command");
  }
  if (expected != router::device_catalog::network_command_ring_entries ||
      !worker.running())
    throw std::runtime_error("network worker did not execute on its owner thread");
  worker.stop();
}
