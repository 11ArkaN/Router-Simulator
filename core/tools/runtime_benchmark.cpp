// Runtime benchmark isolated from packet-path V8 tiering. It measures the
// control-to-forwarding quiescence barrier and structural checkpoint encoding
// with production memory sizes and real pthread ownership domains.

#include "router/runtime.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>

int main() {
  // Heap allocation matches browser lifetime and keeps the runtime's fixed
  // packet and capture stores away from the native executable stack.
  auto runtime = std::make_unique<router::Runtime>();

  // Checkpoints are intentionally fewer than packet benchmark iterations. Each
  // export crosses the worker quiescence boundary and serializes full state.
  constexpr std::uint32_t iterations = 100;
  std::uint64_t sink{};
  const auto started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    const auto checkpoint = runtime->export_checkpoint();
    if (checkpoint.empty())
      return 2;

    // Sampling a rotating byte proves the serialized result remains observable
    // without adding a full hash cost to the measured operation.
    sink += checkpoint[index % checkpoint.size()];
  }

  // Timing ends before JSON formatting so output handling cannot affect the
  // structural checkpoint regression threshold.
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - started);
  std::cout << "{\"checkpointExports\":" << iterations
            << ",\"checkpointExportNs\":"
            << static_cast<double>(elapsed.count()) / iterations
            << ",\"sink\":" << sink << "}\n";
}
