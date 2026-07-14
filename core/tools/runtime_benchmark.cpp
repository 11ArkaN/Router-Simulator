// Runtime benchmark isolated from packet-path V8 tiering. It measures the
// control-to-forwarding quiescence barrier and structural checkpoint encoding
// with production memory sizes and real pthread ownership domains.

#include "router/runtime.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>

int main() {
  auto runtime = std::make_unique<router::Runtime>();
  constexpr std::uint32_t iterations = 100;
  std::uint64_t sink{};
  const auto started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < iterations; ++index) {
    const auto checkpoint = runtime->export_checkpoint();
    if (checkpoint.empty()) return 2;
    sink += checkpoint[index % checkpoint.size()];
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - started);
  std::cout << "{\"checkpointExports\":" << iterations
            << ",\"checkpointExportNs\":"
            << static_cast<double>(elapsed.count()) / iterations
            << ",\"sink\":" << sink << "}\n";
}
