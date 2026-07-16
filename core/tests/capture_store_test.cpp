// Capture tests verify stable 32-bit point identities, selection gating and
// retained PCAPNG records after their topology observation point is removed.

#include "router/capture_store.hpp"

#include <cstdint>
#include <stdexcept>

namespace {

std::uint32_t read32(std::span<const std::uint8_t> bytes,
                     std::size_t offset) {
  // PCAPNG written by CaptureStore is little-endian regardless of host order.
  return static_cast<std::uint32_t>(bytes[offset]) |
         static_cast<std::uint32_t>(bytes[offset + 1]) << 8 |
         static_cast<std::uint32_t>(bytes[offset + 2]) << 16 |
         static_cast<std::uint32_t>(bytes[offset + 3]) << 24;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void capture_store_tests() {
  router::CaptureStore capture;
  constexpr router::CapturePointId selected = 200;
  require(capture.configure_point(
              selected, "router:r7/system:R7/port:1/2/3/egress") &&
              capture.point_active(selected),
          "capture point selection rejected a stable high identifier");

  router::packet::Frame frame;
  frame.length = 60;
  frame.bytes[0] = 0x02;
  require(capture.record(selected, frame, 1234) &&
              capture.deactivate_point(selected) &&
              !capture.point_active(selected) &&
              !capture.record(selected, frame, 1235) && capture.size() == 1,
          "capture deactivation changed retained records or admitted new data");

  capture.encode();
  const auto bytes = capture.prepared();
  std::size_t offset = 28;
  const std::size_t interface_count = 1U;
  for (std::size_t index = 0; index < interface_count; ++index) {
    require(read32(bytes, offset) == 1,
            "capture export omitted a configured interface description");
    offset += read32(bytes, offset + 4);
  }
  require(read32(bytes, offset) == 6 &&
              read32(bytes, offset + 8) == interface_count - 1U &&
              read32(bytes, offset + 20) == frame.length,
          "retained frame did not map stable CapturePointId to compact PCAP ID");

  const auto checkpoint = capture.checkpoint();
  router::CaptureStore restored;
  require(restored.restore(checkpoint) && restored.size() == 1 &&
              !restored.point_active(selected),
          "capture checkpoint did not retain records and selection state");
  auto invalid = checkpoint;
  invalid.records.front().capture_point = 199;
  require(!restored.restore(invalid) && restored.size() == 1,
          "invalid capture checkpoint partially replaced retained records");
}
