// Incremental capture tests verify complete maximum-size packet bytes, dynamic
// point IDs, concatenable drain generations, PCAPNG statistics and metadata-only
// runtime checkpoints. They deliberately inspect blocks instead of comparing a
// golden blob, so added standards-compliant options do not create brittle tests.

#include "router/capture_store.hpp"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

std::uint16_t read16(std::span<const std::uint8_t> bytes,
                     std::size_t offset) {
  return static_cast<std::uint16_t>(bytes[offset]) |
         static_cast<std::uint16_t>(bytes[offset + 1]) << 8U;
}

std::uint32_t read32(std::span<const std::uint8_t> bytes,
                     std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         static_cast<std::uint32_t>(bytes[offset + 1]) << 8U |
         static_cast<std::uint32_t>(bytes[offset + 2]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 3]) << 24U;
}

std::uint64_t read64(std::span<const std::uint8_t> bytes,
                     std::size_t offset) {
  return read32(bytes, offset) |
         static_cast<std::uint64_t>(read32(bytes, offset + 4U)) << 32U;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

std::size_t find_block(std::span<const std::uint8_t> bytes,
                       std::uint32_t type, std::size_t start = 0) {
  for (auto offset = start; offset + 12U <= bytes.size();) {
    const auto length = read32(bytes, offset + 4U);
    require(length >= 12U && !(length & 3U) && offset + length <= bytes.size(),
            "capture emitted an invalid PCAPNG block length");
    require(read32(bytes, offset + length - 4U) == length,
            "capture block trailer does not repeat its length");
    if (read32(bytes, offset) == type)
      return offset;
    offset += length;
  }
  return bytes.size();
}

} // namespace

void capture_store_tests() {
  // Capture identities are monotonic control-plane handles, not array offsets.
  // A restored long-lived project may legitimately carry an ID near uint32's
  // end while having only one active point. The old sparse-vector layout would
  // attempt a multi-gigabyte allocation here and reject an otherwise tiny
  // configuration.
  router::CaptureStore sparse;
  constexpr router::CapturePointId late_identity = 0xfffffff0U;
  require(sparse.configure_point(late_identity, "link:late/direction:1") &&
              sparse.point_active(late_identity) &&
              sparse.checkpoint().points.size() == 1U,
          "capture metadata still scales with the historic identity value");
  require(sparse.deactivate_point(late_identity) &&
              sparse.checkpoint().points.empty(),
          "retired capture metadata remained resident in the checkpoint");

  router::CaptureStore capture;
  constexpr router::CapturePointId selected = 2000U;
  require(capture.configure_point(
              selected, "router:r7/system:R7/port:1/2/3/egress") &&
              capture.point_active(selected),
          "capture rejected a point beyond the former 256-ID lifetime limit");

  router::packet::Frame frame;
  frame.length = static_cast<std::uint16_t>(frame.bytes.size());
  for (std::size_t index = 0; index < frame.size(); ++index)
    frame.bytes[index] = static_cast<std::uint8_t>(index * 37U);
  // The first octets form a QinQ Ethernet header. Capture is byte-opaque and
  // must retain both tags and the complete jumbo payload without snaplen loss.
  frame.bytes[12] = 0x88;
  frame.bytes[13] = 0xa8;
  frame.bytes[16] = 0x81;
  frame.bytes[17] = 0x00;
  require(capture.record(selected, frame, 1234U) && capture.size() == 1U,
          "capture did not admit a complete maximum-size Ethernet frame");

  const auto checkpoint = capture.checkpoint();
  require(checkpoint.points.size() == 1U &&
              checkpoint.points.front().received == 1U,
          "capture packet bytes leaked into the runtime recovery checkpoint");

  capture.encode();
  const auto first = capture.prepared();
  require(read32(first, 0) == 0x0a0d0d0aU,
          "first capture drain omitted the Section Header Block");
  const auto idb = find_block(first, 1U);
  const auto epb = find_block(first, 6U);
  const auto isb = find_block(first, 5U);
  require(idb < first.size() && epb < first.size() && isb < first.size(),
          "capture drain omitted IDB, EPB or Interface Statistics Block");
  require(read16(first, idb + 8U) == 1U &&
              read32(first, idb + 12U) == router::packet::maximum_frame_octets,
          "capture IDB does not describe full Ethernet frames");
  require(read32(first, epb + 20U) == frame.length &&
              read32(first, epb + 24U) == frame.length &&
              std::equal(frame.view().begin(), frame.view().end(),
                         first.begin() + static_cast<std::ptrdiff_t>(epb + 28U)),
          "capture truncated or modified maximum-size QinQ frame bytes");
  require(read16(first, isb + 20U) == 4U && read64(first, isb + 24U) == 1U &&
              read16(first, isb + 32U) == 5U && read64(first, isb + 36U) == 0U,
          "capture ISB omitted per-interface receive or drop counters");

  // A later drain contains only new blocks. Concatenating it after the first
  // generation stays valid because the IDB remains in the same PCAPNG section.
  frame.length = 64U;
  require(capture.record(selected, frame, 1235U),
          "capture did not continue after a drain boundary");
  capture.encode();
  const auto second = capture.prepared();
  require(find_block(second, 6U) < second.size() &&
              find_block(second, 1U) == second.size(),
          "capture drain repeated an IDB or lost the next packet block");

  router::CaptureStore restored;
  require(restored.restore(checkpoint) && restored.size() == 1U &&
              restored.point_active(selected),
          "capture checkpoint did not restore selection and counters");
  require(capture.deactivate_point(selected) &&
              !capture.point_active(selected) &&
              !capture.record(selected, frame, 1236U),
          "capture deactivation admitted a later packet");

  require(capture.configure_point(selected, "link:new/direction:0"),
          "capture could not reuse a released runtime ID as a new PCAP IDB");
  require(capture.clear_session(), "capture session clear succeeds");
  capture.encode();
  require(read32(capture.prepared(), 0U) == 0x0a0d0d0aU &&
              find_block(capture.prepared(), 1U) < capture.prepared().size() &&
              find_block(capture.prepared(), 6U) ==
                  capture.prepared().size() &&
              capture.size() == 0U,
          "capture clear retained an EPB from the previous session");
  // Record one distinguishable frame in the replacement session. Its prepared
  // generation must contain exactly one EPB, proving that clear neither
  // resurrects the old prepared vector nor appends the old stream after the
  // first post-reset packet.
  frame.length = 64U;
  std::fill_n(frame.bytes.begin(), frame.length, std::uint8_t{0xa5U});
  require(capture.record(selected, frame, 9'999U),
          "fresh capture session rejected its first packet");
  capture.encode();
  const auto fresh_epb = find_block(capture.prepared(), 6U);
  require(fresh_epb < capture.prepared().size() &&
              find_block(capture.prepared(), 6U,
                         fresh_epb + read32(capture.prepared(),
                                            fresh_epb + 4U)) ==
                  capture.prepared().size() &&
              std::equal(frame.view().begin(), frame.view().end(),
                         capture.prepared().begin() +
                             static_cast<std::ptrdiff_t>(fresh_epb + 28U)),
          "fresh capture generation mixed old and new packet blocks");

  // Cross the removed 32 MiB session boundary with real maximum-size EPBs.
  // This is intentionally a byte-volume regression, not a capacity constant:
  // the encoder may continue until allocator or persistent storage exhaustion.
  router::CaptureStore large;
  require(large.configure_point(1U, "link:volume/direction:0"),
          "large capture point configuration failed");
  frame.length = static_cast<std::uint16_t>(frame.bytes.size());
  for (std::size_t index = 0; index < 3700U; ++index)
    require(large.record(1U, frame, 10'000U + index),
            "capture retained the removed 32 MiB session ceiling");
  large.encode();
  require(large.prepared().size() > 32U * 1024U * 1024U &&
              large.size() == 3700U,
          "capture did not encode a generation larger than the former arena");
}
