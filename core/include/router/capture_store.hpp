// Forwarding-owned incremental PCAPNG encoder. The packet path writes complete
// frame blocks into a byte stream and never retains a maximum-sized Frame per
// observation. The Worker drains immutable chunks to OPFS, so session length is
// bounded by project storage rather than a fixed WebAssembly capture arena.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/packet.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router {

using CapturePointId = std::uint32_t;

struct CapturePointCheckpoint {
  CapturePointId id{};
  std::string name;
  bool active{};
  std::uint64_t received{};
  std::uint64_t dropped{};
};

struct CaptureStoreCheckpoint {
  std::vector<CapturePointCheckpoint> points;
};

class CaptureStore final {
public:
  CaptureStore();

  // Forwarding-owner only. IDs may be sparse and are not limited by the
  // historic number of selections. Names become immutable PCAPNG IDB metadata
  // once emitted, so a changed name creates a new interface description.
  [[nodiscard]] bool configure_point(CapturePointId id,
                                     std::string_view name);
  [[nodiscard]] bool deactivate_point(CapturePointId id) noexcept;
  [[nodiscard]] bool point_active(CapturePointId id) const noexcept;

  // Appends one complete Enhanced Packet Block. false means either the point
  // is inactive or allocation failed. Allocation failure is recorded per IDB
  // and forwarding must continue without waiting for diagnostics.
  [[nodiscard]] bool record(CapturePointId capture_point,
                            const packet::Frame &frame,
                            std::uint64_t timestamp_us);

  // Finalizes a drain generation with Interface Statistics Blocks and swaps it
  // into an immutable view. Subsequent packets enter a fresh byte vector while
  // the caller copies prepared(). Multiple returned chunks concatenate into a
  // valid PCAPNG section.
  void encode();
  [[nodiscard]] std::span<const std::uint8_t> prepared() const noexcept {
    return prepared_;
  }

  // Starts a new PCAPNG section while preserving selected observation points.
  // The Worker must truncate its OPFS file in the same serialized operation.
  [[nodiscard]] bool clear_session() noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return record_count_; }

  [[nodiscard]] CaptureStoreCheckpoint checkpoint() const;
  [[nodiscard]] static bool
  validate_checkpoint(const CaptureStoreCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const CaptureStoreCheckpoint &state);

private:
  struct Point {
    CapturePointId id{};
    std::string name;
    std::uint32_t pcap_interface{};
    std::uint64_t received{};
    std::uint64_t dropped{};
    std::uint64_t reported_received{};
    std::uint64_t reported_dropped{};
    bool active{};
    bool described{};
  };

  [[nodiscard]] Point *find_point(CapturePointId id) noexcept;
  [[nodiscard]] const Point *find_point(CapturePointId id) const noexcept;
  void append_section_header();
  [[nodiscard]] bool describe(Point &point);
  [[nodiscard]] bool append_packet(Point &point, const packet::Frame &frame,
                                   std::uint64_t timestamp_us);
  void append_statistics(Point &point, std::uint64_t timestamp_us);

  // stream_ has no session-size ceiling. It contains only bytes produced since
  // the previous drain, not an array of 9212-byte record slots. prepared_ is
  // read-only until the next drain and is never touched by the packet path.
  // Only currently configured points live here. The vector is ordered by ID,
  // so packet observation is a logarithmic lookup without a hash allocation.
  // Crucially, memory depends on active capture points, not on the largest ID
  // ever issued during a long-lived lab session.
  std::vector<Point> points_;
  std::vector<std::uint8_t> stream_;
  std::vector<std::uint8_t> prepared_;
  std::size_t record_count_{};
  std::uint32_t next_pcap_interface_{};
};

} // namespace router
