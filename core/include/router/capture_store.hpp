// Forwarding-owned bounded capture storage and deterministic PCAPNG encoding.
// Live packet delivery never waits for capture memory or export serialization.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/packet.hpp"

#include <array>
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
};

struct CaptureRecordCheckpoint {
  std::uint64_t timestamp_us{};
  CapturePointId capture_point{};
  packet::Frame frame{};
};

struct CaptureStoreCheckpoint {
  std::vector<CapturePointCheckpoint> points;
  std::vector<CaptureRecordCheckpoint> records;
};

class CaptureStore final {
public:
  CaptureStore();

  // Point configuration is a low-frequency forwarding-owner command. IDs are
  // stable within one capture session. Deactivation stops future records but
  // deliberately retains the name needed to decode already captured frames.
  [[nodiscard]] bool configure_point(CapturePointId id,
                                     std::string_view name);
  [[nodiscard]] bool deactivate_point(CapturePointId id) noexcept;
  [[nodiscard]] bool point_active(CapturePointId id) const noexcept;

  // Preconditions: forwarding-shard affinity. false means diagnostics capacity
  // is exhausted; callers must continue packet delivery and count the drop.
  [[nodiscard]] bool record(CapturePointId capture_point,
                            const packet::Frame &frame,
                            std::uint64_t timestamp_us);
  // Preconditions: forwarding is quiescent at the caller's barrier. Encoding
  // replaces the prior immutable PCAPNG projection without altering records.
  void encode();
  // The span remains valid until the next encode or CaptureStore destruction.
  [[nodiscard]] std::span<const std::uint8_t> prepared() const noexcept {
    return prepared_;
  }
  // size reports retained records, excluding tail-dropped observations.
  [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }

  // Export is a forwarding-barrier copy. Restore builds a complete temporary
  // store and swaps only after every stable ID, name and record validates.
  [[nodiscard]] CaptureStoreCheckpoint checkpoint() const;
  [[nodiscard]] static bool
  validate_checkpoint(const CaptureStoreCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const CaptureStoreCheckpoint &state);

private:
  struct Record {
    std::uint64_t timestamp_us{};
    CapturePointId capture_point{};
    packet::Frame frame{};
  };

  struct Point {
    std::string name;
    bool configured{};
    bool active{};
  };

  // Starting the expression in size_t prevents a 32-bit intermediate if this
  // budget is raised on a future profile.
  static constexpr std::size_t memory_bytes =
      device_catalog::capture_store_bytes;
  static constexpr std::size_t capacity = memory_bytes / sizeof(Record);
  std::array<Point, device_catalog::selected_capture_points> points_{};
  std::vector<Record> records_;
  std::vector<std::uint8_t> prepared_;
};

} // namespace router
