// Forwarding-owned bounded capture storage and deterministic PCAPNG encoding.
// Live packet delivery never waits for capture memory or export serialization.

#pragma once

#include "router/generated_profile.hpp"
#include "router/packet.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace router {

class CaptureStore final {
public:
  CaptureStore();

  // Preconditions: forwarding-shard affinity. false means diagnostics capacity
  // is exhausted; callers must continue packet delivery and count the drop.
  [[nodiscard]] bool record(std::uint8_t interface_id,
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

private:
  struct Record {
    std::uint64_t timestamp_us{};
    std::uint8_t interface_id{};
    packet::Frame frame{};
  };

  // Starting the expression in size_t prevents a 32-bit intermediate if this
  // budget is raised on a future profile.
  static constexpr std::size_t memory_bytes = profile::capture_memory_bytes;
  static constexpr std::size_t capacity = memory_bytes / sizeof(Record);
  std::vector<Record> records_;
  std::vector<std::uint8_t> prepared_;
};

} // namespace router
