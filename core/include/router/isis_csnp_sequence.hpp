// One circuit and level own a contiguous CSNP transmission sequence. The IS-IS
// control owner supplies its current level database and packet-sized scratch.
// Encoded transmission and circuit epochs remain with the enclosing driver.

#pragma once

#include "router/isis_level_database.hpp"

namespace router::isis {
enum class CompleteSnpStatus : std::uint8_t { prepared, idle, pending, capacity, inconsistent_database };
struct CompleteSnpBatch {
  CompleteSnpStatus status{CompleteSnpStatus::idle};
  packet::isis::LspId first{};
  packet::isis::LspId last{};
  std::size_t count{};
};
class CompleteSnpSequence final {
public:
  // Initialization or the effective CSNP timer requests a complete sequence.
  // A request while active schedules another sequence after the current one,
  // preserving progress through high IDs even under repeated timer expiry.
  void request() noexcept;
  // Output capacity is the caller's exact encoded-PDU entry budget. Entries
  // and range are one synchronous projection; LSDB changes afterward do not
  // invalidate the already encoded PDU. Success reserves one pending batch.
  // Empty databases still produce one range covering all possible LSP IDs.
  // No allocation. Only a prepared result makes output entries meaningful.
  [[nodiscard]] CompleteSnpBatch prepare(const LevelDatabase &database,
      std::span<packet::isis::SnpEntry> output, RuntimeClock::time_point now) noexcept;
  // Caller accepted the current circuit epoch and actual egress receipt.
  // Refusal keeps the current range for retry. Success advances to the exact
  // successor range, with no skipped IDs. Duplicate completions reject.
  [[nodiscard]] bool complete(bool enqueued) noexcept;
  // Circuit Down revokes the outer epoch before clearing this local state.
  void reset() noexcept;
  [[nodiscard]] bool active() const noexcept { return active_; }
  [[nodiscard]] bool pending() const noexcept { return pending_; }
private:
  packet::isis::LspId first_{};
  packet::isis::LspId pending_last_{};
  bool active_{};
  bool pending_{};
  bool repeat_{};
};
} // namespace router::isis
