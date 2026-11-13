// One local LSP's generation state belongs to its instance control owner.
// Semantic content, LSDB admission, entity shutdown and packet transport remain
// with that owner. This module depends only on steady time and wire counters.

#pragma once

#include "router/isis_lsdb.hpp"

namespace router::isis {
enum class GenerationStatus : std::uint8_t { ready, waiting, sequence_exhausted, ticket_exhausted };
struct LspGeneration {
  GenerationStatus status{GenerationStatus::waiting};
  std::uint32_t sequence{};
  std::uint64_t ticket{};
};
struct LspGenerationCheckpoint {
  std::uint32_t version{1U};
  std::chrono::microseconds minimum{}, refresh{};
  std::uint64_t random{}, tickets{};
  std::uint32_t committed{}, observed{};
  std::int64_t refresh_nanoseconds{}, changed_nanoseconds{}, hold_nanoseconds{};
  std::optional<LspGeneration> pending;
  bool dirty{}, changed_during_pending{}, blocked{}, stopped{};
};
class LspGenerationSchedule final {
public:
  // Effective intervals and a nonzero independent PRNG seed are mandatory.
  // The minimum interval must fit the shortest jittered refresh interval.
  // Construction starts sequence one pending and anchors periodic refresh.
  // No allocation. All methods run on the same instance control shard.
  LspGenerationSchedule(std::chrono::microseconds minimum_interval,
      std::chrono::microseconds refresh_interval, std::uint64_t random,
      RuntimeClock::time_point now);
  // A content change never resets the periodic refresh timer. Calls made
  // during a reserved generation remain pending after that generation commits.
  void changed(RuntimeClock::time_point now) noexcept;
  // Parent already validated an LSP/SNP as requiring current-local fight-back.
  // The next publication exceeds both the committed and received sequences.
  // This is not the acceptance path for identical/older copies or unknown IDs.
  void require_after(std::uint32_t sequence, RuntimeClock::time_point now) noexcept;
  // Reserve one generation after its hold-down. Refresh expiration anchors its
  // next jittered deadline before composition. Exhaustion stops this schedule;
  // the parent MUST disable the entire entity for at least MaxAge+ZeroAgeLifetime.
  // A reservation borrows no data and cannot be replaced until completion.
  [[nodiscard]] LspGeneration prepare(RuntimeClock::time_point now) noexcept;
  // Success means finalized bytes were admitted to the local LSDB. Failure
  // preserves the sequence and work, then waits for an explicit resource/key
  // event through retry(). Stale tickets cannot affect another reservation.
  [[nodiscard]] bool complete(std::uint64_t ticket, bool installed,
      RuntimeClock::time_point now) noexcept;
  // Same-owner semantic invalidation before publication. An abandoned ticket
  // cannot commit; no sequence, spacing timer or refresh entropy is consumed.
  void abandon() noexcept { pending_.reset(); changed_during_pending_ = false; dirty_ = true; blocked_ = false; }
  // Preserve deferred semantic work after an independent retained-body refresh.
  // No outstanding reservation may survive this same-owner refusal fence.
  void defer() noexcept { abandon(); blocked_ = true; }
  [[nodiscard]] RuntimeClock::time_point refresh_deadline() const noexcept { return refresh_at_; }
  [[nodiscard]] std::optional<LspGeneration> reservation() const noexcept { return pending_; }
  [[nodiscard]] bool content_pending() const noexcept { return dirty_; }
  [[nodiscard]] std::uint32_t sequence_floor() const noexcept { return observed_ > committed_ ? observed_ : committed_; }
  void retry() noexcept { blocked_ = false; }
  // No deadline while reserved, resource-blocked or stopped by exhaustion.
  [[nodiscard]] std::optional<RuntimeClock::time_point> deadline() const noexcept;
  [[nodiscard]] std::uint32_t committed_sequence() const noexcept { return committed_; }
  [[nodiscard]] bool stopped() const noexcept { return stopped_; }
  [[nodiscard]] bool blocked() const noexcept { return blocked_; }
  // Sequence failure is metadata work, independent of publication credits,
  // authentication availability and minimum spacing between generated PDUs.
  [[nodiscard]] bool sequence_exhaustion_due(RuntimeClock::time_point now) const noexcept;
  // Same-owner transfer after transport quiescence. Relative nanoseconds freeze
  // elapsed time while absent. Capture throws invalid_argument for a clock
  // distance outside the transfer range. Restore requires identical intervals,
  // validates all fields before mutation and allocates no memory.
  [[nodiscard]] LspGenerationCheckpoint checkpoint(RuntimeClock::time_point now) const;
  [[nodiscard]] bool restore(const LspGenerationCheckpoint &saved, RuntimeClock::time_point now) noexcept;
private:
  std::chrono::microseconds minimum_, refresh_;
  std::uint64_t random_{}, tickets_{};
  std::uint32_t committed_{}, observed_{};
  RuntimeClock::time_point refresh_at_, changed_at_, hold_until_;
  std::optional<LspGeneration> pending_;
  bool dirty_{true}, changed_during_pending_{}, blocked_{}, stopped_{};
};
} // namespace router::isis
