// One LAN interface control owner schedules the ISO single-LSP scan path.
// It owns its timer, PRNG and one outstanding admission, never a packet or
// LSDB. Candidate counts and queued-input state come from that same owner.

#pragma once

#include "router/isis_jitter.hpp"
#include "router/isis_level_database.hpp"

#include <cstddef>

namespace router::isis {
struct BroadcastLevel {
  const LevelDatabase *database{};
  std::size_t circuit{};
};
struct BroadcastCandidate { std::size_t level{}; packet::isis::LspId id{}; };
enum class BroadcastScanStatus : std::uint8_t { idle, selected, invalid_catalog };
struct BroadcastSelection {
  BroadcastScanStatus status{BroadcastScanStatus::idle};
  std::optional<BroadcastCandidate> candidate{};
};
class BroadcastScan final {
public:
  using Clock = std::chrono::steady_clock;
  // Effective interval in (0, 65535ms] and nonzero seed are explicit. This is the
  // ISO 7.3.15.6 single-PDU scan, without the optional burst exception or a
  // vendor pacing-bucket default. Invalid inputs throw before publication.
  BroadcastScan(std::chrono::microseconds interval, std::uint64_t random_state,
      Clock::time_point now);
  // Same control owner. Count covers the complete currently eligible SRM set,
  // across both levels of this interface. A returned index uniformly selects
  // its entry for immediate same-turn reservation. No borrowed view survives.
  // Pending ingress inhibits output except the permitted one-per-second path.
  // Every expired periodic deadline advances before work, even with no entry.
  // nullopt reserves nothing; success requires complete() after actual egress
  // or immediate composition/publication refusal. No allocation occurs.
  [[nodiscard]] std::optional<std::size_t> begin(Clock::time_point now,
      std::size_t candidates, bool ingress_pending) noexcept;
  // Same-owner borrowed L1/L2 catalogs. Null databases omit a level. The
  // complete combined SRM set participates without a candidate allocation.
  // Invalid level/media/slot preserves this timer, PRNG and pending state.
  // A selected value owns its ID; prepare it immediately before any mutation.
  [[nodiscard]] BroadcastSelection begin(Clock::time_point now,
      std::array<BroadcastLevel, 2U> levels, bool ingress_pending) noexcept;
  // The parent must first match the circuit epoch and transmission ticket.
  // A false result means no reservation existed and changes nothing. Receipt
  // observation conservatively anchors the queued-input exception spacing.
  // Failed admission leaves reliable SRM obligations with the database owner.
  [[nodiscard]] bool complete(bool enqueued, Clock::time_point now) noexcept;
  // Same owner; pending output waits for its receipt instead of spinning.
  [[nodiscard]] Clock::time_point deadline(bool ingress_pending) const noexcept;
  [[nodiscard]] std::uint64_t random_state() const noexcept { return random_; }
private:
  std::chrono::microseconds interval_;
  Clock::time_point periodic_{};
  std::optional<Clock::time_point> last_sent_;
  std::uint64_t random_{};
  bool pending_{};
};
} // namespace router::isis
