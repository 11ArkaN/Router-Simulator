// Periodic LSDB integrity scans belong to one instance-level control owner.
// The owner supplies steady time and bounded work credits. This module borrows
// only its local database and never accesses transport or another router.

#pragma once

#include "router/isis_lsdb.hpp"

namespace router::isis {
enum class DatabaseValidationStatus : std::uint8_t { waiting, more, complete, corrupted };
struct DatabaseValidationResult {
  DatabaseValidationStatus status{DatabaseValidationStatus::waiting};
  std::optional<packet::isis::LspId> corrupted;
  std::size_t checked{};
};
class DatabaseValidation final {
public:
  // A positive effective maximum generation interval and independent nonzero
  // seed are required. No allocation; construction throws invalid_argument for
  // invalid intervals. All calls and database mutations share the same owner.
  DatabaseValidation(std::chrono::microseconds interval, std::uint64_t random,
      RuntimeClock::time_point now);
  // ISO 10589 7.3.18 skips effective zero-lifetime records. Each visited record
  // consumes one credit. The ID cursor survives insertion, deletion and vector
  // relocation; new or replaced input is independently checked at admission.
  // Corruption is terminal: the parent MUST stop the entity and reacquire its
  // database before replacing this scanner. Complete requires a decision event
  // even without changed topology. Borrowed bytes never escape this call.
  [[nodiscard]] DatabaseValidationResult service(const LinkStateDatabase &database,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
  [[nodiscard]] std::optional<RuntimeClock::time_point> deadline() const noexcept;
private:
  std::chrono::microseconds interval_;
  std::uint64_t random_;
  RuntimeClock::time_point due_;
  std::optional<packet::isis::LspId> cursor_;
  bool scanning_{}, corrupted_{};
};
} // namespace router::isis
