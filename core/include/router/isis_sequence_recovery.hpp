// One entity's sequence exhaustion disables every level for the longest
// configured MaxAge+ZeroAgeLifetime. Its control owner performs circuit Down
// and reconstructs protocol state only after this owner-local admission gate.

#pragma once

#include "router/isis_lsdb.hpp"

namespace router::isis {
struct SequenceLevelLifetime { std::uint16_t maximum_age{}, zero_age_lifetime{}; };
class SequenceRecovery final {
public:
  // Explicit effective lifetimes for enabled levels and an emulator resource
  // retry interval are required. No SR OS retry default is selected. Invalid
  // values throw before publication; the gate owns no clock or event queue.
  SequenceRecovery(std::array<std::optional<SequenceLevelLifetime>, 2U> levels,
      std::chrono::milliseconds resource_retry);
  // First exhaustion starts entity-wide cooldown. Further input while disabled
  // cannot shorten or restart it. The parent must stop all Hello/update output.
  [[nodiscard]] bool begin(RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool ready(RuntimeClock::time_point now) const noexcept;
  // A failed cold reconstruction after cooldown keeps the entity disabled and
  // defers another attempt. It never starts another protocol MaxAge period.
  [[nodiscard]] bool resource_failed(RuntimeClock::time_point now) noexcept;
  // Parent successfully constructed fresh independent counters and databases.
  // Early or unsolicited completion refuses without changing the gate.
  [[nodiscard]] bool recovered(RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool disabled() const noexcept { return disabled_; }
  // Saturation cannot permit immediate restart at clock exhaustion.
  [[nodiscard]] std::optional<RuntimeClock::time_point> deadline() const noexcept;
private:
  void wait(RuntimeClock::time_point now, RuntimeClock::duration duration) noexcept;
  RuntimeClock::duration cooldown_, resource_retry_;
  RuntimeClock::time_point due_{};
  bool disabled_{}, saturated_{};
};
} // namespace router::isis
