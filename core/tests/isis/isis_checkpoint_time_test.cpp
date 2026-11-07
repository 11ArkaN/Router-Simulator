// Host-epoch shifts preserve finite deadlines and scheduling sentinels.
// Exact integer conversion rejects overflow and malformed sentinel images.
// No clock is read and no simulation time control is introduced.

#include "router/isis_checkpoint_time.hpp"

#include <stdexcept>

void isis_checkpoint_time_tests() {
  using namespace router::isis::checkpoint_time;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS checkpoint deadline invariant failed");
  };
  const auto origin = Clock::time_point{100s}, target = Clock::time_point{9000s};
  const auto immediate = deadline(Clock::time_point::min(), origin);
  const auto never = deadline(Clock::time_point::max(), origin);
  const auto pending = deadline(origin + 123456789ns, origin);
  const auto overdue = deadline(origin - 10s, origin);
  require(immediate && never && pending && overdue);
  require(restore_deadline(*immediate, target) == Clock::time_point::min() &&
      restore_deadline(*never, target) == Clock::time_point::max() &&
      restore_deadline(*pending, target) == target + 123456789ns &&
      restore_deadline(*overdue, target) == target - 10s);
  require(!restore_deadline(*pending, Clock::time_point::max()) &&
      !restore_deadline(*overdue, Clock::time_point::min()));
  require(!restore_deadline({DeadlineKind::minimum, 1}, target) &&
      !restore_deadline({DeadlineKind::maximum, -1}, target) &&
      !restore_deadline({static_cast<DeadlineKind>(255U), 0}, target));
  // Observed timestamps retain finite elapsed age even at an endpoint; only
  // explicitly declared scheduling fields may translate endpoint sentinels.
  require(offset(Clock::time_point::max(), Clock::time_point::max()) == 0 &&
      restore(0, target) == target);
  require(!offset(Clock::time_point::max(), Clock::time_point::min()));
}
