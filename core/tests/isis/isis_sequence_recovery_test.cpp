// Entity cooldown uses the longest level lifetime and survives resource waits.
// Test-owned steady values exercise long protocol intervals without a UI clock.

#include "router/isis_sequence_recovery.hpp"

#include <stdexcept>

void isis_sequence_recovery_tests() {
  using namespace router::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) { if (!value) throw std::runtime_error("IS-IS sequence recovery failed"); };
  const auto now = RuntimeClock::time_point{100s};
  SequenceRecovery recovery({SequenceLevelLifetime{1200U, 60U}, SequenceLevelLifetime{1400U, 60U}}, 100ms);
  require(!recovery.disabled() && !recovery.deadline() && !recovery.ready(now) && !recovery.recovered(now));
  require(recovery.begin(now) && recovery.disabled() && recovery.deadline() == now + 1460s);
  require(!recovery.begin(now + 500s) && recovery.deadline() == now + 1460s &&
      !recovery.ready(now + 1459s) && !recovery.resource_failed(now + 1459s) && !recovery.recovered(now + 1459s));
  require(recovery.ready(now + 1460s) && recovery.resource_failed(now + 1460s) &&
      recovery.deadline() == now + 1460s + 100ms && !recovery.ready(now + 1460s + 99ms));
  require(recovery.recovered(now + 1460s + 100ms) && !recovery.disabled() && !recovery.deadline());
  require(recovery.begin(RuntimeClock::time_point::max() - 1s) && recovery.disabled() &&
      !recovery.deadline() && !recovery.ready(RuntimeClock::time_point::max()) &&
      !recovery.recovered(RuntimeClock::time_point::max()));
  for (const auto retry : {0ms, -1ms}) {
    bool rejected{};
    try { SequenceRecovery invalid({SequenceLevelLifetime{1200U, 60U}, std::nullopt}, retry); }
    catch (const std::invalid_argument &) { rejected = true; }
    require(rejected);
  }
  bool empty_rejected{};
  try { SequenceRecovery invalid({}, 100ms); }
  catch (const std::invalid_argument &) { empty_rejected = true; }
  require(empty_rejected);
}
