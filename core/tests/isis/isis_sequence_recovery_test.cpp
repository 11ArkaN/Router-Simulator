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
  SequenceRecovery resumed({SequenceLevelLifetime{1200U, 60U}, SequenceLevelLifetime{1400U, 60U}}, 100ms);
  const auto rebased = RuntimeClock::time_point{9000s};
  require(resumed.restore(recovery.checkpoint(RuntimeClock::time_point::max()), rebased) &&
      resumed.disabled() && !resumed.deadline() && !resumed.ready(rebased + 10000s));
  SequenceRecovery waiting({SequenceLevelLifetime{1200U, 60U}, SequenceLevelLifetime{1400U, 60U}}, 100ms);
  require(waiting.begin(now));
  const auto saved = waiting.checkpoint(now + 500500ms);
  require(resumed.restore(saved, rebased) && resumed.deadline() == rebased + 959500ms);
  for (unsigned invalid{}; invalid < 6U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: ++bad.version; break;
      case 1U: bad.cooldown += 1ns; break;
      case 2U: bad.resource_retry += 1ns; break;
      case 3U: bad.disabled = false; break;
      case 4U: bad.saturated = true; break;
      default: bad.due_nanoseconds = 1460000000001LL; break;
    }
    require(!resumed.restore(bad, rebased) && resumed.deadline() == rebased + 959500ms);
  }
  require(!resumed.restore(saved, RuntimeClock::time_point::max()));
  require(resumed.resource_failed(rebased + 959500ms));
  const auto retried = resumed.checkpoint(rebased + 959550ms);
  require(waiting.restore(retried, now) && waiting.deadline() == now + 50ms &&
      waiting.recovered(now + 50ms));
  require(resumed.restore(waiting.checkpoint(now + 50ms), rebased) && !resumed.disabled());

  const auto orphan = SequenceRecovery::restore_checkpoint(saved, rebased);
  require(orphan && orphan->disabled() && orphan->deadline() == rebased + 959500ms);
  for (unsigned invalid{}; invalid < 5U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: bad.cooldown = 1s; break;
      case 1U: bad.cooldown = 131071s; break;
      case 2U: bad.cooldown += 1ns; break;
      case 3U: bad.resource_retry = 0ns; break;
      default: bad.resource_retry += 1ns; break;
    }
    require(!SequenceRecovery::restore_checkpoint(bad, rebased));
  }

}
