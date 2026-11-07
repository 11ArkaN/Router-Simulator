// Independent local counters and owner-local deadlines exercise refresh,
// admission failure, changes during publication and terminal sequence overflow.

#include "router/isis_lsp_generation.hpp"

#include <limits>
#include <source_location>
#include <stdexcept>
#include <string>

void isis_lsp_generation_tests() {
  using namespace router::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS generation invariant failed at " + std::to_string(location.line()));
  };
  const auto now = RuntimeClock::time_point{100s};
  LspGenerationSchedule first(2s, 40s, 1U, now), second(2s, 40s, 2U, now);
  const auto initial = first.prepare(now);
  require(initial.status == GenerationStatus::ready && initial.sequence == 1U && !first.deadline());
  require(first.prepare(now).status == GenerationStatus::waiting &&
      first.complete(initial.ticket, true, now) && first.committed_sequence() == 1U);
  const auto refresh = *first.deadline();
  require(refresh >= now + 30s && refresh <= now + 40s);
  first.changed(now + 1s);
  require(first.deadline() == now + 2s && first.prepare(now + 1999ms).status == GenerationStatus::waiting);
  const auto event = first.prepare(now + 2s);
  require(event.sequence == 2U);
  first.changed(now + 3s);
  require(first.complete(event.ticket, true, now + 4s) && first.deadline() == now + 6s);
  const auto refused = first.prepare(now + 6s);
  require(refused.sequence == 3U && first.complete(refused.ticket, false, now + 6s) &&
      first.committed_sequence() == 2U && !first.deadline());
  first.retry();
  const auto retried = first.prepare(now + 7s);
  require(retried.sequence == 3U && retried.ticket != refused.ticket &&
      !first.complete(refused.ticket, true, now + 7s) && first.complete(retried.ticket, true, now + 7s));
  require(first.deadline() == refresh);
  require(second.prepare(now).sequence == 1U);
  const auto periodic = first.prepare(refresh);
  require(periodic.sequence == 4U && first.complete(periodic.ticket, true, refresh));
  require(*first.deadline() >= refresh + 30s && *first.deadline() <= refresh + 40s);
  first.require_after(100U, refresh + 1s);
  const auto fight_back = first.prepare(refresh + 2s);
  require(fight_back.sequence == 101U && first.complete(fight_back.ticket, true, refresh + 2s));
  first.require_after(std::numeric_limits<std::uint32_t>::max(), refresh + 3s);
  require(first.deadline() == refresh + 3s && first.sequence_exhaustion_due(refresh + 3s) &&
      first.prepare(refresh + 3s).status == GenerationStatus::sequence_exhausted &&
      first.stopped() && !first.deadline() && first.committed_sequence() == 101U);
  first.retry();
  require(first.prepare(refresh + 1000s).status == GenerationStatus::waiting && first.stopped());
  LspGenerationSchedule blocked(2s, 40s, 3U, now);
  const auto refused_initial = blocked.prepare(now);
  require(blocked.complete(refused_initial.ticket, false, now) && blocked.blocked());
  blocked.require_after(std::numeric_limits<std::uint32_t>::max(), now + 1ms);
  require(blocked.sequence_exhaustion_due(now + 1ms) &&
      blocked.prepare(now + 1ms).status == GenerationStatus::sequence_exhausted && !blocked.committed_sequence());
  LspGenerationSchedule maximum(2s, 40s, 4U, now);
  maximum.require_after(std::numeric_limits<std::uint32_t>::max() - 1U, now);
  const auto final_sequence = maximum.prepare(now);
  require(final_sequence.sequence == std::numeric_limits<std::uint32_t>::max() &&
      maximum.complete(final_sequence.ticket, true, now) && !maximum.sequence_exhaustion_due(now));
  const auto refresh_maximum = *maximum.deadline();
  require(maximum.sequence_exhaustion_due(refresh_maximum) &&
      maximum.prepare(refresh_maximum).status == GenerationStatus::sequence_exhausted);
  // Saturating deadlines cannot wrap into immediate work near clock exhaustion.
  LspGenerationSchedule near_limit(1s, 4s, 3U, RuntimeClock::time_point::max() - 1s);
  const auto last = near_limit.prepare(RuntimeClock::time_point::max() - 1s);
  require(near_limit.complete(last.ticket, true, RuntimeClock::time_point::max() - 1s) &&
      near_limit.deadline() == RuntimeClock::time_point::max());
  for (const auto seed : {0U, 1U}) {
    bool rejected{};
    try { LspGenerationSchedule invalid(seed ? 4s : 1s, 4s, seed, now); }
    catch (const std::invalid_argument &) { rejected = true; }
    require(rejected);
  }
  // A pending publication survives a different host epoch, including content
  // changed after reservation. Future refresh draws must remain identical.
  LspGenerationSchedule live(2s, 40s, 17U, now), resumed(2s, 40s, 99U, now);
  const auto reserved = live.prepare(now);
  live.require_after(50U, now + 500ms);
  const auto saved = live.checkpoint(now + 1s);
  const auto rebased = RuntimeClock::time_point{9000s};
  require(resumed.restore(saved, rebased) && !resumed.deadline());
  for (unsigned invalid{}; invalid < 13U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: bad.version = 2U; break;
      case 1U: bad.minimum += 1us; break;
      case 2U: bad.refresh += 1us; break;
      case 3U: bad.random = 0U; break;
      case 4U: bad.changed_nanoseconds = 1; break;
      case 5U: bad.refresh_nanoseconds = 40000000001LL; break;
      case 6U: bad.hold_nanoseconds = 2000000001LL; break;
      case 7U: bad.pending.reset(); break;
      case 8U: bad.pending->status = GenerationStatus::waiting; break;
      case 9U: bad.pending->ticket = 0U; break;
      case 10U: bad.pending->sequence = 0U; break;
      case 11U: bad.blocked = true; break;
      default: bad.stopped = true; break;
    }
    require(!resumed.restore(bad, rebased) && !resumed.deadline() && !resumed.committed_sequence());
  }
  require(!resumed.restore(saved, RuntimeClock::time_point::max()));
  require(live.complete(reserved.ticket, true, now + 1s) && resumed.complete(reserved.ticket, true, rebased));
  for (unsigned iteration{}; iteration < 12U; ++iteration) {
    const auto a = *live.deadline(), b = *resumed.deadline();
    require(a - (now + 1s) == b - rebased);
    const auto left = live.prepare(a), right = resumed.prepare(b);
    require(left.status == right.status && left.sequence == right.sequence && left.ticket == right.ticket);
    const bool installed = iteration != 2U;
    require(live.complete(left.ticket, installed, a) && resumed.complete(right.ticket, installed, b));
    if (!installed) {
      const auto waiting = live.checkpoint(a);
      require(resumed.restore(waiting, b) && resumed.blocked() && !resumed.deadline());
      live.retry(); resumed.retry();
    }
  }
  const auto stopped = first.checkpoint(refresh + 1000s);
  require(resumed.restore(stopped, rebased) && resumed.stopped() && !resumed.deadline());

}
