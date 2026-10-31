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
}
