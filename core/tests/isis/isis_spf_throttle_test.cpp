// Synthetic monotonic points verify SPF coalescing, burst reset and recovery.
// The test owns the level scheduler and performs no sleep or network access.
#include "router/isis_spf_throttle.hpp"
#include <stdexcept>
namespace {
void require(bool value) { if (!value) throw std::runtime_error("IS-IS SPF throttle invariant"); }
}
void isis_spf_throttle_tests() {
  using namespace router::isis;
  using namespace std::chrono_literals;
  using Clock = SpfThrottle::Clock;
  const auto zero = Clock::time_point{};
  const SpfDelayPolicy policy{10s, 1s, 1s};
  SpfThrottle throttle(policy);
  require(!throttle.deadline() && throttle.changed(zero) && throttle.deadline() == zero + 1s);
  require(throttle.changed(zero + 100ms) && throttle.deadline() == zero + 1s);
  require(!throttle.complete(zero + 999ms) && throttle.complete(zero + 1s));
  auto previous = zero + 1s;
  for (const auto second : {2, 4, 8, 16, 26, 36}) {
    require(throttle.changed(previous + 1ms));
    require(throttle.deadline() == zero + std::chrono::seconds{second});
    require(throttle.complete(*throttle.deadline())); previous = zero + std::chrono::seconds{second};
  }
  require(throttle.changed(zero + 46s) && throttle.deadline() == zero + 47s);
  require(throttle.complete(zero + 47s) && throttle.changed(zero + 47001ms) && throttle.deadline() == zero + 48s);
  SpfThrottle quiet({10s, 200ms, 1s});
  require(quiet.changed(zero) && quiet.complete(zero + 200ms));
  require(quiet.changed(zero + 1200ms) && quiet.deadline() == zero + 1400ms);
  SpfThrottle independent({100ms, 2s, 1s});
  require(independent.changed(zero) && independent.deadline() == zero + 2s && independent.complete(zero + 2s));
  require(independent.changed(zero + 2001ms) && independent.deadline() == zero + 2100ms);
  SpfThrottle immediate({10s, 0ms, 0ms});
  require(immediate.changed(zero) && immediate.complete(zero) && immediate.changed(zero + 1ms) && immediate.complete(zero + 1ms));
  for (const auto invalid : {SpfDelayPolicy{-100ms, 0ms, 0ms}, SpfDelayPolicy{10s, 10ms, 1s},
      SpfDelayPolicy{120100ms, 1s, 1s}, SpfDelayPolicy{10s, 100100ms, 1s}}) {
    bool refused{}; try { SpfThrottle rejected(invalid); } catch (const std::invalid_argument &) { refused = true; }
    require(refused);
  }
  SpfThrottle source(policy);
  require(source.changed(zero) && source.complete(zero + 1s) && source.changed(zero + 1001ms) &&
      source.complete(zero + 2s) && source.changed(zero + 2001ms));
  const auto saved = source.checkpoint(zero + 2050ms);
  SpfThrottle restored(policy);
  const auto resumed = zero + 100s;
  require(restored.restore(saved, resumed) && restored.deadline() == resumed + 1950ms);
  for (unsigned mutation{}; mutation < 4U; ++mutation) {
    auto invalid = saved;
    if (!mutation) invalid.version = 2U;
    else if (mutation == 1U) invalid.next_hold = 3s;
    else if (mutation == 2U) invalid.last_run_nanoseconds = 1;
    else ++*invalid.pending_nanoseconds;
    require(!restored.restore(invalid, resumed) && restored.deadline() == resumed + 1950ms);
  }
  require(!restored.complete(resumed + 1949ms) && restored.complete(resumed + 1950ms));
  require(restored.changed(resumed + 1951ms) && restored.deadline() == resumed + 5950ms);
  SpfThrottle overflow(policy);
  require(!overflow.changed(Clock::time_point::max() - 500ms) && !overflow.deadline());
  require(overflow.changed(Clock::time_point::max() - 1500ms));
  const auto pending = overflow.deadline();
  require(!overflow.complete(*pending) && overflow.deadline() == pending);
}
