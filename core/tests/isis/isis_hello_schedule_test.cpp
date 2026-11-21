// Independent Hello classes retain periodic deadlines across content triggers,
// commit spacing only after egress receipts, and preserve pending updates.

#include "router/isis_hello_schedule.hpp"

#include <stdexcept>

void isis_hello_schedule_tests() {
  using namespace router::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS Hello scheduling invariant failed");
  };
  const auto now = HelloSchedule::Clock::time_point{100s};
  HelloSchedule lan(9s, true, false, 123U, now);
  const auto initial = lan.deadline();
  require(lan.begin(now) && !lan.begin(now));
  lan.changed();
  require(lan.complete(true, now) && !lan.complete(true, now));
  require(!lan.begin(now + 999ms) && lan.begin(now + 1s));
  require(lan.complete(false, now + 1s) && !lan.begin(now + 1s));
  lan.changed();
  require(lan.begin(now + 1s));
  require(lan.complete(true, now + 1s));
  require(lan.deadline() >= now + 6750ms && lan.deadline() <= now + 9s);
  const auto periodic = lan.deadline();
  lan.changed();
  require(lan.begin(now + 2s) && lan.complete(true, now + 2s) && lan.deadline() == periodic);
  require(initial == HelloSchedule::Clock::time_point::min());
  const auto random = lan.random_state();
  require(lan.role(3s, true, now + 2s) && lan.random_state() == random);
  require(lan.begin(now + 3s) && lan.complete(true, now + 3s) && lan.deadline() == now + 5s);
  require(lan.begin(now + 5s) && lan.deadline() == now + 8s && lan.random_state() == random);
  require(lan.complete(true, now + 5s));
  require(!lan.role(0us, true, now + 5s) && lan.deadline() == now + 8s);
  HelloSchedule p2p(9s, false, false, 999U, now);
  require(p2p.begin(now) && p2p.complete(true, now));
  p2p.changed();
  require(p2p.begin(now + 1ms) && p2p.complete(true, now + 1ms));
  require(!p2p.role(3s, true, now));
  HelloSchedule source(9s, true, false, 17U, now), resumed(9s, true, false, 99U, now);
  require(source.begin(now) && source.complete(true, now));
  source.changed();
  require(source.begin(now + 1s));
  source.changed();
  const auto saved = source.checkpoint(now + 1500ms);
  const auto rebased = HelloSchedule::Clock::time_point{9000s};
  require(resumed.restore(saved, rebased) && resumed.pending() && resumed.random_state() == source.random_state());
  for (unsigned invalid{}; invalid < 8U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: ++bad.version; break;
      case 1U: bad.interval += 1us; break;
      case 2U: bad.broadcast = false; break;
      case 3U: bad.designated = true; break;
      case 4U: bad.random = 0U; break;
      case 5U: bad.last_sent_nanoseconds = 1; break;
      case 6U: bad.sent = false; break;
      default: bad.periodic_nanoseconds = 9000000001LL; break;
    }
    require(!resumed.restore(bad, rebased) && resumed.pending());
  }
  require(!resumed.restore(saved, HelloSchedule::Clock::time_point::max()));
  require(source.complete(false, now + 1500ms) && resumed.complete(false, rebased));
  require(source.begin(now + 1500ms) && resumed.begin(rebased));
  require(source.complete(true, now + 1500ms) && resumed.complete(true, rebased));
  for (unsigned iteration{}; iteration < 8U; ++iteration) {
    const auto a = source.deadline(), b = resumed.deadline();
    require(a - (now + 1500ms) == b - rebased);
    require(source.begin(a) && resumed.begin(b) && source.random_state() == resumed.random_state());
    require(source.complete(true, a) && resumed.complete(true, b));
  }
  HelloSchedule near_limit(9s, true, false, 7U, HelloSchedule::Clock::time_point::max() - 1s);
  require(near_limit.begin(HelloSchedule::Clock::time_point::max() - 1s) &&
      near_limit.complete(true, HelloSchedule::Clock::time_point::max() - 1s) &&
      near_limit.deadline() == HelloSchedule::Clock::time_point::max());
  require(!near_limit.role(std::chrono::microseconds::max(), false, now));
  bool overflow_rejected{};
  try { HelloSchedule invalid(std::chrono::microseconds::max(), false, false, 1U, now); }
  catch (const std::invalid_argument &) { overflow_rejected = true; }
  require(overflow_rejected);

}
