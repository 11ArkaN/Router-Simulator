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
}
