// TCP local timer tests verify delayed ACK admission, exact second-segment
// behavior, persist RTO start, exponential ceiling and relative checkpoints.

#include "router/tcp_timers.hpp"

#include <chrono>
#include <stdexcept>

void tcp_timers_tests() {
  using namespace router::transport::tcp;

  using AckClock = DelayedAcknowledger::Clock;
  const auto start = AckClock::time_point{std::chrono::seconds{10}};
  DelayedAcknowledger acknowledgments;
  if (acknowledgments.on_segment(true, 1200U, false, start) !=
          AckSchedule::delayed ||
      acknowledgments.due(start + std::chrono::milliseconds{199}) ||
      !acknowledgments.due(start + std::chrono::milliseconds{200}) ||
      acknowledgments.on_segment(true, 1200U, false,
                                 start + std::chrono::milliseconds{1}) !=
          AckSchedule::immediate)
    throw std::runtime_error("TCP delayed ACK exceeded or skipped its bound");

  if (!acknowledgments.due(start + std::chrono::milliseconds{1}))
    throw std::runtime_error("TCP immediate ACK was not retained for retry");

  // An immediate decision is not the same as successful packet admission.
  // Only commit clears state, so a full queue can retry the same ACK later.
  if (acknowledgments.on_segment(true, 1U, false, start) !=
          AckSchedule::delayed)
    throw std::runtime_error("TCP delayed ACK did not restart after immediate ACK");
  const auto saved_ack = acknowledgments.checkpoint(
      start + std::chrono::milliseconds{50});
  DelayedAcknowledger restored_ack;
  const auto restore_now = AckClock::time_point{std::chrono::seconds{100}};
  if (!restored_ack.restore(saved_ack, restore_now) ||
      restored_ack.deadline() !=
          restore_now + std::chrono::milliseconds{150})
    throw std::runtime_error("TCP delayed ACK checkpoint changed remaining time");
  restored_ack.acknowledge_committed();
  if (restored_ack.deadline() ||
      restored_ack.on_segment(false, 10U, false, restore_now) !=
          AckSchedule::immediate ||
      restored_ack.on_segment(true, 0U, true, restore_now) !=
          AckSchedule::immediate)
    throw std::runtime_error("TCP gap or FIN did not request an immediate ACK");

  using PersistClock = PersistTimer::Clock;
  PersistTimer persist;
  const auto persist_start =
      PersistClock::time_point{std::chrono::seconds{1000}};
  persist.update(true, true, std::chrono::seconds{1}, persist_start);
  if (persist.due(persist_start + std::chrono::milliseconds{999}) ||
      !persist.due(persist_start + std::chrono::seconds{1}) ||
      !persist.probe_committed(persist_start + std::chrono::seconds{1}) ||
      persist.interval() != std::chrono::seconds{2} ||
      persist.deadline() != persist_start + std::chrono::seconds{3})
    throw std::runtime_error("TCP persist did not start from RTO and back off");

  auto now = persist_start + std::chrono::seconds{3};
  while (persist.interval() < router::device_catalog::tcp_persist_maximum) {
    if (!persist.probe_committed(now))
      throw std::runtime_error("TCP persist refused a due probe");
    now = *persist.deadline();
  }
  if (persist.interval() != router::device_catalog::tcp_persist_maximum ||
      !persist.probe_committed(now) ||
      persist.interval() != router::device_catalog::tcp_persist_maximum)
    throw std::runtime_error("TCP persist exceeded its generated ceiling");

  const auto saved_persist = persist.checkpoint(now);
  PersistTimer restored_persist;
  if (!restored_persist.restore(saved_persist, restore_now) ||
      restored_persist.interval() !=
          router::device_catalog::tcp_persist_maximum)
    throw std::runtime_error("TCP persist checkpoint lost backoff state");
  restored_persist.update(false, true, std::chrono::seconds{1}, restore_now);
  if (restored_persist.deadline())
    throw std::runtime_error("TCP persist survived a reopened window");
}
