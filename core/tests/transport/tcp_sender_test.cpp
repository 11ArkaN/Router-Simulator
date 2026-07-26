// Integrated TCP sender tests prove that lower-layer admission owns SND.NXT,
// RTO start, RTT sampling, fast retransmit, timeout backoff and checkpointing.

#include "router/tcp_sender.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

void tcp_sender_tests() {
  using namespace router::transport::tcp;
  using Clock = Sender::Clock;

  std::array<std::uint8_t, 64> storage{};
  std::array<TransmissionRecord, 8> history{};
  std::array<SackRange, 8> sack_ranges{};
  std::array<SackRange, 8> sack_workspace{};
  Sender sender{storage, history, sack_ranges, sack_workspace, 1000U, 8U};
  const auto start = Clock::time_point{std::chrono::seconds{10}};
  sender.update_receiver_window(64U, start);
  constexpr std::array<std::uint8_t, 40> payload{
      1U,  2U,  3U,  4U,  5U,  6U,  7U,  8U,  9U,  10U,
      11U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U,
      21U, 22U, 23U, 24U, 25U, 26U, 27U, 28U, 29U, 30U,
      31U, 32U, 33U, 34U, 35U, 36U, 37U, 38U, 39U, 40U};
  if (!sender.valid() || sender.write(payload, start) != payload.size())
    throw std::runtime_error("TCP sender rejected valid owner storage");

  const auto first = sender.prepare_new(start, false);
  std::array<std::uint8_t, 8> packet{};
  if (!first || first.range.length != 8U ||
      sender.retransmission_deadline() || !sender.copy(first, packet) ||
      packet.front() != 1U || packet.back() != 8U)
    throw std::runtime_error("TCP sender prepared the wrong initial segment");
  // Merely encoding bytes does not prove that IP or a bounded link queue
  // accepted them, so neither the flight size nor RTO may change yet.
  if (sender.flight_size() != 0U || !sender.commit(first, start) ||
      sender.flight_size() != 8U ||
      sender.retransmission_deadline() != start + std::chrono::seconds{1})
    throw std::runtime_error("TCP sender started state before packet admission");

  const auto ack_time = start + std::chrono::milliseconds{100};
  const auto ack = sender.acknowledge(1008U, 64U, false, ack_time);
  if (ack.status != SendAcknowledgeStatus::advanced ||
      ack.newly_acknowledged != 8U || sender.flight_size() != 0U ||
      sender.retransmission_deadline() ||
      sender.rto() != std::chrono::seconds{1} ||
      sender.congestion_window() != 40U)
    throw std::runtime_error("TCP sender did not process a cumulative ACK");

  // Send one segment and meet the strict duplicate-ACK definition three times.
  // Only the third event makes the oldest outstanding range available.
  const auto next = sender.prepare_new(ack_time, false);
  if (!sender.commit(next, ack_time) ||
      sender.acknowledge(1008U, 64U, true, ack_time).fast_retransmission_ready ||
      sender.acknowledge(1008U, 64U, true, ack_time).fast_retransmission_ready ||
      !sender.acknowledge(1008U, 64U, true, ack_time)
           .fast_retransmission_ready)
    throw std::runtime_error("TCP fast retransmit did not require three ACKs");
  const auto fast = sender.prepare_fast_retransmission();
  if (!fast || fast.reason != TransmissionReason::fast_retransmit ||
      fast.range.sequence != 1008U || !sender.copy(fast, packet) ||
      !sender.commit(fast, ack_time))
    throw std::runtime_error("TCP fast retransmit did not repair SND.UNA");

  // A negotiated SACK sender enters RFC 6675 recovery as soon as one block
  // proves more than two SMSS above the hole. It repairs the selected sequence
  // from the retained stream instead of reusing the Reno SND.UNA shortcut.
  std::array<std::uint8_t, 64> sack_storage{};
  std::array<TransmissionRecord, 8> sack_history{};
  std::array<SackRange, 8> sender_sack_ranges{};
  std::array<SackRange, 8> sender_sack_workspace{};
  Sender sack_sender{sack_storage, sack_history, sender_sack_ranges,
                     sender_sack_workspace, 2000U, 8U};
  sack_sender.set_sack_enabled(true);
  sack_sender.update_receiver_window(64U, start);
  static_cast<void>(sack_sender.write(payload, start));
  for (std::size_t segment = 0; segment < 4U; ++segment) {
    const auto original = sack_sender.prepare_new(start, false);
    if (!original || !sack_sender.commit(original, start))
      throw std::runtime_error("TCP SACK fixture did not fill its initial window");
  }
  const std::array delivered{SackBlock{2008U, 2032U}};
  const auto sack_ack = sack_sender.acknowledge(
      2000U, 64U, true, start + std::chrono::milliseconds{10},
      std::nullopt, delivered);
  const auto sack_repair =
      sack_sender.prepare_sack_recovery(start + std::chrono::milliseconds{10});
  if (!sack_ack.sack_recovery_ready || !sack_repair ||
      sack_repair.reason != TransmissionReason::sack_recovery ||
      sack_repair.range.sequence != 2000U ||
      sack_repair.range.length != 8U ||
      !sack_sender.commit(sack_repair,
                          start + std::chrono::milliseconds{10}))
    throw std::runtime_error("TCP sender did not execute RFC 6675 NextSeg");
  const auto active_sack_checkpoint =
      sack_sender.checkpoint(start + std::chrono::milliseconds{15});
  std::array<std::uint8_t, 64> active_restore_storage{};
  std::array<TransmissionRecord, 8> active_restore_history{};
  std::array<SackRange, 8> active_restore_ranges{};
  std::array<SackRange, 8> active_restore_workspace{};
  Sender active_restore{active_restore_storage, active_restore_history,
                        active_restore_ranges, active_restore_workspace, 0U,
                        8U};
  const auto active_restore_at = Clock::time_point{std::chrono::seconds{200}};
  if (!active_restore.restore(active_sack_checkpoint, active_restore_at))
    throw std::runtime_error("TCP sender lost active SACK recovery checkpoint");
  const auto recovery_ack = active_restore.acknowledge(
      2032U, 64U, false, active_restore_at + std::chrono::milliseconds{5});
  if (recovery_ack.sack_recovery_ready || active_restore.flight_size() != 0U ||
      active_restore.congestion_window() != 16U)
    throw std::runtime_error("TCP SACK sender did not exit at RecoveryPoint");

  // A separate sender isolates the timeout path. Before the exact deadline no
  // retransmission is prepared. Once admitted, RTO doubles and cwnd becomes 1 SMSS.
  std::array<std::uint8_t, 32> timeout_storage{};
  std::array<TransmissionRecord, 4> timeout_history{};
  std::array<SackRange, 4> timeout_sack_ranges{};
  std::array<SackRange, 4> timeout_sack_workspace{};
  Sender timeout_sender{timeout_storage, timeout_history, timeout_sack_ranges,
                        timeout_sack_workspace, 5000U, 8U};
  timeout_sender.update_receiver_window(32U, start);
  static_cast<void>(timeout_sender.write(payload, start));
  const auto timeout_first = timeout_sender.prepare_new(start, false);
  if (!timeout_sender.commit(timeout_first, start) ||
      timeout_sender.prepare_timeout_retransmission(
          start + std::chrono::milliseconds{999}))
    throw std::runtime_error("TCP retransmitted before the RTO deadline");
  const auto timed_out = timeout_sender.prepare_timeout_retransmission(
      start + std::chrono::seconds{1});
  if (!timed_out || !timeout_sender.commit(
                        timed_out, start + std::chrono::seconds{1}) ||
      timeout_sender.rto() != std::chrono::seconds{2} ||
      timeout_sender.congestion_window() != 8U ||
      timeout_sender.retransmission_deadline() !=
          start + std::chrono::seconds{3})
    throw std::runtime_error("TCP timeout did not back off RTO and cwnd");

  // The integrated segment ledger lets R1 and R2 retain the original first
  // transmission time across exponential RTO. Queue admission, not packet
  // preparation, increments the retransmission count.
  std::array<std::uint8_t, 16> failure_storage{};
  std::array<TransmissionRecord, 2> failure_history{};
  std::array<SackRange, 2> failure_sack_ranges{};
  std::array<SackRange, 2> failure_sack_workspace{};
  Sender failure_sender{failure_storage, failure_history, failure_sack_ranges,
                        failure_sack_workspace, 6000U, 8U};
  failure_sender.update_receiver_window(16U, start);
  static_cast<void>(failure_sender.write(payload, start));
  const auto failure_first = failure_sender.prepare_new(start, false);
  if (!failure_sender.commit(failure_first, start))
    throw std::runtime_error("TCP failure fixture did not admit original data");
  for (const auto due : {start + std::chrono::seconds{1},
                         start + std::chrono::seconds{3},
                         start + std::chrono::seconds{7}}) {
    const auto repair = failure_sender.prepare_timeout_retransmission(due);
    if (!repair || !failure_sender.commit(repair, due))
      throw std::runtime_error("TCP failure fixture lost an admitted timeout repair");
  }
  if (failure_sender.take_failure_action(start + std::chrono::seconds{7}) !=
          FailureAction::negative_ip_advice ||
      failure_sender.prepare_timeout_retransmission(
          start + std::chrono::seconds{100}) ||
      failure_sender.take_failure_action(start + std::chrono::seconds{100}) !=
          FailureAction::abort_connection)
    throw std::runtime_error("TCP sender did not apply R1 and time-based R2");

  // A pushed short write is legal on an idle connection. With data in flight,
  // Nagle holds another short write until the generated SWS override expires.
  std::array<std::uint8_t, 16> tiny_storage{};
  std::array<TransmissionRecord, 4> tiny_history{};
  std::array<SackRange, 4> tiny_sack_ranges{};
  std::array<SackRange, 4> tiny_sack_workspace{};
  Sender tiny{tiny_storage, tiny_history, tiny_sack_ranges,
              tiny_sack_workspace, 7000U, 8U};
  tiny.update_receiver_window(16U, start);
  constexpr std::array<std::uint8_t, 1> one{0x5aU};
  static_cast<void>(tiny.write(one, start));
  const auto tiny_first = tiny.prepare_new(start, true);
  if (!tiny_first || !tiny.commit(tiny_first, start))
    throw std::runtime_error("TCP Nagle blocked an idle pushed write");
  static_cast<void>(tiny.write(one, start));
  if (tiny.prepare_new(start, true) ||
      tiny.prepare_new(start + std::chrono::milliseconds{199}, true) ||
      !tiny.prepare_new(start + std::chrono::milliseconds{200}, true))
    throw std::runtime_error("TCP Nagle or SWS override used the wrong deadline");
  tiny.set_nagle_enabled(false);
  if (!tiny.prepare_new(start, true))
    throw std::runtime_error("TCP application could not disable Nagle");

  // A closed receive window starts persist at one RTO. Its one-octet probe is
  // neither a congestion loss nor ordinary retransmission-timer flight.
  std::array<std::uint8_t, 16> persist_storage{};
  std::array<TransmissionRecord, 4> persist_history{};
  std::array<SackRange, 4> persist_sack_ranges{};
  std::array<SackRange, 4> persist_sack_workspace{};
  Sender persist_sender{persist_storage, persist_history, persist_sack_ranges,
                        persist_sack_workspace, 9000U, 8U};
  static_cast<void>(persist_sender.write(payload, start));
  persist_sender.update_receiver_window(0U, start);
  if (persist_sender.prepare_persist_probe(
          start + std::chrono::milliseconds{999}))
    throw std::runtime_error("TCP persist probed before one RTO");
  const auto probe =
      persist_sender.prepare_persist_probe(start + std::chrono::seconds{1});
  if (!probe || probe.reason != TransmissionReason::persist_probe ||
      probe.range.length != 1U ||
      !persist_sender.commit(probe, start + std::chrono::seconds{1}) ||
      persist_sender.flight_size() != 1U ||
      persist_sender.retransmission_deadline())
    throw std::runtime_error("TCP persist altered congestion retransmission state");
  const auto repeated_probe =
      persist_sender.prepare_persist_probe(start + std::chrono::seconds{3});
  if (!repeated_probe || !repeated_probe.range.retransmission ||
      !persist_sender.commit(repeated_probe, start + std::chrono::seconds{3}))
    throw std::runtime_error("TCP persist did not retransmit its probe byte");
  persist_sender.update_receiver_window(16U, start + std::chrono::seconds{3});
  if (persist_sender.prepare_persist_probe(start + std::chrono::seconds{10}) ||
      persist_sender.retransmission_deadline() !=
          start + std::chrono::seconds{4})
    throw std::runtime_error("TCP persist survived a window-opening update");

  const auto saved = timeout_sender.checkpoint(start + std::chrono::seconds{2});
  std::array<std::uint8_t, 32> restored_storage{};
  std::array<TransmissionRecord, 4> restored_history{};
  std::array<SackRange, 4> restored_sack_ranges{};
  std::array<SackRange, 4> restored_sack_workspace{};
  Sender restored{restored_storage, restored_history, restored_sack_ranges,
                  restored_sack_workspace, 0U, 8U};
  const auto restore_now = Clock::time_point{std::chrono::seconds{100}};
  if (!restored.restore(saved, restore_now) || restored.flight_size() != 8U ||
      restored.rto() != std::chrono::seconds{2} ||
      restored.congestion_window() != 8U ||
      restored.retransmission_deadline() !=
          restore_now + std::chrono::seconds{1})
    throw std::runtime_error("TCP sender checkpoint changed live timing");

  // Lowering SMSS invalidates an already prepared segment and resegments the
  // oldest admitted range without acknowledging or copying stream bytes. The
  // retransmission clock remains owned by the original admitted transmission.
  std::array<std::uint8_t, 64> pmtu_storage{};
  std::array<TransmissionRecord, 8> pmtu_history{};
  std::array<SackRange, 8> pmtu_sack_ranges{};
  std::array<SackRange, 8> pmtu_sack_workspace{};
  Sender pmtu_sender{pmtu_storage, pmtu_history, pmtu_sack_ranges,
                     pmtu_sack_workspace, 12'000U, 16U};
  pmtu_sender.update_receiver_window(64U, start);
  static_cast<void>(pmtu_sender.write(payload, start));
  const auto admitted_before_pmtu = pmtu_sender.prepare_new(start, false);
  if (!admitted_before_pmtu || admitted_before_pmtu.range.length != 16U ||
      !pmtu_sender.commit(admitted_before_pmtu, start) ||
      !pmtu_sender.transmitted(12'000U) ||
      pmtu_sender.transmitted(12'016U))
    throw std::runtime_error("TCP PMTU fixture did not admit its original segment");
  const auto stale_preparation = pmtu_sender.prepare_new(start, false);
  if (!stale_preparation || !pmtu_sender.reduce_mss(4U) ||
      pmtu_sender.commit(stale_preparation, start))
    throw std::runtime_error("TCP PMTU change did not invalidate staged old-MSS output");
  const auto resegmented = pmtu_sender.prepare_timeout_retransmission(
      start + std::chrono::seconds{1});
  if (!resegmented || resegmented.range.sequence != 12'000U ||
      resegmented.range.length != 4U ||
      !pmtu_sender.commit(resegmented, start + std::chrono::seconds{1}) ||
      pmtu_sender.checkpoint(start + std::chrono::seconds{1})
              .congestion.sender_mss != 4U)
    throw std::runtime_error("TCP PMTU reduction did not resegment retransmission");

  auto invalid = saved;
  invalid.retransmission_deadline_present = false;
  invalid.retransmission_remaining_nanoseconds = 0;
  if (restored.restore(invalid, restore_now))
    throw std::runtime_error("TCP sender restored flight without an RTO");
}
