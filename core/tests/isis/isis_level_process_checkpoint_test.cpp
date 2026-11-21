// A restored level owns fresh databases and every borrowing exchange. The
// original is destroyed before receipts resume, exposing stale-reference bugs.
// Policy, epoch, Waiting and nested-state failures never touch the live owner.

#include "router/isis_level_process.hpp"

#include <array>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

namespace {
using namespace router;
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS level checkpoint invariant failed at " + std::to_string(at.line()));
}
SnpContents snp_program() {
  SnpContents result;
  result.header.type = PduType::psnp_l1;
  result.header.source = {9U, 8U, 7U, 6U, 5U, 4U};
  result.header.maximum_area_addresses = 3U;
  result.source = {2U, 0U, 0U, 0U, 0U, 1U};
  result.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  result.maximum_pdu_octets = psnp_header_octets + 2U + snp_entry_octets;
  return result;
}
}
void isis_level_process_checkpoint_tests() {
  const auto now = RuntimeClock::time_point{100s}, captured = now + 2500ms;
  const auto resumed_at = RuntimeClock::time_point{1000s};
  const LevelProcessConfiguration policy{PduType::lsp_l1, {4U, 1024U, 128U}, 8U, 1200U, 60s, 5s, 4U};
  const std::array first{LevelCircuitConfiguration{false, 10U}};
  const std::array bindings{LevelCircuitProgram{{false, 10U}, 4U}, LevelCircuitProgram{{true, 20U}, 6U}};
  auto original = std::make_unique<LevelProcess>(policy.level, policy.database, first,
      policy.acknowledgement_capacity, 4U, policy.maximum_age, policy.purge_retention, policy.waiting_time, policy.maximum_circuits);
  require(original->admit_circuit(bindings[1U].configuration, bindings[1U].snp_entry_capacity).index == 1U);
  unsigned events{};
  const LevelObserver observer{&events, +[](void *context, const LevelEvent &) noexcept { ++*static_cast<unsigned *>(context); }};
  require(original->circuit(0U, 10U, false, true, false, true, observer) == LevelStatus::applied &&
      original->circuit(1U, 20U, true, true, true, true, observer) == LevelStatus::applied);
  const LspId live{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  auto unknown = live;
  unknown[7U] = 9U;
  std::array<std::uint8_t, 128U> bytes{};
  auto encoded = encode_lsp(bytes, {PduType::lsp_l1, live, 1200U, 1U, 3U}, {});
  require(encoded && original->receive_lsp(0U, 10U, *encoded, now, observer).status == LevelStatus::applied);
  encoded = encode_lsp(bytes, {PduType::lsp_l1, unknown, 0U, 7U, 3U}, {});
  require(encoded && original->receive_lsp(1U, 20U, *encoded, now, observer).acknowledgement &&
      original->transient_acknowledgements() == 1U);
  auto scratch = std::make_unique<PduScratch>();
  auto frame = std::make_unique<packet::Frame>();
  std::uint64_t partial_ticket{}, acknowledgement_ticket{}, lsp_ticket{};
  {
    auto p2p = original->outputs(0U, 10U), lan = original->outputs(1U, 20U);
    require(p2p && lan);
    const auto partial = p2p->snp.prepare(SnpEmission::partial, snp_program(), false, *frame, *scratch, now);
    const auto ack = lan->snp.prepare(SnpEmission::transient_acknowledgement, snp_program(), true, *frame, *scratch, now);
    const auto lsp = lan->lsp.prepare(live, snp_program().source, snp_program().destination, 1492U, 1U, *frame, *scratch, now);
    require(partial.status == SnpExchangeStatus::encoded && ack.status == SnpExchangeStatus::encoded &&
        lsp.status == LspEmissionStatus::encoded);
    partial_ticket = partial.ticket;
    acknowledgement_ticket = ack.ticket;
    lsp_ticket = lsp.ticket;
  }
  require(original->decision_unavailable(now, observer));
  const auto saved = original->checkpoint(captured);
  const auto before_events = events;
  auto restored = LevelProcess::restore_checkpoint(saved, policy, bindings, resumed_at);
  require(restored && events == before_events && restored->waiting() && restored->waiting_deadline() == resumed_at + 2500ms);
  original.reset();
  const auto *buffer = restored->database().database().find(live, resumed_at)->pdu.bytes.data();
  const auto refused = [&](const LevelProcessCheckpoint &invalid, RuntimeClock::time_point epoch = RuntimeClock::time_point{1000s}) {
    require(!LevelProcess::restore_checkpoint(invalid, policy, bindings, epoch) && restored->outputs(0U, 10U)->snp.pending() &&
        restored->outputs(1U, 20U)->lsp.pending() && restored->transient_acknowledgements() == 1U &&
        restored->database().database().find(live, resumed_at)->pdu.bytes.data() == buffer && events == before_events);
  };
  auto invalid = saved;
  invalid.version = 2U; refused(invalid);
  invalid = saved; ++invalid.configuration.maximum_age; refused(invalid);
  invalid = saved; invalid.circuits.pop_back(); refused(invalid);
  invalid = saved; invalid.circuits[0U].activated = false; refused(invalid);
  invalid = saved; invalid.circuits[0U].designated = true; refused(invalid);
  invalid = saved; ++invalid.circuits[0U].configuration.epoch; refused(invalid);
  invalid = saved; ++invalid.circuits[0U].snp.entry_capacity; refused(invalid);
  invalid = saved; invalid.database.circuits[0U].eligible = false; refused(invalid);
  invalid = saved; invalid.acknowledgements.entries[0U].circuit = 2U; refused(invalid);
  invalid = saved; invalid.waiting = false; refused(invalid);
  invalid = saved; invalid.waiting_nanoseconds.reset(); refused(invalid);
  invalid = saved; invalid.waiting_nanoseconds = 6'000'000'000LL; refused(invalid);
  invalid = saved; invalid.waiting_timer_expired = true; refused(invalid);
  invalid = saved; ++invalid.circuits[0U].snp.transmission.epoch; refused(invalid);
  invalid = saved; invalid.circuits[1U].lsp.pending->sequence = 0U; refused(invalid);
  invalid = saved; invalid.database.database.records[0U].bytes.back() ^= 1U; refused(invalid);
  invalid = saved; ++invalid.database.maximum_circuits; refused(invalid);
  invalid = saved; invalid.acknowledgements.next_ticket = 1U; refused(invalid);
  invalid = saved; invalid.circuits[1U].snp.acknowledgements[0U].ticket = 99U; refused(invalid);
  refused(saved, RuntimeClock::time_point::min());
  refused(saved, RuntimeClock::time_point::max());

  const auto partial = restored->outputs(0U, 10U)->snp.complete(10U, partial_ticket, true, resumed_at);
  const auto ack = restored->outputs(1U, 20U)->snp.complete(20U, acknowledgement_ticket, true, resumed_at);
  const auto lsp = restored->outputs(1U, 20U)->lsp.complete(20U, lsp_ticket, true, resumed_at);
  require(partial.accepted && partial.retired == 1U && ack.accepted && ack.retired == 1U &&
      lsp.accepted && lsp.current_version && !restored->database().flags(live, 0U)->ssn &&
      !restored->database().flags(live, 1U)->srm && !restored->transient_acknowledgements());
  require(!restored->outputs(1U, 20U)->snp.complete(20U, acknowledgement_ticket, true, resumed_at).accepted &&
      !restored->outputs(1U, 20U)->lsp.complete(20U, lsp_ticket, true, resumed_at).accepted);
  require(!restored->service_waiting(resumed_at + 2499ms, true, observer) &&
      !restored->service_waiting(resumed_at + 2500ms, false, observer) && restored->waiting() && !restored->waiting_deadline());
  const auto blocked = restored->checkpoint(resumed_at + 2500ms);
  auto blocked_copy = LevelProcess::restore_checkpoint(blocked, policy, bindings, RuntimeClock::time_point{2000s});
  require(blocked_copy && blocked_copy->waiting() && !blocked_copy->waiting_deadline() &&
      blocked_copy->service_waiting(RuntimeClock::time_point{2000s}, true, observer) && !blocked_copy->waiting());
  const auto recovered = blocked_copy->checkpoint(RuntimeClock::time_point{2000s});
  auto recovered_copy = LevelProcess::restore_checkpoint(recovered, policy, bindings, RuntimeClock::time_point{3000s});
  require(recovered_copy && !recovered_copy->waiting() && recovered_copy->decision_unavailable(RuntimeClock::time_point{3000s}, observer) &&
      recovered_copy->waiting_deadline() == RuntimeClock::time_point{3005s});
  require(recovered_copy->circuit(1U, 20U, true, false, false, false, observer) == LevelStatus::applied);
  const auto down = recovered_copy->checkpoint(RuntimeClock::time_point{3000s});
  auto down_copy = LevelProcess::restore_checkpoint(down, policy, bindings, RuntimeClock::time_point{4000s});
  require(down_copy && !down_copy->outputs(1U, 20U) &&
      down_copy->circuit(1U, 20U, true, true, true, true, observer) == LevelStatus::stale_epoch &&
      down_copy->circuit(1U, 21U, true, true, true, true, observer) == LevelStatus::applied);
  require(down_copy->outputs(1U, 21U)->lsp.checkpoint().transmission.next_ticket == 2U);
  require(down_copy->admit_circuit({false, 30U}, 3U).index == 2U);

  const LevelProcessConfiguration empty_policy{PduType::lsp_l1, {}, 0U, 1200U, 60s, 5s, 0U};
  LevelProcess empty(empty_policy.level, {}, {}, 0U, 0U, 1200U, 60s, 5s);
  auto empty_copy = LevelProcess::restore_checkpoint(empty.checkpoint(now), empty_policy, {}, resumed_at);
  require(empty_copy && !empty_copy->waiting() && !empty_copy->outputs(0U, 1U));
}
