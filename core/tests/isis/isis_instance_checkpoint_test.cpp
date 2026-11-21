// Instance snapshots retain two independent level owners, accepted LAN peer
// catalogs and stable-slot fences. Tests destroy the source before using the
// restored owners and preserve cold/retired admission markers without replay.

#include "router/isis_instance_update.hpp"

#include <array>
#include <limits>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace router;
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS instance checkpoint invariant failed at " + std::to_string(at.line()));
}
LspId id(std::size_t level, std::uint8_t fragment = 0U) {
  return {1U, 2U, 3U, 4U, 5U, static_cast<std::uint8_t>(level ? 10U : 9U), 0U, fragment};
}
SnpContents contents(PduType type) {
  SnpContents result;
  result.header.type = type;
  result.header.source = {1U, 2U, 3U, 4U, 5U, 1U};
  result.header.maximum_area_addresses = 3U;
  result.source = {2U, 0U, 0U, 0U, 0U, 1U};
  result.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  result.maximum_pdu_octets = (type == PduType::csnp_l1 ? csnp_header_octets : psnp_header_octets) + 2U + snp_entry_octets;
  return result;
}
}
void isis_instance_checkpoint_tests() {
  const auto now = RuntimeClock::time_point{100s}, captured = now + 2500ms, resumed_at = RuntimeClock::time_point{1000s};
  const packet::Mac group{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  const packet::Mac peer{2U, 0U, 0U, 0U, 0U, 4U};
  const packet::Mac first{2U, 0U, 0U, 0U, 0U, 2U}, second{2U, 0U, 0U, 0U, 0U, 3U};
  const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 8U, 1492U, 1200U, 60s, 60s, false, false, false, PurgeRules::registry_6233};
  const InstanceUpdateConfiguration policy{{1U, 2U, 3U, 4U, 5U, 1U}, 3U, {level, level},
      {InstanceFormat::standard, 0U}, 4U, 41U};
  std::vector<UpdateCircuitConfiguration> bindings{
      {7U, Levels::both, true, InstanceFormat::standard, 0U, {group, group}},
      {8U, Levels::both, false, InstanceFormat::standard, 0U, {group, group}, true, 4U}};
  auto original = std::make_unique<InstanceUpdateProcess>(policy.local, policy.maximum_areas, policy.levels,
      bindings, policy.selector, policy.maximum_circuits, policy.initial_synchronization_epoch);
  unsigned events{};
  const LevelObserver observer{&events, +[](void *context, const LevelEvent &) noexcept { ++*static_cast<unsigned *>(context); }};
  P2pCircuitEvent up;
  up.after.present = up.after.iso_up = true;
  up.after.usage = Levels::both;
  up.after.neighbor_mac = peer;
  up.transition.outcome = P2pOutcome::up;
  require(original->p2p(0U, 7U, up, observer) == UpdateStatus::applied);
  const std::array peers{first, second};
  require(original->lan(1U, 8U, 0U, peers, true, observer) == UpdateStatus::applied &&
      original->lan(1U, 8U, 1U, std::span{&second, 1U}, false, observer) == UpdateStatus::applied);
  auto cold = bindings[0U];
  cold.configuration_epoch = 9U;
  cold.levels = Levels::level1;
  const auto admission = original->admit_circuit(cold);
  require(admission.status == UpdateStatus::applied && admission.index == 2U && admission.ticket == 1U);
  bindings.push_back(cold);
  auto cancelled_binding = cold;
  cancelled_binding.configuration_epoch = 10U;
  auto cancelled = original->admit_circuit(cancelled_binding);
  require(cancelled.status == UpdateStatus::applied && cancelled.ticket == 2U && original->cancel_circuit_admission(cancelled));
  auto inbound = std::make_unique<packet::Frame>(), outbound = std::make_unique<packet::Frame>();
  auto scratch = std::make_unique<PduScratch>();
  const auto receive = [&](InstanceUpdateProcess &process, std::size_t selected_level, const packet::Mac &source,
      std::uint32_t sequence, std::uint16_t lifetime, std::uint8_t fragment, RuntimeClock::time_point at) {
    std::array<std::uint8_t, 128U> bytes{};
    const auto encoded = encode_lsp(bytes, {selected_level ? PduType::lsp_l2 : PduType::lsp_l1,
        id(selected_level, fragment), lifetime, sequence, 3U}, {});
    require(encoded && ethernet_pdu_into(*inbound, source, group, *encoded));
    return process.receive(1U, 8U, *inbound, {}, at, observer);
  };
  require(receive(*original, 0U, first, 1U, 1200U, 0U, now).status == UpdateStatus::applied &&
      receive(*original, 1U, second, 1U, 1200U, 0U, now).status == UpdateStatus::applied &&
      receive(*original, 1U, second, 7U, 0U, 9U, now).status == UpdateStatus::applied);
  std::array<std::uint64_t, 2U> lsp_tickets{};
  std::uint64_t complete_ticket{}, acknowledgement_ticket{};
  for (std::size_t selected_level{}; selected_level < 2U; ++selected_level) {
    auto output = original->outputs(0U, selected_level);
    require(output.has_value());
    const auto sent = output->reservations.lsp.prepare(id(selected_level), contents(PduType::psnp_l1).source,
        group, 1492U, 1U, *outbound, *scratch, now);
    require(sent.status == LspEmissionStatus::encoded);
    lsp_tickets[selected_level] = sent.ticket;
  }
  {
    auto first_level = original->outputs(1U, 0U), second_level = original->outputs(1U, 1U);
    require(first_level && second_level);
    const auto complete = first_level->reservations.snp.prepare(SnpEmission::complete, contents(PduType::csnp_l1),
        first_level->reservations.designated, *outbound, *scratch, now);
    const auto acknowledgement = second_level->reservations.snp.prepare(SnpEmission::transient_acknowledgement,
        contents(PduType::psnp_l2), second_level->reservations.designated, *outbound, *scratch, now);
    require(complete.status == SnpExchangeStatus::encoded && acknowledgement.status == SnpExchangeStatus::encoded);
    complete_ticket = complete.ticket;
    acknowledgement_ticket = acknowledgement.ticket;
  }
  const auto saved = original->checkpoint(captured);
  const auto event_count = events;
  require(saved.circuits[2U].admission_pending && saved.admission_counter == 2U &&
      saved.levels[0U]->configuration.database.minimum_pdu_allocation > policy.levels[0U]->database.minimum_pdu_allocation);
  auto restored = InstanceUpdateProcess::restore_checkpoint(saved, policy, bindings, resumed_at);
  require(restored && events == event_count && restored->maximum_synchronization_epoch() == 41U);
  original.reset();
  const auto *buffer = restored->level(0U)->database().database().find(id(0U), resumed_at)->pdu.bytes.data();
  const auto refused = [&](const InstanceUpdateCheckpoint &invalid) {
    require(!InstanceUpdateProcess::restore_checkpoint(invalid, policy, bindings, resumed_at) &&
        restored->outputs(0U, 0U)->reservations.lsp.pending() && restored->outputs(1U, 1U)->reservations.snp.pending() &&
        restored->level(0U)->database().database().find(id(0U), resumed_at)->pdu.bytes.data() == buffer && events == event_count);
  };
  auto invalid = saved;
  invalid.version = 2U; refused(invalid);
  invalid = saved; ++invalid.configuration.levels[0U]->maximum_age; refused(invalid);
  invalid = saved; ++invalid.circuits[0U].configuration.configuration_epoch; refused(invalid);
  invalid = saved; invalid.circuits[0U].active = static_cast<Levels>(4U); refused(invalid);
  invalid = saved; invalid.circuits[0U].configured = false; refused(invalid);
  invalid = saved; invalid.circuits[1U].peer = peer; refused(invalid);
  invalid = saved; invalid.circuits[0U].peer[0U] = 1U; refused(invalid);
  invalid = saved; std::swap(invalid.circuits[1U].lan_peers[0U][0U], invalid.circuits[1U].lan_peers[0U][1U]); refused(invalid);
  invalid = saved; invalid.circuits[1U].lan_peers[0U][0U] = {}; refused(invalid);
  invalid = saved; invalid.circuits[1U].lan_peers[0U].resize(5U, second); refused(invalid);
  invalid = saved; invalid.circuits[1U].active = Levels::level2; refused(invalid);
  invalid = saved; invalid.circuits[0U].synchronization_epochs[0U] = 0U; refused(invalid);
  invalid = saved; invalid.circuits[0U].activated[0U] = false; refused(invalid);
  invalid = saved; invalid.admission_counter = 0U; refused(invalid);
  invalid = saved; invalid.circuits[0U].admission_pending = true; refused(invalid);
  invalid = saved; invalid.circuits[0U].admission_ticket = 1U; refused(invalid);
  invalid = saved; invalid.circuits[2U].admission_ticket = 3U; refused(invalid);
  invalid = saved; invalid.circuits[2U].admission_ticket = 0U; refused(invalid);
  invalid = saved; invalid.levels[1U].reset(); refused(invalid);
  invalid = saved; invalid.levels[0U]->circuits[0U].eligible = false; refused(invalid);
  invalid = saved; ++invalid.levels[0U]->circuits[0U].configuration.epoch; refused(invalid);
  invalid = saved; invalid.levels[0U]->circuits[0U].configuration.broadcast = true; refused(invalid);
  invalid = saved; invalid.levels[1U]->database.database.records[0U].bytes.back() ^= 1U; refused(invalid);
  invalid = saved; --invalid.levels[0U]->configuration.database.minimum_pdu_allocation; refused(invalid);

  require(restored->lan(1U, 8U, 0U, std::span{&second, 1U}, true, observer) == UpdateStatus::applied);
  require(restored->outputs(1U, 0U)->reservations.snp.complete(41U, complete_ticket, true, resumed_at).accepted);
  for (std::size_t selected_level{}; selected_level < 2U; ++selected_level) {
    const auto completed = restored->outputs(0U, selected_level)->reservations.lsp.complete(41U,
        lsp_tickets[selected_level], true, resumed_at);
    require(completed.accepted && completed.current_version && restored->level(selected_level)->database().flags(id(selected_level), 0U)->srm);
  }
  require(restored->outputs(1U, 1U)->reservations.snp.complete(41U, acknowledgement_ticket, true, resumed_at).retired == 1U);
  require(receive(*restored, 1U, first, 2U, 1200U, 0U, resumed_at).status == UpdateStatus::adjacency &&
      receive(*restored, 0U, first, 2U, 1200U, 0U, resumed_at).status == UpdateStatus::adjacency &&
      receive(*restored, 0U, second, 2U, 1200U, 0U, resumed_at).status == UpdateStatus::applied);
  require(restored->lan(1U, 8U, 0U, {}, false, observer) == UpdateStatus::applied && !restored->outputs(1U, 0U) &&
      restored->outputs(1U, 1U)->synchronization_epoch == 41U &&
      restored->lan(1U, 8U, 0U, std::span{&second, 1U}, true, observer) == UpdateStatus::applied &&
      restored->outputs(1U, 0U)->synchronization_epoch == 42U);
  auto replayed = InstanceUpdateProcess::restore_checkpoint(restored->checkpoint(resumed_at), policy, bindings, now);
  require(replayed && replayed->outputs(1U, 0U)->synchronization_epoch == 42U && replayed->outputs(1U, 1U)->synchronization_epoch == 41U);
  auto next = restored->admit_circuit(cancelled_binding);
  require(next.status == UpdateStatus::applied && next.ticket == 3U && restored->cancel_circuit_admission(next));
  require(restored->release_circuit(2U, 9U) == UpdateStatus::applied);
  const auto retired = restored->checkpoint(resumed_at);
  require(!retired.circuits[2U].configured && retired.circuits[2U].admission_pending);
  auto retired_copy = InstanceUpdateProcess::restore_checkpoint(retired, policy, bindings, now);
  require(retired_copy && !retired_copy->outputs(2U, 0U));
  auto broadcast = cold;
  broadcast.configuration_epoch = 11U;
  broadcast.physical_point_to_point = false;
  broadcast.broadcast = true;
  broadcast.neighbor_capacity = 2U;
  require(restored->prepare_rebind_circuit(2U, broadcast) == UpdateStatus::applied &&
      restored->rebind_circuit(2U, broadcast) == UpdateStatus::applied && restored->lan(2U, 11U, 0U, {}, false, observer) == UpdateStatus::applied);
  bindings[2U] = broadcast;
  const auto mixed = restored->checkpoint(resumed_at);
  require(mixed.levels[0U]->circuits[2U].configuration.broadcast && !mixed.levels[1U]->circuits[2U].configuration.broadcast);
  require(InstanceUpdateProcess::restore_checkpoint(mixed, policy, bindings, now) != nullptr);

  auto exhausted = mixed;
  exhausted.admission_counter = std::numeric_limits<std::uint64_t>::max();
  auto exhausted_copy = InstanceUpdateProcess::restore_checkpoint(exhausted, policy, bindings, now);
  require(exhausted_copy && exhausted_copy->admit_circuit(cancelled_binding).status == UpdateStatus::epoch_exhausted);
  auto saturated = mixed;
  saturated.circuits[0U].synchronization_epochs[0U] = std::numeric_limits<std::uint64_t>::max();
  auto &level_state = saturated.levels[0U]->circuits[0U];
  level_state.configuration.epoch = saturated.circuits[0U].synchronization_epochs[0U];
  level_state.snp.transmission.epoch = level_state.lsp.transmission.epoch = level_state.configuration.epoch;
  auto saturated_copy = InstanceUpdateProcess::restore_checkpoint(saturated, policy, bindings, now);
  require(saturated_copy != nullptr);
  P2pCircuitEvent down;
  down.before = up.after;
  down.after.neighbor_mac = peer;
  require(saturated_copy->p2p(0U, 7U, down, observer) == UpdateStatus::applied &&
      saturated_copy->p2p(0U, 7U, up, observer) == UpdateStatus::epoch_exhausted &&
      !saturated_copy->outputs(0U, 0U) && !saturated_copy->outputs(0U, 1U));
}
