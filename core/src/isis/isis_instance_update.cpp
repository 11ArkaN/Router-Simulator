// ISO 10589 7.3.15 acceptance precedes every update mutation. Configuration
// epochs protect transport generations; owner-local synchronization epochs
// cancel reservations across adjacency loss without inventing a config edit.

#include "router/isis_instance_update.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace router::isis {
namespace {
bool includes(Levels levels, std::size_t level) noexcept {
  return (static_cast<std::uint8_t>(levels) & (1U << level)) != 0U;
}
std::optional<std::size_t> pdu_level(packet::isis::PduType type) noexcept {
  using packet::isis::PduType;
  if (type == PduType::lsp_l1 || type == PduType::csnp_l1 || type == PduType::psnp_l1) return 0U;
  if (type == PduType::lsp_l2 || type == PduType::csnp_l2 || type == PduType::psnp_l2) return 1U;
  return std::nullopt;
}
bool valid_circuit(const UpdateCircuitConfiguration &circuit,
    const std::array<std::optional<UpdateLevelConfiguration>, 2U> &levels) noexcept {
  const auto mask = static_cast<std::uint8_t>(circuit.levels);
  if (!circuit.configuration_epoch || !mask || mask > 3U ||
      (circuit.format != packet::isis::InstanceFormat::standard &&
       circuit.format != packet::isis::InstanceFormat::legacy_2009)) return false;
  for (std::size_t index{}; index < levels.size(); ++index)
    if (includes(circuit.levels, index) && (!levels[index] ||
        (circuit.destinations[index][0U] & 1U) == 0U)) return false;
  return true;
}
}
InstanceUpdateProcess::InstanceUpdateProcess(packet::isis::SystemId local,
    std::uint8_t maximum_areas,
    std::array<std::optional<UpdateLevelConfiguration>, 2U> levels,
    std::span<const UpdateCircuitConfiguration> circuits, std::size_t maximum_circuits)
    : local_(local), maximum_areas_(maximum_areas), configuration_(std::move(levels)),
      maximum_circuits_(maximum_circuits ? maximum_circuits : circuits.size()) {
  if (!maximum_areas || maximum_areas == 255U || (!configuration_[0U] && !configuration_[1U]))
    throw std::invalid_argument("IS-IS update owner requires effective levels and maximum areas");
  if (maximum_circuits_ < circuits.size() || maximum_circuits_ > circuits_.max_size())
    throw std::invalid_argument("Invalid IS-IS update circuit capacity");
  circuits_.reserve(circuits.size());
  std::vector<LevelCircuitConfiguration> slots(circuits.size(), {false, 1U});
  for (const auto &circuit : circuits) {
    if (!valid_circuit(circuit, configuration_))
      throw std::invalid_argument("Invalid IS-IS update circuit generation");
    circuits_.push_back({circuit});
  }
  for (std::size_t index{}; index < levels_.size(); ++index) {
    if (!configuration_[index]) continue;
    const auto &value = *configuration_[index];
    if (value.receive_pdu_octets < packet::isis::lsp_header_octets || value.receive_pdu_octets > 65535U ||
        (maximum_circuits_ && !value.snp_entry_capacity))
      throw std::invalid_argument("Invalid IS-IS receive PDU budget");
    levels_[index] = std::make_unique<LevelProcess>(index ? packet::isis::PduType::lsp_l2 :
        packet::isis::PduType::lsp_l1, value.database, slots, value.acknowledgement_capacity,
        value.snp_entry_capacity, value.maximum_age, value.purge_retention, value.waiting_time, maximum_circuits_);
  }
}

UpdateCircuitAdmission InstanceUpdateProcess::admit_circuit(UpdateCircuitConfiguration configuration) noexcept {
  if (!valid_circuit(configuration, configuration_)) return {};
  if (circuits_.size() == maximum_circuits_) return {UpdateStatus::capacity, LevelStatus::capacity, {}};
  const auto index = circuits_.size();
  try { circuits_.reserve(index + 1U); }
  catch (const std::bad_alloc &) { return {UpdateStatus::capacity, LevelStatus::capacity, {}}; }
  catch (const std::length_error &) { return {UpdateStatus::capacity, LevelStatus::capacity, {}}; }
  for (std::size_t level{}; level < levels_.size(); ++level) {
    if (!levels_[level]) continue;
    const auto admitted = levels_[level]->admit_circuit({false, 1U}, configuration_[level]->snp_entry_capacity);
    if (admitted.status != LevelStatus::applied) {
      for (std::size_t previous{}; previous < level; ++previous)
        if (levels_[previous] && !levels_[previous]->cancel_circuit_admission(index)) std::terminate();
      return {UpdateStatus::level_refused, admitted.status, {}};
    }
    if (admitted.index != index) std::terminate();
  }
  circuits_.push_back({configuration});
  return {UpdateStatus::applied, LevelStatus::applied, index};
}

UpdateStatus InstanceUpdateProcess::p2p(std::size_t index, std::uint64_t configuration_epoch,
    const P2pCircuitEvent &event, LevelObserver observer) noexcept {
  if (!observer.event) return UpdateStatus::missing_observer;
  if (index >= circuits_.size()) return UpdateStatus::invalid_circuit;
  auto &circuit = circuits_[index];
  if (configuration_epoch != circuit.configuration.configuration_epoch) return UpdateStatus::stale_configuration;
  const auto before = event.before.iso_up ? event.before.usage : Levels::none;
  const auto after = event.after.iso_up ? event.after.usage : Levels::none;
  const auto mask = static_cast<std::uint8_t>(after);
  if (before != circuit.active || (before != Levels::none && event.before.neighbor_mac != circuit.peer) ||
      (event.after.iso_up && (!event.after.present || !mask)) || mask > 3U ||
      (static_cast<unsigned>(mask) & ~static_cast<unsigned>(circuit.configuration.levels)) != 0U)
    return UpdateStatus::invalid_event;
  for (std::size_t level{}; level < levels_.size(); ++level)
    if (!includes(before, level) && includes(after, level) && circuit.activated[level] &&
        circuit.synchronization_epochs[level] == std::numeric_limits<std::uint64_t>::max())
      return UpdateStatus::epoch_exhausted;
  for (std::size_t level{}; level < levels_.size(); ++level) {
    const bool was_up = includes(before, level), up = includes(after, level);
    // RFC 5303 Initialize emits no ISO adjacency Down. A later explicit Up
    // nevertheless restarts synchronization, even if ISO usage stayed Up.
    const bool resynchronize = up && event.transition.outcome == P2pOutcome::up;
    if (was_up == up && !resynchronize) continue;
    if (!was_up && up && circuit.activated[level]) ++circuit.synchronization_epochs[level];
    // Constructor and event preflight guarantee this exact owner/slot/epoch.
    // A violated internal invariant must fail closed, never publish half an Up.
    if (levels_[level]->circuit(index, circuit.synchronization_epochs[level], false,
        up, false, up, observer) != LevelStatus::applied) std::terminate();
    circuit.activated[level] = circuit.activated[level] || up;
  }
  circuit.active = after;
  circuit.peer = event.after.neighbor_mac;
  return UpdateStatus::applied;
}

UpdateReceiveResult InstanceUpdateProcess::receive(std::size_t index,
    std::uint64_t configuration_epoch, const packet::Frame &frame,
    std::optional<AuthenticationKey> key, RuntimeClock::time_point now,
    LevelObserver observer) noexcept {
  if (!observer.event) return {UpdateStatus::missing_observer};
  if (index >= circuits_.size()) return {UpdateStatus::invalid_circuit};
  auto &circuit = circuits_[index];
  if (configuration_epoch != circuit.configuration.configuration_epoch) return {UpdateStatus::stale_configuration};
  packet::isis::EthernetDecodeError error{};
  const auto wire = packet::isis::parse_ethernet_pdu(frame.view(), error);
  const auto selected = wire ? pdu_level(wire->pdu.type) : std::nullopt;
  if (!selected) return {};
  const auto level = *selected;
  if (!includes(circuit.active, level) || !levels_[level]) return {UpdateStatus::inactive, level};
  if (wire->ethernet.destination != circuit.configuration.destinations[level] ||
      (!circuit.configuration.physical_point_to_point && wire->ethernet.source != circuit.peer))
    return {UpdateStatus::destination, level};
  const auto &effective = *configuration_[level];
  if (wire->pdu.bytes.size() > effective.receive_pdu_octets) return {UpdateStatus::receive_capacity, level};
  packet::isis::InstanceError instance_error{};
  const auto instance = packet::isis::select_instance(wire->pdu, circuit.configuration.format,
      circuit.configuration.physical_point_to_point, instance_error);
  if (!instance || instance->instance != circuit.configuration.wire_instance) return {UpdateStatus::instance, level};
  if (!level && wire->pdu.maximum_area_addresses != maximum_areas_) return {UpdateStatus::maximum_areas, level};
  using packet::isis::PduType;
  const bool lsp = wire->pdu.type == PduType::lsp_l1 || wire->pdu.type == PduType::lsp_l2;
  const bool complete = wire->pdu.type == PduType::csnp_l1 || wire->pdu.type == PduType::csnp_l2;
  const bool authenticate = lsp ? effective.authenticate_lsp :
      complete ? effective.authenticate_csnp : effective.authenticate_psnp;
  if (authenticate && (!key || verify_authentication(wire->pdu.bytes, *key) != AuthenticationError::none))
    return {UpdateStatus::authentication, level};
  if (lsp) {
    auto header = packet::isis::lsp(wire->pdu);
    if (!header) return {};
    if (std::equal(local_.begin(), local_.end(), header->id.begin())) {
      if (header->checksum && !packet::isis::valid_lsp_checksum(wire->pdu)) return {};
      if (!header->checksum) header->remaining_seconds = 0U;
      return {UpdateStatus::self_originated, level, {}, {}, header};
    }
    const auto result = levels_[level]->receive_lsp(index, circuit.synchronization_epochs[level],
        wire->pdu.bytes, now, observer);
    return {result.status == LevelStatus::applied ? UpdateStatus::applied : UpdateStatus::level_refused,
        level, result};
  }
  const auto result = levels_[level]->receive_snp(index, circuit.synchronization_epochs[level],
      wire->pdu, now, observer);
  return {result.status == LevelStatus::applied ? UpdateStatus::applied : UpdateStatus::level_refused,
      level, {}, result};
}

std::optional<UpdateOutputs> InstanceUpdateProcess::outputs(std::size_t circuit, std::size_t level) noexcept {
  if (circuit >= circuits_.size() || level >= levels_.size() || !levels_[level]) return std::nullopt;
  const auto epoch = circuits_[circuit].synchronization_epochs[level];
  const auto output = levels_[level]->outputs(circuit, epoch);
  return output ? std::optional(UpdateOutputs{epoch, *output}) : std::nullopt;
}
const LevelProcess *InstanceUpdateProcess::level(std::size_t index) const noexcept {
  return index < levels_.size() ? levels_[index].get() : nullptr;
}

LevelOriginResult InstanceUpdateProcess::originate(std::size_t level,
    std::span<const std::uint8_t> wire, RuntimeClock::time_point now,
    OriginPurgeReason purge, LevelObserver observer) noexcept {
  if (level >= levels_.size() || !levels_[level])
    return {LevelStatus::invalid_configuration, LspInstallResult::malformed};
  packet::isis::DecodeError error{};
  const auto pdu = packet::isis::parse(wire, error);
  const auto header = pdu ? packet::isis::lsp(*pdu) : std::nullopt;
  if (!header || !std::equal(local_.begin(), local_.end(), header->id.begin()))
    return {LevelStatus::invalid_configuration, LspInstallResult::malformed};
  return levels_[level]->originate(wire, now, purge, observer);
}
} // namespace router::isis
