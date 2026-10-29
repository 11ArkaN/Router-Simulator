// Level-local synchronization and overload transitions. ISO 10589 7.3.15-7.3.19
// govern database obligations and Waiting; the parent instance owns authenticated
// origination, adjacency acceptance, circuit timers and route publication.

#include "router/isis_level_process.hpp"

#include <stdexcept>
#include <new>
#include <type_traits>
#include <limits>

namespace router::isis {
namespace {
std::vector<FloodCircuit> initial_circuits(std::span<const LevelCircuitConfiguration> values) {
  std::vector<FloodCircuit> result;
  result.reserve(values.size());
  for (const auto &value : values) {
    if (!value.epoch) throw std::invalid_argument("IS-IS level circuit epoch cannot be zero");
    result.push_back({value.broadcast, false, false, false});
  }
  return result;
}
}
LevelProcess::LevelProcess(packet::isis::PduType level, LsdbLimits limits,
    std::span<const LevelCircuitConfiguration> circuits,
    std::size_t acknowledgement_capacity, std::size_t snp_entry_capacity,
    std::uint16_t maximum_age, std::chrono::seconds purge_retention,
    std::chrono::seconds waiting_time, std::size_t maximum_circuits)
    : database_(level, limits, initial_circuits(circuits), maximum_circuits),
      acknowledgements_(acknowledgement_capacity), maximum_age_(maximum_age),
      purge_retention_(purge_retention), waiting_time_(waiting_time) {
  if (!maximum_age || purge_retention.count() <= 0 || waiting_time.count() <= 0 ||
      waiting_time > std::chrono::duration_cast<std::chrono::seconds>(RuntimeClock::duration::max()) ||
      purge_retention.count() > std::numeric_limits<std::uint16_t>::max() ||
      ((!circuits.empty() || maximum_circuits) && !acknowledgement_capacity) ||
      (!circuits.empty() && !snp_entry_capacity))
    throw std::invalid_argument("IS-IS level lifetime and Waiting Time must be positive and representable");
  static_assert(std::is_nothrow_move_constructible_v<Circuit>);
  circuits_.reserve(circuits.size());
  for (std::size_t index{}; index < circuits.size(); ++index)
    circuits_.emplace_back(database_, acknowledgements_, index, circuits[index], snp_entry_capacity);
}

LevelCircuitAdmission LevelProcess::admit_circuit(LevelCircuitConfiguration configuration,
    std::size_t snp_entry_capacity) noexcept {
  if (!configuration.epoch || !snp_entry_capacity) return {};
  if (!database_.circuit_capacity_available()) return {LevelStatus::capacity, std::nullopt};
  try { circuits_.reserve(circuits_.size() + 1U); }
  catch (const std::bad_alloc &) { return {LevelStatus::capacity, std::nullopt}; }
  catch (const std::length_error &) { return {LevelStatus::capacity, std::nullopt}; }
  const auto index = database_.admit_circuit(configuration.broadcast);
  if (!index) return {LevelStatus::capacity, std::nullopt};
  try {
    circuits_.emplace_back(database_, acknowledgements_, *index, configuration, snp_entry_capacity);
    return {LevelStatus::applied, index};
  } catch (const std::bad_alloc &) {
    static_cast<void>(database_.cancel_circuit_admission(*index));
    return {LevelStatus::capacity, std::nullopt};
  } catch (const std::length_error &) {
    static_cast<void>(database_.cancel_circuit_admission(*index));
    return {};
  }
}

void LevelProcess::emit(LevelEventKind event, LevelObserver observer,
    std::optional<packet::isis::LspId> id) noexcept {
  observer.event(observer.context, {event, database_.type(), id});
}

bool LevelProcess::cancel_circuit_admission(std::size_t index) noexcept {
  if (index >= circuits_.size() || index + 1U != circuits_.size() ||
      circuits_[index].activated || circuits_[index].eligible || circuits_[index].snp.pending() ||
      !database_.cancel_circuit_admission(index)) return false;
  circuits_.pop_back();
  return true;
}

LevelStatus LevelProcess::accept(std::size_t circuit, std::uint64_t epoch,
    LevelObserver observer) const noexcept {
  if (!observer.event) return LevelStatus::missing_observer;
  if (circuit >= circuits_.size()) return LevelStatus::invalid_circuit;
  if (circuits_[circuit].configuration.epoch != epoch) return LevelStatus::stale_epoch;
  return circuits_[circuit].eligible ? LevelStatus::applied : LevelStatus::inactive;
}

LevelStatus LevelProcess::circuit(std::size_t index, std::uint64_t epoch,
    bool broadcast, bool eligible, bool designated, bool synchronize,
    LevelObserver observer) noexcept {
  if (!observer.event) return LevelStatus::missing_observer;
  if (index >= circuits_.size()) return LevelStatus::invalid_circuit;
  if ((designated && (!broadcast || !eligible)) || (synchronize && !eligible))
    return LevelStatus::invalid_configuration;
  auto &circuit = circuits_[index];
  if (!epoch || epoch < circuit.configuration.epoch ||
      (eligible && !circuit.eligible && circuit.activated && epoch == circuit.configuration.epoch))
    return LevelStatus::stale_epoch;
  if (circuit.eligible && broadcast != circuit.configuration.broadcast) return LevelStatus::needs_down;
  const bool replacement = epoch > circuit.configuration.epoch;
  const bool was_designated = circuit.designated;
  const bool was_eligible = circuit.eligible;
  const bool changed = replacement || circuit.configuration.broadcast != broadcast ||
      was_eligible != eligible || was_designated != designated;
  if (replacement || !eligible) {
    static_cast<void>(database_.circuit(index, circuit.configuration.broadcast, false, false));
    circuit.snp.cancel();
    circuit.lsp.cancel();
    static_cast<void>(acknowledgements_.clear_circuit(index));
  }
  if (replacement) {
    static_cast<void>(circuit.snp.replace_epoch(epoch));
    static_cast<void>(circuit.lsp.replace_epoch(epoch));
  }
  static_cast<void>(database_.circuit(index, broadcast, eligible,
      synchronize || (eligible && (replacement || !was_eligible))));
  circuit.configuration = {broadcast, epoch};
  circuit.eligible = eligible;
  circuit.designated = broadcast && eligible && designated;
  circuit.activated = circuit.activated || eligible;
  if (was_designated && !circuit.designated) circuit.snp.cancel();
  if ((circuit.designated && (!was_designated || replacement)) ||
      (!broadcast && eligible && (synchronize || replacement || !was_eligible)))
    circuit.snp.request_complete();
  if (changed || synchronize) emit(LevelEventKind::circuit_changed, observer);
  return LevelStatus::applied;
}

void LevelProcess::wait(RuntimeClock::time_point now, bool restart, LevelObserver observer) noexcept {
  const bool entered = !waiting_;
  if (entered || restart) {
    const auto duration = std::chrono::duration_cast<RuntimeClock::duration>(waiting_time_);
    waiting_until_ = now > RuntimeClock::time_point::max() - duration
        ? RuntimeClock::time_point::max() : now + duration;
    waiting_timer_expired_ = false;
  }
  waiting_ = true;
  if (entered) emit(LevelEventKind::overload_entered, observer);
}

LevelLspResult LevelProcess::receive_lsp(std::size_t circuit, std::uint64_t epoch,
    std::span<const std::uint8_t> wire, RuntimeClock::time_point now,
    LevelObserver observer) noexcept {
  const auto status = accept(circuit, epoch, observer);
  if (status != LevelStatus::applied) return {status, {}, std::nullopt};
  auto result = database_.receive(wire, circuit, now, maximum_age_, purge_retention_);
  if (result.flooding.waiting_state) {
    wait(now, true, observer);
    return {LevelStatus::capacity, result, std::nullopt};
  }
  if (result.install == LspInstallResult::malformed) return {LevelStatus::malformed, result, std::nullopt};
  if (result.install == LspInstallResult::invalid_checksum || result.install == LspInstallResult::excessive_lifetime)
    return {LevelStatus::discarded, result, std::nullopt};
  if (result.install == LspInstallResult::installed) {
    packet::isis::DecodeError error;
    const auto pdu = packet::isis::parse(wire, error);
    emit(LevelEventKind::database_changed, observer, packet::isis::lsp(*pdu)->id);
  }
  if (!result.transient_acknowledgement) return {LevelStatus::applied, result, std::nullopt};
  if (circuits_[circuit].configuration.broadcast)
    return {LevelStatus::unsupported_lan_acknowledgement, result, std::nullopt};
  const auto admitted = acknowledgements_.admit(circuit, *result.transient_acknowledgement);
  const bool accepted = admitted.status == AcknowledgementAdmission::queued ||
      admitted.status == AcknowledgementAdmission::duplicate;
  return {accepted ? LevelStatus::applied : LevelStatus::capacity, result, admitted};
}

LevelSnpResult LevelProcess::receive_snp(std::size_t circuit, std::uint64_t epoch,
    const packet::isis::PduView &pdu, RuntimeClock::time_point now,
    LevelObserver observer) noexcept {
  const auto status = accept(circuit, epoch, observer);
  if (status != LevelStatus::applied) return {status, {}};
  const auto result = database_.receive_snp(pdu, circuit, circuits_[circuit].designated, now);
  if (result.waiting_state) wait(now, true, observer);
  return {result.status == SnpBatchStatus::malformed ? LevelStatus::malformed :
      result.status == SnpBatchStatus::discarded ? LevelStatus::discarded :
      result.waiting_state ? LevelStatus::capacity : LevelStatus::applied, result};
}

LevelOriginResult LevelProcess::originate(std::span<const std::uint8_t> wire,
    RuntimeClock::time_point now, OriginPurgeReason purge, LevelObserver observer) noexcept {
  if (!observer.event) return {LevelStatus::missing_observer, LspInstallResult::malformed};
  packet::isis::DecodeError error;
  const auto pdu = packet::isis::parse(wire, error);
  const auto header = pdu ? packet::isis::lsp(*pdu) : std::nullopt;
  if (!header || pdu->type != database_.type()) return {};
  if (purge > OriginPurgeReason::initiated ||
      (header->remaining_seconds != 0U) != (purge == OriginPurgeReason::none))
    return {LevelStatus::invalid_configuration, LspInstallResult::malformed};
  if (header->remaining_seconds && !header->checksum)
    return {LevelStatus::discarded, LspInstallResult::invalid_checksum};
  if (purge != OriginPurgeReason::none) {
    const auto current = database_.database().find(header->id, now);
    if (!current && purge == OriginPurgeReason::lifetime_expired)
      return {LevelStatus::invalid_configuration, LspInstallResult::malformed};
    if (current && ((purge == OriginPurgeReason::initiated) != (current->header.remaining_seconds != 0U)))
      return {LevelStatus::invalid_configuration, LspInstallResult::malformed};
  }
  const auto retention = purge == OriginPurgeReason::initiated
      ? std::chrono::seconds{maximum_age_} : purge_retention_;
  const auto result = database_.originate(wire, now, maximum_age_, retention);
  if (result == LspInstallResult::capacity_exhausted) {
    wait(now, true, observer);
    return {LevelStatus::capacity, result};
  }
  if (result == LspInstallResult::installed) {
    emit(LevelEventKind::database_changed, observer, header->id);
  }
  return {result == LspInstallResult::malformed ? LevelStatus::malformed :
      result == LspInstallResult::invalid_checksum || result == LspInstallResult::excessive_lifetime ||
          result == LspInstallResult::unknown_purge
          ? LevelStatus::discarded : LevelStatus::applied, result};
}

std::optional<LevelOutputs> LevelProcess::outputs(std::size_t circuit, std::uint64_t epoch) noexcept {
  if (circuit >= circuits_.size() || !circuits_[circuit].eligible ||
      circuits_[circuit].configuration.epoch != epoch) return std::nullopt;
  auto &owned = circuits_[circuit];
  return LevelOutputs{owned.snp, owned.lsp, owned.designated};
}

bool LevelProcess::retire_purge(const packet::isis::LspId &id,
    RuntimeClock::time_point now, LevelObserver observer) noexcept {
  if (!observer.event || !database_.retire_purge(id, now)) return false;
  emit(LevelEventKind::database_changed, observer, id);
  return true;
}

bool LevelProcess::decision_unavailable(RuntimeClock::time_point now, LevelObserver observer) noexcept {
  if (!observer.event) return false;
  wait(now, false, observer);
  return true;
}

bool LevelProcess::service_waiting(RuntimeClock::time_point now,
    bool decision_resources_available, LevelObserver observer) noexcept {
  if (!observer.event || !waiting_ || now < waiting_until_) return false;
  waiting_timer_expired_ = true;
  if (!decision_resources_available) return false;
  waiting_ = false;
  emit(LevelEventKind::overload_recovered, observer);
  return true;
}

std::optional<RuntimeClock::time_point> LevelProcess::waiting_deadline() const noexcept {
  return waiting_ && !waiting_timer_expired_ ? std::optional(waiting_until_) : std::nullopt;
}
} // namespace router::isis
