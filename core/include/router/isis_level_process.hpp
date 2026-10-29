// One instance-level control owner joins its LSDB, flood obligations and egress
// reservations. Circuit slot identities remain stable until destruction; cold
// admission invalidates borrowed coordinator references. Peer information enters
// only as accepted encoded PDUs.

#pragma once

#include "router/isis_lsp_exchange.hpp"
#include "router/isis_snp_exchange.hpp"

namespace router::isis {
struct LevelCircuitConfiguration { bool broadcast{}; std::uint64_t epoch{}; };
enum class LevelEventKind : std::uint8_t {
  database_changed, circuit_changed, overload_entered, overload_recovered
};
struct LevelEvent {
  LevelEventKind kind{};
  packet::isis::PduType level{};
  std::optional<packet::isis::LspId> id;
};
struct LevelObserver {
  void *context{};
  // Synchronous same-owner notification. Mark origination/SPF work here;
  // never reenter this owner or retain borrowed packet and database views.
  void (*event)(void *, const LevelEvent &) noexcept{};
};
enum class LevelStatus : std::uint8_t {
  applied, invalid_circuit, stale_epoch, inactive, needs_down, missing_observer,
  malformed, discarded, capacity, invalid_configuration, unsupported_lan_acknowledgement
};
struct LevelLspResult {
  LevelStatus status{LevelStatus::malformed};
  LevelReceiveResult database;
  std::optional<AcknowledgementResult> acknowledgement;
};
struct LevelSnpResult {
  LevelStatus status{LevelStatus::malformed};
  SnpBatchResult database;
};
struct LevelOriginResult {
  LevelStatus status{LevelStatus::malformed};
  LspInstallResult install{LspInstallResult::malformed};
};
enum class OriginPurgeReason : std::uint8_t { none, lifetime_expired, initiated };
struct LevelOutputs {
  SnpExchange &snp;
  LspExchange &lsp;
  bool designated{};
};
struct LevelCircuitAdmission {
  LevelStatus status{LevelStatus::invalid_configuration};
  std::optional<std::size_t> index{};
};
class LevelProcess final {
public:
  // All limits are emulator admission budgets. Effective lifetime/retention
  // and Waiting Time must already be selected from the conformance profile.
  // Construction allocates all circuit reservations before publication and
  // rejects zero epochs, nonpositive durations or purge retention exceeding
  // the LSDB's unsigned 16-bit seconds contract. Nonempty circuit sets need
  // nonzero acknowledgement and SNP storage budgets. Future circuit capacity
  // also requires acknowledgement storage. Initial circuits are Down.
  LevelProcess(packet::isis::PduType level, LsdbLimits limits,
      std::span<const LevelCircuitConfiguration> circuits,
      std::size_t acknowledgement_capacity, std::size_t snp_entry_capacity,
      std::uint16_t maximum_age, std::chrono::seconds purge_retention,
      std::chrono::seconds waiting_time, std::size_t maximum_circuits = 0U);
  LevelProcess(const LevelProcess &) = delete;
  LevelProcess &operator=(const LevelProcess &) = delete;
  LevelProcess(LevelProcess &&) = delete;
  LevelProcess &operator=(LevelProcess &&) = delete;
  // Same owner, with no borrowed outputs outstanding. Adds an initially Down
  // slot within the construction budget, preserving the LSDB and every existing
  // output reservation. Failure publishes no slot or event. A nonzero epoch and
  // SNP entry budget are mandatory; no default or platform limit is selected.
  [[nodiscard]] LevelCircuitAdmission admit_circuit(LevelCircuitConfiguration configuration,
      std::size_t snp_entry_capacity) noexcept;
  // The parent completed old adjacency Down before replacing its epoch.
  // First activation may use the reserved epoch; reactivation needs a newer
  // epoch. Active media changes require Down. Synchronization floods retained
  // LSPs, requests a P2P complete sequence, and never invents peer information.
  [[nodiscard]] LevelStatus circuit(std::size_t index, std::uint64_t epoch,
      bool broadcast, bool eligible, bool designated, bool synchronize,
      LevelObserver observer) noexcept;
  // Parent accepted source adjacency, medium, level, instance, authentication,
  // maximum-area rules and self-originated fight-back before these calls.
  // Views expire on return. Refusal cannot acknowledge an unstored live LSP.
  [[nodiscard]] LevelLspResult receive_lsp(std::size_t circuit, std::uint64_t epoch,
      std::span<const std::uint8_t> wire, RuntimeClock::time_point now,
      LevelObserver observer) noexcept;
  [[nodiscard]] LevelSnpResult receive_snp(std::size_t circuit, std::uint64_t epoch,
      const packet::isis::PduView &pdu, RuntimeClock::time_point now,
      LevelObserver observer) noexcept;
  // The originator supplied finalized identity, sequence, options and digest.
  // A purge reason must match retained effective lifetime. Initiated purges
  // retain for MaxAge; expiration purges use the selected ZeroAgeLifetime.
  // Installed generations notify the same owner's SPF/origination scheduler.
  [[nodiscard]] LevelOriginResult originate(std::span<const std::uint8_t> wire,
      RuntimeClock::time_point now, OriginPurgeReason purge, LevelObserver observer) noexcept;
  // Borrowed coordinators stay on this shard and must not survive a circuit
  // transition. The parent supplies source-backed deadlines and dispatches
  // only encoded frames; actual receipts return to these exact reservations.
  [[nodiscard]] std::optional<LevelOutputs> outputs(std::size_t circuit,
      std::uint64_t epoch) noexcept;
  [[nodiscard]] bool retire_purge(const packet::isis::LspId &id,
      RuntimeClock::time_point now, LevelObserver observer) noexcept;
  // Decision resource failure enters Waiting without resetting an existing
  // last-ignored-LSP deadline. Update admission failures reset that deadline.
  // Waiting never stops reception, forwarding, flooding or ordinary SPF work.
  [[nodiscard]] bool decision_unavailable(RuntimeClock::time_point now,
      LevelObserver observer) noexcept;
  [[nodiscard]] bool service_waiting(RuntimeClock::time_point now,
      bool decision_resources_available, LevelObserver observer) noexcept;
  [[nodiscard]] bool waiting() const noexcept { return waiting_; }
  // Once an expired timer waits solely for a resource event, no past deadline
  // is exposed to the enclosing worker's sleep predicate.
  [[nodiscard]] std::optional<RuntimeClock::time_point> waiting_deadline() const noexcept;
  [[nodiscard]] const LevelDatabase &database() const noexcept { return database_; }
  [[nodiscard]] std::size_t transient_acknowledgements() const noexcept {
    return acknowledgements_.size();
  }
private:
  struct Circuit {
    LevelCircuitConfiguration configuration;
    bool eligible{}, designated{}, activated{};
    SnpExchange snp;
    LspExchange lsp;
    Circuit(LevelDatabase &database, TransientAcknowledgements &acknowledgements,
        std::size_t index, LevelCircuitConfiguration value, std::size_t entries)
        : configuration(value), snp(database, acknowledgements, index,
              value.epoch, entries), lsp(database, index, value.epoch) {}
  };
  [[nodiscard]] LevelStatus accept(std::size_t circuit, std::uint64_t epoch,
      LevelObserver observer) const noexcept;
  void emit(LevelEventKind event, LevelObserver observer,
      std::optional<packet::isis::LspId> id = std::nullopt) noexcept;
  void wait(RuntimeClock::time_point now, bool restart, LevelObserver observer) noexcept;
  LevelDatabase database_;
  TransientAcknowledgements acknowledgements_;
  std::vector<Circuit> circuits_;
  std::uint16_t maximum_age_{};
  std::chrono::seconds purge_retention_, waiting_time_;
  RuntimeClock::time_point waiting_until_{};
  bool waiting_{}, waiting_timer_expired_{};
};
} // namespace router::isis
