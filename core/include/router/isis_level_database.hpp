// One IS-IS level owns its encoded LSDB and per-circuit flood obligations.
// The instance control shard is the sole mutable owner. Accepted packets and
// actual egress receipts enter through this contract; no peer state is read.

#pragma once

#include "router/isis_flooding.hpp"

namespace router::isis {

struct LevelReceiveResult {
  LspInstallResult install{LspInstallResult::malformed};
  LspFloodResult flooding;
  // Effective purge fields for the transient owner, including normalization
  // of a received zero checksum to lifetime zero. No encoded LSP is retained.
  std::optional<packet::isis::SnpEntry> transient_acknowledgement;
};
struct PartialSnpSelection {
  std::size_t count{};
  std::optional<packet::isis::LspId> cursor;
};
enum class SnpBatchStatus : std::uint8_t { accepted, discarded, malformed };
struct SnpBatchResult {
  SnpBatchStatus status{SnpBatchStatus::discarded};
  bool waiting_state{};
  std::size_t confusions{};
};

// Same-owner transfer values join encoded LSDB records to their stable circuit
// slots and zero-sequence request metadata. Nested wire needs protected export.
struct LevelFloodRecordCheckpoint {
  packet::isis::LspId id{};
  std::vector<FloodCircuit> circuits;
  bool placeholder{};
};
struct LevelDatabaseCheckpoint {
  std::uint32_t version{1U};
  LsdbCheckpoint database;
  std::size_t maximum_circuits{};
  std::vector<FloodCircuit> circuits;
  std::vector<LevelFloodRecordCheckpoint> records;
};

class LevelDatabase final {
public:
  // Circuit positions are stable for this aggregate's lifetime. Replacing a
  // circuit requires a new owner epoch before old egress receipts are applied.
  // Limits are emulator budgets. Construction reserves record metadata and
  // copies circuit eligibility; allocation failure precedes publication.
  LevelDatabase(packet::isis::PduType type, LsdbLimits limits,
                std::span<const FloodCircuit> circuits, std::size_t maximum_circuits = 0U);
  // Same-owner cold-path admission. Zero constructor budget fixes the initial
  // slot count; otherwise the explicit emulator budget bounds future slots.
  // New slots start Down with no flood obligations. Allocation failure preserves
  // lengths and contents, although already reserved capacity may remain.
  // Same-owner cold preparation for a complete slot set. Checks the configured
  // ceiling and reserves every metadata vector without publishing a slot or
  // changing flags. Refusal may retain spare capacity but no logical mutation.
  [[nodiscard]] bool reserve_circuit_capacity(std::size_t count) noexcept;
  [[nodiscard]] std::optional<std::size_t> admit_circuit(bool broadcast) noexcept;
  [[nodiscard]] bool circuit_capacity_available() const noexcept {
    return circuits_.size() < maximum_circuits_;
  }
  // Construction rollback only: index is the last admitted, unpublished Down
  // slot, with no outstanding coordinator or receipt. Active slots never move
  // or disappear. A failed precondition preserves every slot and flag.
  [[nodiscard]] bool cancel_circuit_admission(std::size_t index) noexcept;

  // Same acceptance preconditions as LinkStateDatabase::install. Retained flag
  // storage is admitted before the LSDB changes. Allocation refusal cannot
  // acknowledge an LSP or publish a partial record. Views are not retained.
  [[nodiscard]] LevelReceiveResult receive(std::span<const std::uint8_t> wire,
      std::size_t ingress, RuntimeClock::time_point now,
      std::uint16_t maximum_age, std::chrono::seconds purge_retention) noexcept;
  // The local originator has completed identity, sequence and authentication
  // construction. An installed generation floods to every eligible circuit.
  // Local purges may retain an identity from a previous incarnation absent from this LSDB;
  // received unknown purges instead remain transient acknowledgements.
  // Optional local allocation reserves future content within the byte budget;
  // the parent uses it to guarantee its own non-pseudonode zeroth LSP storage.
  [[nodiscard]] LspInstallResult originate(std::span<const std::uint8_t> wire,
      RuntimeClock::time_point now, std::uint16_t maximum_age,
      std::chrono::seconds purge_retention, std::size_t minimum_allocation = 0U,
      LspPurgeAnchor anchor = LspPurgeAnchor::preserve_expiration) noexcept;
  // Stable slot programming runs after the instance finishes its Down work.
  // Media cannot change while eligible. flood_all is the owner's explicit
  // adjacency-Up or synchronization decision, never inferred from topology.
  [[nodiscard]] bool circuit(std::size_t index, bool broadcast, bool eligible,
      bool flood_all) noexcept;

  // Cold owner preparation for a bounded local fragment transaction. Capacity
  // is derived from reserved local IDs, never a new advertised platform limit.
  // Refusal changes no protocol state; already reserved spare storage may stay.
  [[nodiscard]] bool reserve_origin_batch(std::size_t count) noexcept;
  // Same owner, distinct local IDs and stable disjoint encoded inputs. Each
  // request supplies its validated lifetime, purge retention and allocation
  // floor; metadata callbacks must be absent because this owner stages flags.
  // Refusal preserves bodies, placeholders and all SRM/SSN. Success installs
  // every body before setting every affected eligible SRM and clearing SSN in
  // one uninterrupted owner turn, as required by ISO 10589 7.3.4.4.
  [[nodiscard]] LspInstallResult originate_batch(
      std::span<const LspInstallRequest> requests, RuntimeClock::time_point now) noexcept;


  // Receipt header identifies the exact queued version. A delayed completion
  // for a superseded LSP cannot clear the replacement's flooding obligation.
  // The enclosing instance rejects stale circuit epochs before calling here.
  [[nodiscard]] bool complete(const packet::isis::LspView &sent,
      std::size_t circuit, bool partial_snp, bool enqueued,
      RuntimeClock::time_point now) noexcept;
  // Same-owner ISO 10589 7.3.15 emission-size refusal. Caller just compared
  // this retained LSP with the effective circuit dataLinkBlockSize, has no
  // pending output for it, and must report lSPTooLargeToPropagate. Clear only
  // this circuit's SRM; retain the LSP, SSN and all other circuit obligations.
  [[nodiscard]] bool suppress_oversized(const packet::isis::LspId &id,
      std::size_t circuit) noexcept;
  // The instance accepted the containing SNP's source, level, authentication
  // and DIS rules. Missing live entries reserve bounded zero-sequence
  // placeholders with SSN on this circuit and no SRM. Refusal reports Waiting
  // State without accepting responsibility. Confusion returns to its purge owner.
  [[nodiscard]] SnpFloodResult receive_snp_entry(const packet::isis::SnpEntry &entry,
      std::size_t circuit, RuntimeClock::time_point now) noexcept;
  // Input is parse() output whose source adjacency, instance, authentication
  // and maximum-area acceptance passed on this owner. The complete ordered
  // entry list is validated before any flag mutation. Broadcast PSNPs require
  // local DIS role. Capacity refusal enters Waiting without acknowledging the
  // missing entry; other valid entries still apply. Confused retained headers
  // remain unchanged so the originator can rescan and resolve them afterward.
  [[nodiscard]] SnpBatchResult receive_snp(const packet::isis::PduView &pdu,
      std::size_t circuit, bool designated, RuntimeClock::time_point now) noexcept;
  // Called for retained entries absent from an accepted complete SNP range.
  // The instance has compared its complete, decoded entry list with this LSDB.
  void omitted(const packet::isis::LspId &id, std::size_t circuit,
      const packet::isis::LspId &first, const packet::isis::LspId &last,
      RuntimeClock::time_point now) noexcept;
  // Same-owner routing expiry latch only. No packet, flood flag or reservation
  // changes; false reports an ineligible or already notified record.
  [[nodiscard]] bool mark_expiration_notified(const packet::isis::LspId &id,
      RuntimeClock::time_point now) noexcept { return database_.mark_expiration_notified(id, now); }
  // Retires only a finalized purge after its LSDB retention deadline, then
  // removes its flags in the same owner turn. No borrowed view survives it.
  [[nodiscard]] bool retire_purge(const packet::isis::LspId &id,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] std::optional<FloodCircuit> flags(
      const packet::isis::LspId &id, std::size_t circuit) const noexcept;
  [[nodiscard]] const LinkStateDatabase &database() const noexcept { return database_; }
  // Includes zero-sequence requests without fabricating an encoded LSP.
  // Borrow-free projections run only on this level's owner shard.
  [[nodiscard]] std::optional<packet::isis::SnpEntry> snp_entry(
      const packet::isis::LspId &id, RuntimeClock::time_point now) const noexcept;
  [[nodiscard]] std::optional<packet::isis::SnpEntry> snp_entry_at(
      std::size_t index, RuntimeClock::time_point now) const noexcept;
  // Same owner, quiesced exchange coordinators. Copies the complete LSDB,
  // stable circuit slots, SRM/SSN and placeholders. Allocation/clock failures
  // propagate without changing the level; no borrowed packet view is returned.
  [[nodiscard]] LevelDatabaseCheckpoint checkpoint(RuntimeClock::time_point now) const;
  // Same owner. Requires matching slot count, media and construction budgets.
  // Validates all metadata and stages every allocation before the nested LSDB
  // commit; subsequent vector swaps cannot fail. False preserves the complete
  // level for malformed/capacity/clock input. Success invalidates borrowed views;
  // coordinator references to this LevelDatabase object remain valid.
  [[nodiscard]] bool restore(const LevelDatabaseCheckpoint &checkpoint,
      RuntimeClock::time_point now, std::uint16_t maximum_age) noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }
  [[nodiscard]] packet::isis::PduType type() const noexcept { return type_; }
  // Same-owner circuit-wide media/eligibility projection. Per-LSP SRM/SSN
  // remain available only through flags(id, circuit).
  [[nodiscard]] std::optional<FloodCircuit> circuit_state(std::size_t index) const noexcept {
    return index < circuits_.size() ? std::optional(circuits_[index]) : std::nullopt;
  }
  // Same owner, no mutation between counting and indexed selection. These
  // allocation-free LAN projections include retained SRM entries only, never
  // zero-sequence placeholders. Ineligible slots return zero/no identity;
  // invalid or non-broadcast slots return nullopt. Returned IDs own their bytes.
  [[nodiscard]] std::optional<std::size_t> broadcast_srm_count(std::size_t circuit) const noexcept;
  [[nodiscard]] std::optional<packet::isis::LspId> broadcast_srm_at(
      std::size_t circuit, std::size_t ordinal) const noexcept;
  // Caller retains a separate scan cursor per circuit and advances it to the
  // returned cursor after selecting this batch. Selection never clears SSN.
  // The cyclic scan prevents low-ID churn from starving higher IDs; output
  // is sorted for SNP composition even when the scan wraps. No allocation.
  [[nodiscard]] PartialSnpSelection partial_snp(std::size_t circuit,
      std::optional<packet::isis::LspId> cursor,
      std::span<packet::isis::SnpEntry> output, RuntimeClock::time_point now) const noexcept;

private:
  [[nodiscard]] LevelReceiveResult admit(std::span<const std::uint8_t> wire,
      std::optional<std::size_t> ingress, RuntimeClock::time_point now,
      std::uint16_t maximum_age, std::chrono::seconds purge_retention,
      std::size_t minimum_allocation = 0U, LspPurgeAnchor anchor = LspPurgeAnchor::preserve_expiration) noexcept;
  struct Record {
    packet::isis::LspId id{};
    std::vector<FloodCircuit> circuits;
    bool placeholder{};
  };
  [[nodiscard]] std::size_t position(const packet::isis::LspId &id) const noexcept;
  packet::isis::PduType type_;
  LinkStateDatabase database_;
  std::vector<FloodCircuit> circuits_;
  std::vector<Record> records_;
  std::size_t maximum_records_{};
  std::size_t maximum_circuits_{};
  // Derived synchronous transaction staging. Empty outside originate_batch;
  // only new identities allocate flag arrays, which then become live storage.
  std::vector<LspInstallRequest> origin_requests_;
  std::vector<Record> origin_records_;
};

} // namespace router::isis
