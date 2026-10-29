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

class LevelDatabase final {
public:
  // Circuit positions are stable for this aggregate's lifetime. Replacing a
  // circuit requires a new owner epoch before old egress receipts are applied.
  // Limits are emulator budgets. Construction reserves record metadata and
  // copies circuit eligibility; allocation failure precedes publication.
  LevelDatabase(packet::isis::PduType type, LsdbLimits limits,
                std::span<const FloodCircuit> circuits);

  // Same acceptance preconditions as LinkStateDatabase::install. Retained flag
  // storage is admitted before the LSDB changes. Allocation refusal cannot
  // acknowledge an LSP or publish a partial record. Views are not retained.
  [[nodiscard]] LevelReceiveResult receive(std::span<const std::uint8_t> wire,
      std::size_t ingress, RuntimeClock::time_point now,
      std::uint16_t maximum_age, std::chrono::seconds purge_retention) noexcept;
  // The local originator has completed identity, sequence and authentication
  // construction. An installed generation floods to every eligible circuit.
  // An unknown local purge is returned explicitly for the originator to handle.
  [[nodiscard]] LspInstallResult originate(std::span<const std::uint8_t> wire,
      RuntimeClock::time_point now, std::uint16_t maximum_age,
      std::chrono::seconds purge_retention) noexcept;
  // Stable slot programming runs after the instance finishes its Down work.
  // Media cannot change while eligible. flood_all is the owner's explicit
  // adjacency-Up or synchronization decision, never inferred from topology.
  [[nodiscard]] bool circuit(std::size_t index, bool broadcast, bool eligible,
      bool flood_all) noexcept;

  // Receipt header identifies the exact queued version. A delayed completion
  // for a superseded LSP cannot clear the replacement's flooding obligation.
  // The enclosing instance rejects stale circuit epochs before calling here.
  [[nodiscard]] bool complete(const packet::isis::LspView &sent,
      std::size_t circuit, bool partial_snp, bool enqueued,
      RuntimeClock::time_point now) noexcept;
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
  [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }
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
      std::uint16_t maximum_age, std::chrono::seconds purge_retention) noexcept;
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
};

} // namespace router::isis
