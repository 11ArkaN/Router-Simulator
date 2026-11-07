// An instance control owner retains current local semantic LSP content and
// independent generation schedules here. Publication uses its own update
// process; peer information must already have arrived through local circuits.

#pragma once

#include "router/isis_instance_update.hpp"
#include "router/isis_lsp_generation.hpp"

namespace router::isis {
struct LocalLspContent {
  std::uint8_t level{};
  packet::isis::LspId id{};
  std::uint8_t flags{};
  std::vector<std::uint8_t> options;
  // Cold-reserved identity and semantic buffer; false excludes it from current
  // generation without forgetting the sequence needed for later reuse.
  bool active{true};
  bool operator==(const LocalLspContent &) const = default;
};
struct LocalLspFragment {
  std::uint8_t number{}, flags{};
  std::span<const std::uint8_t> options;
};
struct LocalLspLevelProgram {
  std::uint16_t maximum_age{}, maximum_pdu_octets{};
  std::chrono::microseconds minimum_interval{}, refresh_interval{};
  bool operator==(const LocalLspLevelProgram &) const = default;
};
struct LocalLspProgram {
  std::array<std::optional<LocalLspLevelProgram>, 2U> levels;
  std::vector<LocalLspContent> records;
  // Same-owner value count; inactive reserved identities consume no LSDB record.
  [[nodiscard]] std::size_t active_records() const noexcept;
  std::uint64_t random{};
  bool operator==(const LocalLspProgram &) const = default;
};
enum class LocalContentResult : std::uint8_t { unchanged, changed, missing, invalid, capacity };
struct LocalGenerationResult {
  std::optional<RuntimeClock::time_point> deadline;
  std::size_t published{}, blocked{};
  GenerationStatus terminal{GenerationStatus::waiting};
};
struct LocalLspEntryCheckpoint {
  LocalLspContent content;
  LspGenerationCheckpoint generation;
  UpdateStatus last_error{UpdateStatus::applied};
  bool retirement_pending{}, retirement_blocked{};
};
struct LocalLspSetCheckpoint {
  std::uint32_t version{1U};
  packet::isis::SystemId local{};
  std::uint8_t maximum_areas{};
  UpdateInstanceSelector selector;
  std::array<std::optional<LocalLspLevelProgram>, 2U> levels;
  std::array<bool, 2U> waiting_overload{};
  std::vector<LocalLspEntryCheckpoint> entries;
  std::size_t first{};
  GenerationStatus terminal{GenerationStatus::waiting};
};
class LocalLspSet final {
public:
  // Cold construction validates unique local IDs, levels, framing and explicit
  // intervals, then reserves semantic and preparation buffers before publication.
  // Area Addresses are legal only in non-pseudonode fragment zero. Programs
  // contain local semantic records only, never received foreign bytes. The update
  // owner and all authentication leases outlive synchronous service calls.
  LocalLspSet(packet::isis::SystemId local, std::uint8_t maximum_areas,
      UpdateInstanceSelector selector, LocalLspProgram program,
      RuntimeClock::time_point now);
  // Same-owner content replacement within reserved capacity, without allocation.
  // Also reactivates a reserved withdrawn identity with its retained counter.
  // Refusal preserves content and scheduling. Repeated identical content does
  // not regenerate an LSP. Configuration owner validates semantic TLV values.
  [[nodiscard]] LocalContentResult replace(std::size_t level, const packet::isis::LspId &id,
      std::uint8_t flags, std::span<const std::uint8_t> options, RuntimeClock::time_point now) noexcept;
  // Same-owner complete semantic replacement for one seven-octet source ID.
  // Inputs are strictly ordered fragment numbers and must start at zero when
  // nonempty. Every identity/buffer is cold-reserved. Absent active fragments
  // become pending purges; the ordinary root family cannot become empty.
  // Preflight checks the entire set before changing content or schedules.
  // No allocation/callback and no wire publication. Caller inputs are disjoint
  // from private storage and expire on return. Generation publishes separately.
  [[nodiscard]] LocalContentResult replace_fragments(std::size_t level,
      const packet::isis::LanId &source, std::span<const LocalLspFragment> fragments,
      RuntimeClock::time_point now) noexcept;
  // Withdraws a reserved non-root identity. Its current body is purged with
  // unchanged sequence and MaxAge retention; an already expired body follows
  // ordinary expiration. Root 00 cannot be withdrawn while its level exists.
  // No allocation, immediate membership change, wire publication is deferred
  // to service(). Unknown IDs report missing; repeated withdrawal is unchanged.
  [[nodiscard]] LocalContentResult withdraw(std::size_t level, const packet::isis::LspId &id) noexcept;
  // Current-set membership is independent of retention in the local LSDB.
  [[nodiscard]] bool contains(std::size_t level, const packet::isis::LspId &id) const noexcept;
  // Same-owner current semantic projection for stable fragment placement.
  // Missing/withdrawn identities return nullopt. Option bytes borrow private
  // storage until the next mutation of this owner; never retain or send them
  // across shards. This view has no encoded authentication or received data.
  [[nodiscard]] std::optional<LocalLspFragment> fragment(std::size_t level,
      const packet::isis::LspId &id) const noexcept;
  // Last publication result, or nullopt for an identity outside reserved slots.
  // Value projection only; no semantic content or key reference escapes.
  [[nodiscard]] std::optional<UpdateStatus> last_error(std::size_t level,
      const packet::isis::LspId &id) const noexcept;
  // Committed live publication counter, retained while withdrawn; initially zero.
  [[nodiscard]] std::optional<std::uint32_t> sequence(std::size_t level,
      const packet::isis::LspId &id) const noexcept;
  // Parent classified a received own LSP/SNP as requiring regeneration. Unknown
  // IDs return false and remain the parent's initiated-purge responsibility.
  // A reserved withdrawn ID only remembers this floor; it emits no live LSP
  // until replace() reactivates it.
  [[nodiscard]] bool require_after(std::size_t level, const packet::isis::LspId &id,
      std::uint32_t sequence, RuntimeClock::time_point now) noexcept;
  // Projection from this same level process's overload event. Applies only to
  // the zeroth non-pseudonode LSP and never clears a configured overload flag.
  [[nodiscard]] LocalContentResult waiting_overload(std::size_t level, bool enabled,
      RuntimeClock::time_point now) noexcept;
  // Retry only after an actual storage/key-policy event. No timer polling of
  // failed publication. Existing pending content and sequence floors survive.
  void retry(std::size_t level) noexcept;
  // Cold control-owner preparation before publishing or restoring this local
  // catalog. Reserves update transaction metadata for the largest family in
  // each enabled level. Refusal changes no semantic or protocol state.
  [[nodiscard]] bool reserve_publication(InstanceUpdateProcess &update) const noexcept;
  // Bounded round-robin publication runs on the instance shard. Cold
  // reserve_publication() must precede grouped publication. Root zero
  // reserves its full effective originating buffer inside the existing LSDB
  // budget. Keys are borrowed for this call; scratch is exclusively reused.
  // A terminal result REQUIRES parent entity-wide shutdown and cooldown before
  // another set is constructed. This component never operates Hello circuits.
  [[nodiscard]] LocalGenerationResult service(InstanceUpdateProcess &update,
      std::array<TransmitAuthentication, 2U> authentication, RuntimeClock::time_point now,
      PduScratch &scratch, LevelObserver observer, std::size_t &budget) noexcept;
  // Same instance shard after quiescence. Capture owns semantic bytes and
  // relative schedules; allocation/clock failures throw. Restore checks the
  // caller's policy and reserved identities before publishing a fresh owner.
  // Refusal returns null without touching any existing owner or update process.
  [[nodiscard]] LocalLspSetCheckpoint checkpoint(RuntimeClock::time_point now) const;
  [[nodiscard]] static std::unique_ptr<LocalLspSet> restore_checkpoint(const LocalLspSetCheckpoint &saved,
      packet::isis::SystemId local, std::uint8_t maximum_areas, UpdateInstanceSelector selector,
      LocalLspProgram expected, RuntimeClock::time_point now) noexcept;
private:
  struct Entry {
    LocalLspContent content;
    LspGenerationSchedule generation;
    UpdateStatus last_error{UpdateStatus::applied};
    bool retirement_pending{}, retirement_blocked{};
    // Derived encoded preparation, owned only by this control shard. Capacity
    // is reserved cold; pending sequence/ticket remains in generation state.
    // No authentication lease survives encoding. Restore rebuilds these bytes.
    std::vector<std::uint8_t> prepared;
    OriginPurgeReason prepared_reason{OriginPurgeReason::none};
    Entry(LocalLspContent value, const LocalLspLevelProgram &program,
        std::uint64_t random, RuntimeClock::time_point now);
  };
  [[nodiscard]] LspBuild compose(const Entry &entry, std::uint32_t sequence,
      std::span<const std::uint8_t> options, std::uint8_t flags,
      std::optional<AuthenticationKey> key, PduScratch &scratch) const noexcept;
  void service_retained(InstanceUpdateProcess &update, Entry &entry,
      TransmitAuthentication authentication, RuntimeClock::time_point now,
      PduScratch &scratch, LevelObserver observer, std::size_t &budget, LocalGenerationResult &result) noexcept;
  void service_overload(InstanceUpdateProcess &update, std::size_t level,
      TransmitAuthentication authentication, RuntimeClock::time_point now,
      PduScratch &scratch, LevelObserver observer, std::size_t &budget, LocalGenerationResult &result) noexcept;
  [[nodiscard]] bool service_family(InstanceUpdateProcess &update, std::size_t index,
      std::array<TransmitAuthentication, 2U> authentication, RuntimeClock::time_point now,
      PduScratch &scratch, LevelObserver observer, std::size_t &budget, LocalGenerationResult &result) noexcept;
  [[nodiscard]] Entry *find(std::size_t level, const packet::isis::LspId &id) noexcept;
  packet::isis::SystemId local_;
  std::uint8_t maximum_areas_{};
  UpdateInstanceSelector selector_;
  std::array<std::optional<LocalLspLevelProgram>, 2U> levels_;
  std::array<bool, 2U> waiting_overload_{};
  std::vector<Entry> entries_;
  std::size_t first_{};
  GenerationStatus terminal_{GenerationStatus::waiting};
};
} // namespace router::isis
