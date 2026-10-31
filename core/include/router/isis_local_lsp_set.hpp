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
};
struct LocalLspLevelProgram {
  std::uint16_t maximum_age{}, maximum_pdu_octets{};
  std::chrono::microseconds minimum_interval{}, refresh_interval{};
};
struct LocalLspProgram {
  std::array<std::optional<LocalLspLevelProgram>, 2U> levels;
  std::vector<LocalLspContent> records;
  // Same-owner value count; inactive reserved identities consume no LSDB record.
  [[nodiscard]] std::size_t active_records() const noexcept;
  std::uint64_t random{};
};
enum class LocalContentResult : std::uint8_t { unchanged, changed, missing, invalid, capacity };
struct LocalGenerationResult {
  std::optional<RuntimeClock::time_point> deadline;
  std::size_t published{}, blocked{};
  GenerationStatus terminal{GenerationStatus::waiting};
};
class LocalLspSet final {
public:
  // Cold construction validates unique local IDs, levels, framing and explicit
  // intervals, then reserves each semantic buffer before publication. Programs
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
  // Withdraws a reserved non-root identity. Its current body is purged with
  // unchanged sequence and MaxAge retention; an already expired body follows
  // ordinary expiration. Root 00 cannot be withdrawn while its level exists.
  // No allocation, immediate membership change, wire publication is deferred
  // to service(). Unknown IDs report missing; repeated withdrawal is unchanged.
  [[nodiscard]] LocalContentResult withdraw(std::size_t level, const packet::isis::LspId &id) noexcept;
  // Current-set membership is independent of retention in the local LSDB.
  [[nodiscard]] bool contains(std::size_t level, const packet::isis::LspId &id) const noexcept;
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
  // Bounded round-robin publication runs on the instance shard. Root zero
  // reserves its full effective originating buffer inside the existing LSDB
  // budget. Keys are borrowed for this call; scratch is exclusively reused.
  // A terminal result REQUIRES parent entity-wide shutdown and cooldown before
  // another set is constructed. This component never operates Hello circuits.
  [[nodiscard]] LocalGenerationResult service(InstanceUpdateProcess &update,
      std::array<TransmitAuthentication, 2U> authentication, RuntimeClock::time_point now,
      PduScratch &scratch, LevelObserver observer, std::size_t &budget) noexcept;
private:
  struct Entry {
    LocalLspContent content;
    LspGenerationSchedule generation;
    UpdateStatus last_error{UpdateStatus::applied};
    bool retirement_pending{}, retirement_blocked{};
    Entry(LocalLspContent value, const LocalLspLevelProgram &program,
        std::uint64_t random, RuntimeClock::time_point now);
  };
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
