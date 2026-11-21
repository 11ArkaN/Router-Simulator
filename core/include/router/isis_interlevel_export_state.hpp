// One control owner keeps two copied export banks: the active selected payload
// and one route publication awaiting installation and selected-RIB feedback.
// Backpressure protects both lifetimes without retaining an SPF or RIB pointer.
// Source: ietf.isis.selected_interlevel_export
#pragma once
#include "router/isis_interlevel_templates.hpp"
#include <bitset>
#include <memory>
namespace router::isis {
struct InterlevelEligibility {
  std::uint64_t admission{}, entity{};
  std::uint8_t families{};
};
enum class InterlevelApplyStatus : std::uint8_t { applied, stale, invalid };
struct InterlevelApplyResult {
  InterlevelApplyStatus status{InterlevelApplyStatus::stale};
  std::bitset<device_catalog::isis_instance_last + 1U> dirty;
};
struct InterlevelExportCheckpoint {
  std::uint32_t version{1U};
  lab::DeviceHandle device{};
  InterlevelTemplatesCheckpoint active, pending;
  std::vector<std::uint8_t> selected;
  bool pending_confirmed{};
  std::uint64_t last_selection_revision{};
};
class InterlevelExportState final {
public:
  // Cold per-device admission only. The constructor validates the physical
  // handle and reserves both template banks and flag arrays before publishing
  // any owner. Invalid arguments throw; allocation failure propagates.
  InterlevelExportState(lab::DeviceHandle, InterlevelTemplateBudget);
  InterlevelExportState(const InterlevelExportState &) = delete;
  InterlevelExportState &operator=(const InterlevelExportState &) = delete;
  // One control shard, no unfinished build. A confirmed pending bank blocks
  // further route publication until its copied selection arrives. A selection
  // is itself authoritative post-FIB evidence, even before the separate receipt.
  [[nodiscard]] InterlevelTemplateBudget budget() const noexcept { return budget_; }
  [[nodiscard]] bool can_publish_routes() const noexcept;
  [[nodiscard]] bool begin_routes(std::uint64_t publication) noexcept;
  // Borrowed builder is valid only until route_published or abort_build. It must
  // not escape this synchronous build or cross a queue. Null outside a build.
  [[nodiscard]] InterlevelTemplates *building_templates() noexcept { return building_ ? pending_.get() : nullptr; }
  [[nodiscard]] bool route_published(std::uint64_t publication) noexcept;
  [[nodiscard]] bool abort_build() noexcept;
  // Installation confirms provenance, not export eligibility. Confirmation is
  // idempotent, including a generation already promoted by selection feedback.
  // Refusal cannot discard confirmed provenance. Unknown identities preserve state.
  [[nodiscard]] bool confirm_routes(std::uint64_t publication) noexcept;
  [[nodiscard]] bool refuse_routes(std::uint64_t publication) noexcept;
  // A complete configuration transaction carries the actual retained candidate
  // source publication. It may confirm a pending bank before its late receipt,
  // but cannot revert a source already proved newer by receipt or feedback.
  [[nodiscard]] bool can_retain_source(std::uint64_t publication) const noexcept;
  [[nodiscard]] bool confirm_retained_source(std::uint64_t publication) noexcept;
  // Only copied structurally valid values for this device/current epoch and a
  // newer selection revision are admitted. Owners are indexed by instance;
  // zero families disables an owner. All service methods allocate nothing.
  // A matching pending bank is promoted directly: this channel's sole producer
  // publishes only after real FIB commit. The ordinary receipt still returns
  // its independent route-channel credit and updates publisher bookkeeping.
  [[nodiscard]] InterlevelApplyResult accept(const routing::IsisRouteSelection &, std::uint64_t epoch,
      std::span<const InterlevelEligibility>) noexcept;
  // After owner/admin/family changes, clear stale eligibility. Re-enabling an
  // owner cannot revive old flags; incoming old-epoch messages remain stale.
  [[nodiscard]] InterlevelApplyResult reconcile(std::span<const InterlevelEligibility>) noexcept;
  // Same-shard views expire on a successful selected-publication promotion or
  // restore. Reads borrow no remote owner and invalid ordinals are unselected.
  [[nodiscard]] const InterlevelTemplates &active_templates() const noexcept { return *active_; }
  [[nodiscard]] bool selected(std::size_t index) const noexcept;
  [[nodiscard]] std::uint64_t pending_publication() const noexcept { return pending_->publication(); }
  [[nodiscard]] bool pending_confirmed() const noexcept { return pending_confirmed_; }
  [[nodiscard]] std::uint64_t last_selection_revision() const noexcept { return last_revision_; }
  // Quiescent capture may allocate and refuses an unfinished build. Restore
  // checks exact budgets, physical identity, flags and owner incarnations on
  // detached banks before one nonthrowing publication. Failure
  // preserves both live banks. No callback, origination or route publication.
  [[nodiscard]] InterlevelExportCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const InterlevelExportCheckpoint &,
      std::span<const InterlevelEligibility>) noexcept;
private:
  [[nodiscard]] InterlevelApplyResult apply_prepared(bool pending, std::uint64_t revision,
      std::span<const InterlevelEligibility>) noexcept;
  lab::DeviceHandle device_;
  InterlevelTemplateBudget budget_;
  std::unique_ptr<InterlevelTemplates> active_, pending_;
  std::unique_ptr<bool[]> selected_, scratch_;
  bool building_{}, pending_confirmed_{};
  std::uint64_t last_revision_{};
};
}
