// One IS-IS control owner copies L1 advertisement attributes beside a complete
// route publication. Installed and pending publications use separate banks; a later
// SPF cannot invalidate these values. Dependencies point to local protocol and
// copied RIB-selection contracts, never a remote router or a shared RIB view.
// Source: ietf.isis.selected_interlevel_export
#pragma once
#include "router/isis_prefix_set.hpp"
#include "router/isis_prefix_distance.hpp"
#include "router/isis_route_selection.hpp"
#include <limits>
namespace router::isis {
struct InterlevelOwner {
  std::uint8_t instance{};
  // Admission identifies the retained instance shell. Entity identifies its
  // current process incarnation and changes after fresh sequence recovery.
  // Neither value follows ordinary circuit synchronization-epoch increments.
  std::uint64_t admission{}, entity{};
  bool operator==(const InterlevelOwner &) const = default;
};
struct InterlevelTemplate {
  PrefixAdvertisement advertisement;
  PrefixDistance distance;
  InterlevelOwner owner;
  bool operator==(const InterlevelTemplate &) const = default;
};
struct InterlevelTemplateBudget {
  std::size_t prefixes{}, attributes{}, candidates_per_family{};
  bool operator==(const InterlevelTemplateBudget &) const = default;
};
struct InterlevelTemplatesCheckpoint {
  std::uint32_t version{1U};
  InterlevelTemplateBudget budget;
  lab::DeviceHandle device{};
  std::uint64_t publication{};
  std::vector<InterlevelTemplate> entries;
  std::vector<std::uint8_t> attributes;
  std::array<std::vector<std::uint32_t>, 2U> candidates;
};
enum class InterlevelTemplateStatus : std::uint8_t { applied, ineligible, invalid, capacity };
struct InterlevelTemplateResult {
  InterlevelTemplateStatus status{InterlevelTemplateStatus::invalid};
  std::uint32_t index{UINT32_MAX};
};
class InterlevelTemplates final {
public:
  static constexpr std::uint32_t no_template = UINT32_MAX;
  // Cold allocation of explicit emulator budgets. Invalid extents throw
  // invalid_argument; allocation failure propagates. Copies are forbidden so
  // service cannot inherit vectors whose capacity shrank during a value copy.
  explicit InterlevelTemplates(InterlevelTemplateBudget);
  InterlevelTemplates(const InterlevelTemplates &) = delete;
  InterlevelTemplates &operator=(const InterlevelTemplates &) = delete;
  // Control shard, exclusively unpublished bank after all prior leases ended.
  // Nonzero device/publication identity is mandatory. Refusal preserves state;
  // success clears the previous payload without allocation or observer calls.
  [[nodiscard]] bool begin(lab::DeviceHandle, std::uint64_t publication) noexcept;
  // Same unpublished-bank precondition as begin. Ends every borrowed view and
  // removes its identity/payload while retaining all reserved capacity.
  void clear() noexcept;
  // Same revision-fenced L1 decision as its route generation. Complete joined
  // attributes are copied now, before the next SPF can expire their source view.
  // Only wide, non-Down L1 advertisements are eligible. Ineligible input changes
  // nothing. Invalid/capacity preserves this append; the caller must abandon the
  // complete unpublished generation on refusal rather than publish a subset.
  [[nodiscard]] InterlevelTemplateResult append(const PrefixAdvertisement &, PrefixDistance,
      InterlevelOwner, std::span<const std::uint8_t> attributes) noexcept;
  // One append per original route-publication ordinal, including sentinels for
  // L2, Down and synthetic Attached defaults. ECMP ordinals may share a template.
  // Family is 0 for IPv4 or 1 for IPv6. Refusal preserves the map. No allocation.
  [[nodiscard]] InterlevelTemplateStatus map_candidate(std::size_t family, std::uint32_t index) noexcept;
  // After an actual matching RIB/FIB commit, produce one boolean per template.
  // Structural value, device, publication and both original candidate counts
  // must match. Configuration epoch, selection revision and owner incarnations
  // remain receiver-owned fences. Refusal preserves output. No retained borrow,
  // allocation or origination occurs, and an empty bitmap withdraws every item.
  [[nodiscard]] bool select(const routing::IsisRouteSelection &, std::span<bool>) const noexcept;
  // Same-shard immutable views expire at begin, successful append or restore.
  // No ownership crosses the view; an invalid attribute index returns empty.
  [[nodiscard]] std::span<const InterlevelTemplate> entries() const noexcept { return entries_; }
  [[nodiscard]] std::span<const std::uint8_t> attributes(std::size_t index) const noexcept;
  // Same-owner identity reads and original-ordinal lookup allocate nothing.
  // An invalid family/ordinal has no mapping; the sentinel is a valid mapping.
  [[nodiscard]] std::uint64_t publication() const noexcept { return publication_; }
  [[nodiscard]] lab::DeviceHandle device() const noexcept { return device_; }
  [[nodiscard]] InterlevelTemplateBudget budget() const noexcept { return budget_; }
  [[nodiscard]] std::optional<std::uint32_t> candidate_template(std::size_t family, std::size_t ordinal) const noexcept {
    return family < candidates_.size() && ordinal < candidates_[family].size() ?
        std::optional{candidates_[family][ordinal]} : std::nullopt;
  }
  [[nodiscard]] std::size_t candidate_count(std::size_t family) const noexcept {
    return family < candidates_.size() ? candidates_[family].size() : 0U;
  }
  // Quiescent value capture may allocate. Restore requires the exact budget and
  // expected physical device; it validates every span/map before allocation-free
  // replacement. A never-begun empty bank is valid. Refusal preserves this bank.
  [[nodiscard]] InterlevelTemplatesCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const InterlevelTemplatesCheckpoint &, lab::DeviceHandle expected) noexcept;
private:
  InterlevelTemplateBudget budget_;
  lab::DeviceHandle device_{};
  std::uint64_t publication_{};
  std::vector<InterlevelTemplate> entries_;
  std::vector<std::uint8_t> attributes_;
  std::array<std::vector<std::uint32_t>, 2U> candidates_;
};
}
