// One serialized RIB owner retains source-publication ordinals and coalesced
// selection work. Live tables stay outside this object. A cold retirement saves
// original candidate values only when filtering first makes them unavailable.
// Source: ietf.isis.selected_interlevel_export
#pragma once
#include "router/isis_route_selection.hpp"
#include <memory>
#include <vector>
namespace router::routing {
struct IsisSelectionProducerCheckpoint {
  std::uint32_t version{1U};
  lab::DeviceHandle device{};
  std::size_t capacity{};
  std::uint64_t publication{}, revision{};
  bool dirty{}, filtered{};
  std::array<std::uint32_t,2U> original_counts{};
  std::array<std::vector<std::uint16_t>,2U> ordinals;
  std::vector<lab::routing::DynamicInput> original_ipv4;
  std::vector<lab::routing::Ipv6DynamicInput> original_ipv6;
};
class IsisSelectionProducer final {
public:
  class PreparedRetain final {
  public:
    PreparedRetain() = default;
    PreparedRetain(const PreparedRetain &) = delete;
    PreparedRetain &operator=(const PreparedRetain &) = delete;
  private:
    friend class IsisSelectionProducer;
    lab::DeviceHandle device{};
    std::uint64_t publication{}, revision{};
    std::array<std::size_t,2U> retained_counts{};
    std::array<std::vector<std::uint16_t>,2U> ordinals;
    std::vector<lab::routing::DynamicInput> original_ipv4;
    std::vector<lab::routing::Ipv6DynamicInput> original_ipv6;
    bool copy_original{}, ready{true};
  };
  // Cold admission only for a router requiring upward export. The immutable
  // device and positive capacity must fit generated bounds. Invalid values
  // throw invalid_argument; allocation failure propagates. Maps reserve their
  // full capacity, so hot replacement and publication cannot allocate.
  IsisSelectionProducer(lab::DeviceHandle, std::size_t capacity);
  IsisSelectionProducer(const IsisSelectionProducer &) = delete;
  IsisSelectionProducer &operator=(const IsisSelectionProducer &) = delete;
  // Same RIB owner, before any FIB/configuration mutation requiring feedback.
  // A terminal revision refuses instead of wrapping and reusing an identity.
  [[nodiscard]] bool can_change() const noexcept { return revision_ != UINT64_MAX; }
  [[nodiscard]] bool can_replace(std::uint64_t publication, std::array<std::uint32_t,2U> counts) const noexcept;
  // After real FIB commit and candidate retention, adopts a new complete source
  // publication and identity ordinal maps. Preflight above must have succeeded
  // without an intervening owner mutation. False preserves all state.
  [[nodiscard]] bool replace(std::uint64_t publication, std::array<std::uint32_t,2U> counts) noexcept;
  // Cold configuration prepare copies new maps and, on the first filter, the
  // original complete candidate values. Later filters reuse that owned copy.
  // Current spans are the actual retained source candidates; no borrowed view
  // escapes. Invalid subset, exhaustion or allocation failure returns null and
  // preserves this object. Preparation must precede the real FIB transaction.
  [[nodiscard]] std::unique_ptr<PreparedRetain> prepare_retain(
      std::span<const std::uint16_t> ipv4, std::span<const std::uint16_t> ipv6,
      std::span<const lab::routing::DynamicInput> current_ipv4,
      std::span<const lab::routing::Ipv6DynamicInput> current_ipv6) const noexcept;
  // Same owner after successful FIB retirement. Guarded allocation-free swaps
  // consume the detached preparation exactly once. A prior retention can only
  // reduce map sizes, so the guarded counts also reject superseded leases.
  // No restore is permitted while a preparation is leased. False preserves live state.
  [[nodiscard]] bool commit_retain(PreparedRetain &) noexcept;
  // Successful unrelated FIB changes or configuration refencing mark the latest
  // complete selection dirty. Full SPSC capacity leaves this flag set until
  // publication or a later actual commit supersedes it. No source returns false.
  [[nodiscard]] bool mark_dirty() noexcept;
  [[nodiscard]] bool ready() const noexcept { return dirty_ && publication_ && can_change(); }
  // Same committed RIB/candidate cohort, no intervening mutation until published.
  // The projection borrows only for this call and delegates route selection to
  // the shared comparator. Refusal preserves output and all producer state.
  [[nodiscard]] IsisSelectionStatus project(std::uint64_t configuration_epoch,
      std::span<const lab::routing::DynamicInput> competing_ipv4,
      std::span<const lab::routing::DynamicInput> retained_ipv4,
      std::span<const lab::routing::Ipv6DynamicInput> competing_ipv6,
      std::span<const lab::routing::Ipv6DynamicInput> retained_ipv6,
      const lab::routing::RouteTable &, const lab::routing::Ipv6RouteTable &,
      IsisRouteSelection &) const noexcept;
  // After SPSC release-publication, copy this identity before ending its lease.
  // Success advances the revision and clears dirty work. Duplicate or stale
  // identities refuse. The caller must not read the published slot afterwards.
  [[nodiscard]] bool published(IsisSelectionIdentity) noexcept;
  [[nodiscard]] std::uint64_t publication() const noexcept { return publication_; }
  [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }
  [[nodiscard]] std::optional<std::uint16_t> ordinal(std::size_t family, std::size_t index) const noexcept;
  // Quiescent value capture may allocate. Restore validates exact device and
  // capacity, canonical maps, revision state and the actual retained candidates
  // before allocation-free replacement. A cold original cache may allocate in
  // restore; failure or invalid input preserves every live field.
  [[nodiscard]] IsisSelectionProducerCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const IsisSelectionProducerCheckpoint &,
      std::span<const lab::routing::DynamicInput> retained_ipv4,
      std::span<const lab::routing::Ipv6DynamicInput> retained_ipv6) noexcept;
private:
  [[nodiscard]] bool valid_current(std::span<const lab::routing::DynamicInput>,
      std::span<const lab::routing::Ipv6DynamicInput>) const noexcept;
  lab::DeviceHandle device_;
  std::size_t capacity_;
  std::uint64_t publication_{}, revision_{};
  bool dirty_{}, filtered_{};
  std::array<std::uint32_t,2U> original_counts_{};
  std::array<std::vector<std::uint16_t>,2U> ordinals_;
  std::vector<lab::routing::DynamicInput> original_ipv4_;
  std::vector<lab::routing::Ipv6DynamicInput> original_ipv6_;
};
}
