// One instance control owner reuses bounded derived scratch for local root and
// pseudonode composition. The catalog, sequence, key and packet owners remain
// separate. Dependencies point to semantic encoders and the local content API.
#pragma once
#include "router/isis_fragment_composition.hpp"
#include "router/isis_neighbor_origination.hpp"
namespace router::isis {
// Same-owner cold catalog projection. Sorted unique source-family IDs borrow
// caller scratch until reuse. Empty reports missing root, duplicates or bounds;
// caller scratch may change on refusal. No semantic bytes or allocation escape.
[[nodiscard]] std::span<const std::uint8_t> local_fragment_slots(const LocalLspProgram &program,
    std::size_t level, const packet::isis::LanId &source, std::span<std::uint8_t> scratch) noexcept;
class OriginFragmentWorkspace final {
public:
  // Cold allocation before instance publication. Fragments are 1..256, and
  // semantic capacity fits a 16-bit PDU after its fixed header. Throws on
  // invalid/overflowing bounds or allocation refusal. One control shard only.
  OriginFragmentWorkspace(std::size_t maximum_units, std::size_t maximum_fragments,
      std::size_t maximum_semantic_octets);
  OriginFragmentWorkspace(const OriginFragmentWorkspace &) = delete;
  OriginFragmentWorkspace &operator=(const OriginFragmentWorkspace &) = delete;
  // Discards only derived preparation and borrowed views, without allocation.
  void reset() noexcept;
  // Borrowed complete semantic options outlive compose/reset. Link methods
  // instead encode into owned scratch. All add methods allocate nothing and
  // latch the first refusal; no local protocol/configuration state changes.
  [[nodiscard]] bool add_options(FragmentUnitId key, std::span<const std::uint8_t> options,
      std::optional<std::uint8_t> previous, bool root_only) noexcept;
  // Adds active non-pseudonode base content as individual complete TLVs.
  // Only Area Addresses are pinned to zero; movable root metadata/prefixes
  // retain their previous fragment where possible. Program storage outlives
  // compose/reset. Domain zero is reserved for these generated metadata keys.
  // A present area override replaces all base Area Addresses options as one
  // root-only unit; empty omits them. It borrows complete validated options
  // until compose/reset and never changes the admitted base configuration.
  [[nodiscard]] bool add_root_options(const LocalLspProgram &program, std::size_t level,
      std::optional<std::span<const std::uint8_t>> area_override = {}) noexcept;
  [[nodiscard]] bool add_link(FragmentUnitId key, packet::isis::LanId neighbor,
      const P2pOriginMetric &metric, std::optional<std::uint8_t> previous) noexcept;
  [[nodiscard]] bool add_pseudonode_link(FragmentUnitId key, packet::isis::SystemId peer,
      bool narrow, std::optional<std::uint8_t> previous) noexcept;
  // Same-owner complete edit. Keys are sorted without allocation before
  // packing. Caller chooses this family's cold-reserved contiguous ID count
  // and exact effective post-authentication capacity within constructor bounds.
  // Refusal preserves every local record/schedule. All borrowed views clear
  // before return; encoded publication remains deferred to the local owner.
  [[nodiscard]] LocalContentResult compose(LocalLspSet &local, std::size_t level,
      const packet::isis::LanId &source, std::uint8_t flags, std::size_t fragments,
      std::size_t semantic_octets, RuntimeClock::time_point now) noexcept;
  // Sparse reserved-ID variant. Previous placements use actual LSP numbers;
  // the workspace maps them to ordered slots before planning. Other contracts
  // match the contiguous variant. Validation changes no local catalog.
  [[nodiscard]] LocalContentResult compose(LocalLspSet &local, std::size_t level,
      const packet::isis::LanId &source, std::uint8_t flags, std::span<const std::uint8_t> slots,
      std::size_t semantic_octets, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] LocalContentResult validate(std::span<const std::uint8_t> slots,
      std::size_t semantic_octets) noexcept;
  // Read-only same-owner MT0 edge placement, ignoring mutable metrics. No
  // received state, allocations or borrowed view escapes. Missing returns null.
  [[nodiscard]] static std::optional<std::uint8_t> previous_link(const LocalLspSet &local,
      std::size_t level, const packet::isis::LanId &source, packet::isis::LanId neighbor,
      std::size_t fragments) noexcept;
private:
  [[nodiscard]] LocalContentResult prepare_units(std::span<const std::uint8_t> slots,
      std::size_t semantic_octets) noexcept;
  [[nodiscard]] bool finish_link(FragmentUnitId key, std::size_t size,
      std::optional<std::uint8_t> previous) noexcept;
  FragmentPlanner planner_;
  const std::size_t maximum_units_, maximum_semantic_;
  std::vector<std::uint8_t> input_, output_;
  std::vector<FragmentUnit> units_;
  std::vector<FragmentOptions> fragments_;
  std::size_t input_size_{};
  LocalContentResult error_{LocalContentResult::unchanged};
};
}
