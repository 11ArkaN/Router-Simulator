// One control shard owns derived export scratch. Copied selection banks supply
// immutable provenance; complete wire units enter the existing local fragment
// workspace. No RIB pointer or mutable peer state is read or retained.
// Source: ietf.isis.selected_interlevel_export
#pragma once
#include "router/isis_interlevel_export_state.hpp"
#include "router/isis_interlevel_attributes.hpp"
#include "router/isis_origin_fragment_workspace.hpp"
#include "router/isis_local_prefix_catalog.hpp"
namespace router::isis {
struct InterlevelLocalPrefix {
  const void *context{};
  bool (*present)(const void *,const ip::IpPrefix &) noexcept{};
};
enum class InterlevelCompositionStatus : std::uint8_t { applied, invalid, capacity, conflicting_attributes };
struct InterlevelCompositionBounds { std::size_t attributes{}, parts{}, wire_octets{}; };
// Cold value calculation only. Bounds cover canonical flag growth, whole-tag
// splitting and independently encoded IPv6 host-prefix parts. nullopt refuses
// invalid emulator extents or host-size overflow; no allocation or vendor limit.
[[nodiscard]] std::optional<InterlevelCompositionBounds> interlevel_composition_bounds(InterlevelTemplateBudget) noexcept;
class InterlevelComposition final {
public:
  // Cold explicit emulator bounds. Scratch belongs to one control shard;
  // invalid or overflowing extents throw, allocation failure propagates.
  explicit InterlevelComposition(InterlevelTemplateBudget);
  // Same owner, stable selection bank and exclusively unpublished workspace.
  // The callback identifies already-originated local L2 prefixes and borrows
  // only for this call. New flag generation is explicit policy; received flags
  // remain preserved. Coequal origins with conflicting supported attributes
  // refuse instead of inventing an unsourced vendor tie-break. A late refusal
  // can change workspace scratch; the caller must abandon the whole root edit.
  // No allocation or protocol publication. Keys use domain 5 and copied parts.
  [[nodiscard]] InterlevelCompositionStatus append(OriginFragmentWorkspace &,
      const InterlevelExportState &,std::uint8_t instance,bool generate_flags,
      InterlevelLocalPrefix = {}) noexcept;
  // Same unpublished-workspace contract. A validated local catalog supplies
  // L1-only source prefixes under its ordinary interface/AF gates. Local L2
  // prefixes keep their existing metric via the callback. No RIB next hop is
  // invented for Self; the caller owns this separate local origination path.
  [[nodiscard]] InterlevelCompositionStatus append_local(OriginFragmentWorkspace &,
      const LocalPrefixCatalogProgram &,bool generate_flags,LocalPrefixAvailability = {},
      InterlevelLocalPrefix = {}) noexcept;
private:
  InterlevelTemplateBudget budget_;
  std::vector<std::size_t> order_;
  std::array<std::vector<std::uint8_t>,2U> attributes_;
};
}
