// The serialized network RIB owner creates selected-candidate projections only
// after real FIB commit. An IS-IS owner consumes copied versioned values through
// an SPSC lease; this module retains no RIB, candidate or protocol pointer.
// Source: ietf.isis.selected_interlevel_export
#pragma once
#include "router/lab_registry.hpp"
#include "router/routing_selected_candidates.hpp"
#include <array>
#include <cstdint>
namespace router::routing {
static_assert(device_catalog::maximum_dynamic_routes_per_router <= UINT16_MAX);
struct IsisSelectionIdentity {
  lab::DeviceHandle device{};
  std::uint64_t publication{}, configuration_epoch{}, revision{};
  bool operator==(const IsisSelectionIdentity &) const = default;
};
struct IsisRouteSelection {
  static constexpr std::size_t words = (device_catalog::maximum_dynamic_routes_per_router + 63U) / 64U;
  std::uint32_t version{1U};
  IsisSelectionIdentity identity{};
  std::array<std::uint32_t, 2U> counts{};
  std::array<std::array<std::uint64_t, words>, 2U> selected{};
  bool operator==(const IsisRouteSelection &) const = default;
  // Read-only copied value; false also covers an invalid family or ordinal.
  [[nodiscard]] bool contains(std::size_t family, std::size_t ordinal) const noexcept {
    return family < counts.size() && ordinal < counts[family] &&
        ordinal < device_catalog::maximum_dynamic_routes_per_router &&
        (selected[family][ordinal / 64U] & (UINT64_C(1) << (ordinal % 64U)));
  }
};
template <typename Entry> struct IsisSelectionInput {
  std::span<const Entry> competing, candidates;
  // Cold filtering during retirement preserves original publication ordinals.
  // Nonempty maps are strictly increasing and cover every retained candidate.
  // Empty means identity order, or a complete withdrawal when candidates empty.
  std::span<const std::uint16_t> ordinals;
  std::uint32_t original_count{};
};
enum class IsisSelectionStatus : std::uint8_t { applied, invalid, capacity };
// Structural wire-value admission, including zeroed unused bitmap bits. Device
// liveness, configuration epoch and publication identity remain receiver-owned.
[[nodiscard]] bool valid_isis_route_selection(const IsisRouteSelection &) noexcept;
// Same RIB shard, after successful dual-family FIB publication. Tables are the
// committed primary selections and candidate spans are their validated inputs.
// IS-IS distance preselection is reused before matching complete forwarding
// identities, so a discarded secondary metric cannot create a false winner.
// Output changes only on success. No allocation, borrowing or observer call;
// empty input is an explicit complete selection withdrawal for that family.
[[nodiscard]] IsisSelectionStatus project_isis_route_selection(IsisSelectionIdentity,
    const IsisSelectionInput<lab::routing::DynamicInput> &,
    const IsisSelectionInput<lab::routing::Ipv6DynamicInput> &,
    const lab::routing::RouteTable &, const lab::routing::Ipv6RouteTable &,
    IsisRouteSelection &) noexcept;
}
