// The same instance control owner connects pure semantic packing to its local
// content catalog. This adapter owns no state, timer, key or received topology.
#pragma once
#include "router/isis_fragment_plan.hpp"
#include "router/isis_local_lsp_set.hpp"
namespace router::isis {
// Caller supplies complete local units, exact post-header/IID/authentication
// capacity and disjoint cold-reserved fragment buffers. All leases expire on
// return. The source family and every used ID must already be reserved locally.
// Success replaces the complete family and schedules removed fragments' purges;
// wire publication remains with LocalLspSet::service(). Refusal preserves all
// local content and schedules, but caller scratch may change. No allocation,
// callbacks or cross-shard access. An empty pseudonode family is withdrawn;
// the non-pseudonode root remains present even when it has no semantic options.
[[nodiscard]] LocalContentResult compose_local_fragments(LocalLspSet &local, FragmentPlanner &planner,
    std::size_t level, const packet::isis::LanId &source, std::uint8_t flags,
    std::span<const FragmentUnit> units, std::size_t semantic_octets,
    std::span<FragmentOptions> scratch, RuntimeClock::time_point now) noexcept;
// Explicit slot variant preserves sparse reserved LSP numbers. Slot IDs are
// sorted unique and start at zero; scratch has one buffer per slot. Previous
// placements in units refer to slot indices. Other ownership rules are equal.
[[nodiscard]] LocalContentResult compose_local_fragment_slots(LocalLspSet &local, FragmentPlanner &planner,
    std::size_t level, const packet::isis::LanId &source, std::uint8_t flags,
    std::span<const FragmentUnit> units, std::size_t semantic_octets,
    std::span<const std::uint8_t> slots, std::span<FragmentOptions> scratch, RuntimeClock::time_point now) noexcept;

}
