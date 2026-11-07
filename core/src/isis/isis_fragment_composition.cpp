// ISO 10589 7.3.4 keeps fragment zero and retires empty higher fragments.
// Planning precedes one complete semantic edit; the local publication owner
// subsequently makes all changed encoded bodies and SRM obligations atomic.
#include "router/isis_fragment_composition.hpp"
#include <array>
#include <algorithm>
#include <numeric>
namespace router::isis {
LocalContentResult compose_local_fragments(LocalLspSet &local, FragmentPlanner &planner,
    std::size_t level, const packet::isis::LanId &source, std::uint8_t flags,
    std::span<const FragmentUnit> units, std::size_t semantic_octets,
    std::span<FragmentOptions> scratch, RuntimeClock::time_point now) noexcept {
  if (scratch.size() > 256U) return LocalContentResult::capacity;
  std::array<std::uint8_t, 256U> slots{};
  std::iota(slots.begin(), slots.end(), std::uint8_t{});
  return compose_local_fragment_slots(local, planner, level, source, flags, units, semantic_octets,
      std::span{slots}.first(scratch.size()), scratch, now);
}
LocalContentResult compose_local_fragment_slots(LocalLspSet &local, FragmentPlanner &planner,
    std::size_t level, const packet::isis::LanId &source, std::uint8_t flags,
    std::span<const FragmentUnit> units, std::size_t semantic_octets,
    std::span<const std::uint8_t> slots, std::span<FragmentOptions> scratch, RuntimeClock::time_point now) noexcept {
  if (slots.empty() || slots.size() > 256U || slots.size() != scratch.size() || slots.front() ||
      !std::is_sorted(slots.begin(), slots.end()) || std::adjacent_find(slots.begin(), slots.end()) != slots.end())
    return LocalContentResult::invalid;
  const auto planned = planner.compose(units, semantic_octets, source[6U] != 0U, scratch);
  if (planned != FragmentPlanStatus::planned)
    return planned == FragmentPlanStatus::capacity ? LocalContentResult::capacity : LocalContentResult::invalid;
  std::array<LocalLspFragment, 256U> fragments{};
  std::size_t count{};
  for (std::size_t index{}; index < scratch.size(); ++index)
    if (scratch[index].size || (!index && (!source[6U] || !units.empty())))
      fragments[count++] = {slots[index], flags, scratch[index].storage.first(scratch[index].size)};
  return local.replace_fragments(level, source, std::span{fragments}.first(count), now);
}
}
