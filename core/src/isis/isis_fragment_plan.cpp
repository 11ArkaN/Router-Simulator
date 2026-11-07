// ISO 10589 7.3.4 retains adjacency placement when possible. Root-only content
// is placed first so it cannot be displaced by a previous ordinary assignment.
#include "router/isis_fragment_plan.hpp"
#include "router/isis_packet.hpp"
#include <algorithm>
#include <array>
#include <numeric>

namespace router::isis {
FragmentPlanner::FragmentPlanner(std::size_t maximum_units) : maximum_units_(maximum_units) {
  assignments_.reserve(maximum_units);
  order_.reserve(maximum_units);
}
FragmentPlanStatus FragmentPlanner::prepare(std::span<const FragmentUnit> units,
    std::size_t semantic_octets, std::size_t fragment_count, bool pseudonode) noexcept {
  if (!fragment_count || fragment_count > 256U) return FragmentPlanStatus::malformed;
  if (units.size() > maximum_units_)
    return FragmentPlanStatus::capacity;
  for (std::size_t index{}; index < units.size(); ++index) {
    const auto &unit = units[index];
    if ((index && units[index - 1U].identity >= unit.identity) || unit.tlv.empty())
      return FragmentPlanStatus::malformed;
    packet::isis::TlvCursor cursor(unit.tlv);
    while (const auto option = cursor.next())
      if (option->code == 7U || option->code == 10U || option->code == 13U ||
          (option->code == 1U && (!unit.root_only || pseudonode))) return FragmentPlanStatus::malformed;
    if (!cursor.valid()) return FragmentPlanStatus::malformed;
    if (unit.tlv.size() > semantic_octets) return FragmentPlanStatus::capacity;
  }
  assignments_.resize(units.size());
  std::array<std::size_t, 256U> used{};
  // Root-only units cannot fall back to a different fragment.
  for (std::size_t index{}; index < units.size(); ++index) if (units[index].root_only) {
    if (units[index].tlv.size() > semantic_octets - used[0U]) return FragmentPlanStatus::capacity;
    used[0U] += units[index].tlv.size();
    assignments_[index] = 0U;
  }
  // Reserve surviving old assignments before allocating newly introduced units.
  // Two passes prevent a new unit from evicting an unchanged old adjacency.
  for (std::size_t index{}; index < units.size(); ++index) {
    const auto &unit = units[index];
    if (unit.root_only) continue;
    const auto old = unit.previous_fragment;
    if (old && *old < fragment_count && unit.tlv.size() <= semantic_octets - used[*old]) {
      assignments_[index] = *old;
      used[*old] += unit.tlv.size();
    } else assignments_[index] = 256U;
  }
  for (std::size_t index{}; index < units.size(); ++index) {
    if (assignments_[index] != 256U) continue;
    const auto &unit = units[index];
    std::size_t fragment{};
    while (fragment < fragment_count && unit.tlv.size() > semantic_octets - used[fragment]) ++fragment;
    if (fragment == fragment_count) return dense(units, semantic_octets, fragment_count);
    assignments_[index] = static_cast<std::uint8_t>(fragment);
    used[fragment] += unit.tlv.size();
  }
  return FragmentPlanStatus::planned;
}
FragmentPlanStatus FragmentPlanner::dense(std::span<const FragmentUnit> units,
    std::size_t semantic_octets, std::size_t fragment_count) noexcept {
  // Stable placement may leave several small holes while a new larger unit
  // would fit after relocation. Retry with descending complete-unit sizes;
  // no byte is split and no caller output has changed at this point.
  order_.resize(units.size());
  std::iota(order_.begin(), order_.end(), std::size_t{});
  std::sort(order_.begin(), order_.end(), [&](auto left, auto right) {
    return units[left].tlv.size() != units[right].tlv.size() ?
        units[left].tlv.size() > units[right].tlv.size() : left < right;
  });
  std::array<std::size_t, 256U> used{};
  for (const auto index : order_) if (units[index].root_only) {
    assignments_[index] = 0U;
    used[0U] += units[index].tlv.size();
  }
  for (const auto index : order_) {
    const auto &unit = units[index];
    if (unit.root_only) continue;
    auto best = fragment_count;
    for (std::size_t fragment{}; fragment < fragment_count; ++fragment)
      if (unit.tlv.size() <= semantic_octets - used[fragment] &&
          (best == fragment_count || used[fragment] > used[best])) best = fragment;
    if (best == fragment_count) return FragmentPlanStatus::capacity;
    assignments_[index] = static_cast<std::uint16_t>(best);
    used[best] += unit.tlv.size();
  }
  return FragmentPlanStatus::planned;
}
FragmentPlanStatus FragmentPlanner::plan(std::span<const FragmentUnit> units,
    std::size_t semantic_octets, std::size_t fragment_count, bool pseudonode,
    std::span<std::uint8_t> output) noexcept {
  if (output.size() < units.size()) return FragmentPlanStatus::capacity;
  const auto status = prepare(units, semantic_octets, fragment_count, pseudonode);
  if (status != FragmentPlanStatus::planned) return status;
  std::transform(assignments_.begin(), assignments_.end(), output.begin(),
      [](std::uint16_t fragment) { return static_cast<std::uint8_t>(fragment); });
  return FragmentPlanStatus::planned;
}
FragmentPlanStatus FragmentPlanner::compose(std::span<const FragmentUnit> units,
    std::size_t semantic_octets, bool pseudonode, std::span<FragmentOptions> fragments) noexcept {
  const auto status = prepare(units, semantic_octets, fragments.size(), pseudonode);
  if (status != FragmentPlanStatus::planned) return status;
  std::array<std::size_t, 256U> sizes{};
  for (std::size_t index{}; index < units.size(); ++index)
    sizes[assignments_[index]] += units[index].tlv.size();
  for (std::size_t index{}; index < fragments.size(); ++index)
    if (sizes[index] > fragments[index].storage.size()) return FragmentPlanStatus::capacity;
  // All framing, placement and output bounds are complete before the first
  // caller-owned byte changes. No throwing operation remains in this commit.
  for (auto &fragment : fragments) fragment.size = 0U;
  for (std::size_t index{}; index < units.size(); ++index) {
    auto &fragment = fragments[assignments_[index]];
    std::copy(units[index].tlv.begin(), units[index].tlv.end(), fragment.storage.begin() + fragment.size);
    fragment.size += units[index].tlv.size();
  }
  return FragmentPlanStatus::planned;
}
}
