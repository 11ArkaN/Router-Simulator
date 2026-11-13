// Effective area selection and transition notifications remain on the instance
// control owner. Cold storage is reserved once; service and restoration neither
// allocate nor retain borrowed database, decision or observer references.
// Source: iso.10589.2002.area_addresses
#include "router/isis_area_set.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
namespace router::isis {
namespace {
bool less(const NeighborArea &a, const NeighborArea &b) noexcept {
  return std::lexicographical_compare(a.view().begin(), a.view().end(), b.view().begin(), b.view().end());
}
bool canonical(std::span<const NeighborArea> values) noexcept {
  for (const auto &area : values)
    if (!area.length || area.length > area.bytes.size() ||
        std::any_of(area.bytes.begin() + area.length, area.bytes.end(), [](auto byte) { return byte != 0U; })) return false;
  return true;
}
bool ordered(std::span<const NeighborArea> values) noexcept {
  return canonical(values) && std::adjacent_find(values.begin(), values.end(),
      [](const auto &a, const auto &b) { return !less(a, b); }) == values.end();
}
}
bool area_set_options_match(std::span<const std::uint8_t> options,
    std::span<const NeighborArea> expected) noexcept {
  if (!ordered(expected)) return false;
  std::size_t count{};
  packet::isis::TlvCursor cursor(options);
  while (const auto option = cursor.next()) if (option->code == 1U) {
    packet::isis::AreaAddressCursor addresses(*option);
    while (const auto address = addresses.next()) {
      if (count == expected.size() || !std::ranges::equal(*address, expected[count].view())) return false;
      ++count;
    }
    if (!addresses.valid()) return false;
  }
  return cursor.valid() && count == expected.size();
}
std::optional<std::size_t> encode_area_set_options(std::span<const NeighborArea> values,
    std::span<std::uint8_t> output) noexcept {
  if (values.size() > 255U || !ordered(values)) return {};
  if (values.empty()) return 0U;
  std::array<std::span<const std::uint8_t>, 255U> areas{};
  for (std::size_t index{}; index < values.size(); ++index) areas[index] = values[index].view();
  packet::isis::TlvWriter writer(output);
  if (!packet::isis::encode_area_addresses(writer, std::span{areas}.first(values.size()))) return {};
  return writer.bytes().size();
}
AreaAddressSet::AreaAddressSet(std::uint8_t maximum, std::span<const NeighborArea> manual) : maximum_(maximum) {
  if (!maximum || manual.size() > maximum || !canonical(manual))
    throw std::invalid_argument("Invalid IS-IS manual area set");
  manual_.assign(manual.begin(), manual.end());
  std::sort(manual_.begin(), manual_.end(), less);
  if (!ordered(manual_)) throw std::invalid_argument("Duplicate IS-IS manual area address");
  effective_.reserve(maximum);
  effective_.assign(manual_.begin(), manual_.end());
  rejected_.resize(manual_.size());
}
AreaSetResult AreaAddressSet::recompute(const LinkStateDatabase &database, const P2pRouteDecision &decision,
    RuntimeClock::time_point now, AreaSetObserver observer) noexcept {
  std::array<NeighborArea, 255U> selected{};
  std::array<bool, 255U> observed{};
  const auto count = collect_area_addresses(database, decision, now, std::span{selected}.first(maximum_),
      [&](const NeighborArea &area) noexcept {
        const auto found = std::lower_bound(manual_.begin(), manual_.end(), area, less);
        if (found != manual_.end() && *found == area) observed[static_cast<std::size_t>(found - manual_.begin())] = true;
      });
  if (!count) return {};
  const auto next = std::span{selected}.first(*count);
  const bool changed = !std::ranges::equal(next, effective_);
  effective_.assign(next.begin(), next.end());
  std::size_t events{};
  for (std::size_t index{}; index < manual_.size(); ++index) {
    if (std::binary_search(next.begin(), next.end(), manual_[index], less)) rejected_[index] = 0U;
    else if (observed[index] && !rejected_[index]) {
      rejected_[index] = 1U;
      ++dropped_;
      ++events;
      if (observer.dropped) observer.dropped(observer.context, ManualAreaDropped{manual_[index]});
    }
  }
  return {true, changed, events};
}
void AreaAddressSet::reset_to_manual() noexcept {
  effective_.assign(manual_.begin(), manual_.end());
  std::fill(rejected_.begin(), rejected_.end(), 0U);
}
AreaSetCheckpoint AreaAddressSet::checkpoint() const {
  return {1U, maximum_, manual_, effective_, rejected_, dropped_};
}
bool AreaAddressSet::restore(const AreaSetCheckpoint &saved) noexcept {
  if (saved.version != 1U || saved.maximum != maximum_ || saved.manual != manual_ ||
      saved.effective.size() > maximum_ || !ordered(saved.effective) || saved.rejected.size() != manual_.size()) return false;
  for (std::size_t index{}; index < manual_.size(); ++index)
    if (saved.rejected[index] > 1U || (saved.rejected[index] &&
        std::binary_search(saved.effective.begin(), saved.effective.end(), manual_[index], less))) return false;
  effective_.assign(saved.effective.begin(), saved.effective.end());
  std::copy(saved.rejected.begin(), saved.rejected.end(), rejected_.begin());
  dropped_ = saved.manual_addresses_dropped;
  return true;
}
}
