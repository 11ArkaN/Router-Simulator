// Derived input/output buffers never move after construction. Borrowed base
// options are released after each attempt; no packing history is authoritative.
// Previous edge placement is reconstructed from the local semantic catalog.
#include "router/isis_origin_fragment_workspace.hpp"
#include <algorithm>
#include <limits>
#include <array>
#include <numeric>
#include <stdexcept>
namespace router::isis {
namespace {
std::size_t product(std::size_t count, std::size_t octets) {
  if (count && octets > std::numeric_limits<std::size_t>::max() / count)
    throw std::invalid_argument("IS-IS fragment workspace overflow");
  return count * octets;
}
}
std::span<const std::uint8_t> local_fragment_slots(const LocalLspProgram &program,
    std::size_t level, const packet::isis::LanId &source, std::span<std::uint8_t> scratch) noexcept {
  std::size_t count{};
  for (const auto &record : program.records)
    if (record.level == level && std::equal(source.begin(), source.end(), record.id.begin())) {
      if (count == scratch.size()) return {};
      scratch[count++] = record.id[7U];
    }
  const auto slots = scratch.first(count);
  std::sort(slots.begin(), slots.end());
  if (slots.empty() || slots.front() || std::adjacent_find(slots.begin(), slots.end()) != slots.end()) return {};
  return slots;
}
OriginFragmentWorkspace::OriginFragmentWorkspace(std::size_t maximum_units,
    std::size_t maximum_fragments, std::size_t maximum_semantic_octets)
    : planner_(maximum_units), maximum_units_(maximum_units), maximum_semantic_(maximum_semantic_octets) {
  if (!maximum_fragments || maximum_fragments > 256U ||
      maximum_semantic_octets > 65535U - packet::isis::lsp_header_octets)
    throw std::invalid_argument("Invalid IS-IS fragment workspace bounds");
  input_.resize(product(maximum_units, 27U));
  output_.resize(product(maximum_fragments, maximum_semantic_octets));
  units_.reserve(maximum_units);
  fragments_.reserve(maximum_fragments);
  for (std::size_t fragment{}; fragment < maximum_fragments; ++fragment)
    fragments_.push_back({std::span{output_}.subspan(fragment * maximum_semantic_octets, maximum_semantic_octets), 0U});
}
void OriginFragmentWorkspace::reset() noexcept {
  units_.clear(); input_size_ = 0U; error_ = LocalContentResult::unchanged;
}
bool OriginFragmentWorkspace::add_options(FragmentUnitId key, std::span<const std::uint8_t> options,
    std::optional<std::uint8_t> previous, bool root_only) noexcept {
  if (error_ != LocalContentResult::unchanged) return false;
  if (units_.size() == maximum_units_) { error_ = LocalContentResult::capacity; return false; }
  units_.push_back({key, options, previous, root_only});
  return true;
}
bool OriginFragmentWorkspace::add_root_options(const LocalLspProgram &program, std::size_t level,
    std::optional<std::span<const std::uint8_t>> area_override) noexcept {
  if (level > 1U) { error_ = LocalContentResult::invalid; return false; }
  if (area_override) {
    packet::isis::TlvCursor framing(*area_override);
    while (const auto option = framing.next()) {
      if (option->code != 1U) { error_ = LocalContentResult::invalid; return false; }
      packet::isis::AreaAddressCursor addresses(*option);
      while (addresses.next()) {}
      if (!addresses.valid()) { error_ = LocalContentResult::invalid; return false; }
    }
    if (!framing.valid()) { error_ = LocalContentResult::invalid; return false; }
  }
  bool area_added{};
  std::uint64_t metadata{};
  for (const auto &record : program.records) {
    if (record.level != level || record.id[6U] || !record.active) continue;
    packet::isis::TlvCursor cursor(record.options);
    std::size_t offset{};
    while (const auto option = cursor.next()) {
      const auto size = option->value.size() + 2U;
      if (option->code == 1U && record.id[7U]) { error_ = LocalContentResult::invalid; return false; }
      const auto key = metadata++;
      if (option->code == 1U && area_override) {
        if (!area_added && !area_override->empty() && !add_options({0U, key}, *area_override, 0U, true)) return false;
        area_added = true;
      } else if (!add_options({0U, key}, std::span{record.options}.subspan(offset, size),
          record.id[7U], option->code == 1U)) return false;
      offset += size;
    }
    if (!cursor.valid()) { error_ = LocalContentResult::invalid; return false; }
  }
  if (area_override && !area_added && !area_override->empty())
    if (!add_options({0U, metadata}, *area_override, 0U, true)) return false;
  return error_ == LocalContentResult::unchanged;
}
bool OriginFragmentWorkspace::finish_link(FragmentUnitId key, std::size_t size,
    std::optional<std::uint8_t> previous) noexcept {
  if (!size) { error_ = LocalContentResult::invalid; return false; }
  const auto options = std::span<const std::uint8_t>{input_}.subspan(input_size_, size);
  if (!add_options(key, options, previous, false)) return false;
  input_size_ += size;
  return true;
}
bool OriginFragmentWorkspace::add_link(FragmentUnitId key, packet::isis::LanId neighbor,
    const P2pOriginMetric &metric, std::optional<std::uint8_t> previous) noexcept {
  if (error_ != LocalContentResult::unchanged) return false;
  if (units_.size() == maximum_units_) { error_ = LocalContentResult::capacity; return false; }
  packet::isis::TlvWriter writer(std::span{input_}.subspan(input_size_));
  packet::isis::SystemId system{};
  std::copy_n(neighbor.begin(), system.size(), system.begin());
  const bool encoded = neighbor[6U] ? append_lan_origin_neighbor(writer, neighbor, metric) :
      append_p2p_origin_neighbor(writer, system, metric);
  return finish_link(key, encoded ? writer.bytes().size() : 0U, previous);
}
bool OriginFragmentWorkspace::add_pseudonode_link(FragmentUnitId key, packet::isis::SystemId peer,
    bool narrow, std::optional<std::uint8_t> previous) noexcept {
  if (error_ != LocalContentResult::unchanged) return false;
  if (units_.size() == maximum_units_) { error_ = LocalContentResult::capacity; return false; }
  packet::isis::TlvWriter writer(std::span{input_}.subspan(input_size_));
  const bool encoded = append_pseudonode_origin_neighbor(writer, peer, narrow);
  return finish_link(key, encoded ? writer.bytes().size() : 0U, previous);
}
LocalContentResult OriginFragmentWorkspace::compose(LocalLspSet &local, std::size_t level,
    const packet::isis::LanId &source, std::uint8_t flags, std::size_t fragments,
    std::size_t semantic_octets, RuntimeClock::time_point now) noexcept {
  if (fragments > 256U) { reset(); return LocalContentResult::capacity; }
  std::array<std::uint8_t, 256U> slots{};
  std::iota(slots.begin(), slots.end(), std::uint8_t{});
  return compose(local, level, source, flags, std::span{slots}.first(fragments), semantic_octets, now);
}
LocalContentResult OriginFragmentWorkspace::prepare_units(std::span<const std::uint8_t> slots,
    std::size_t semantic_octets) noexcept {
  if (error_ != LocalContentResult::unchanged) return error_;
  if (slots.empty() || slots.size() > fragments_.size() || semantic_octets > maximum_semantic_)
    return LocalContentResult::capacity;
  if (slots.front() || !std::is_sorted(slots.begin(), slots.end()) ||
      std::adjacent_find(slots.begin(), slots.end()) != slots.end()) return LocalContentResult::invalid;
  std::sort(units_.begin(), units_.end(), [](const auto &a, const auto &b) { return a.identity < b.identity; });
  for (auto &unit : units_) if (unit.previous_fragment) {
    const auto position = std::lower_bound(slots.begin(), slots.end(), *unit.previous_fragment);
    if (position == slots.end() || *position != *unit.previous_fragment) unit.previous_fragment.reset();
    else unit.previous_fragment = static_cast<std::uint8_t>(position - slots.begin());
  }
  return LocalContentResult::unchanged;
}
LocalContentResult OriginFragmentWorkspace::compose(LocalLspSet &local, std::size_t level,
    const packet::isis::LanId &source, std::uint8_t flags, std::span<const std::uint8_t> slots,
    std::size_t semantic_octets, RuntimeClock::time_point now) noexcept {
  struct Clear { OriginFragmentWorkspace &owner; ~Clear() { owner.reset(); } } clear{*this};
  const auto status = prepare_units(slots, semantic_octets);
  if (status != LocalContentResult::unchanged) return status;
  return compose_local_fragment_slots(local, planner_, level, source, flags, units_, semantic_octets,
      slots, std::span{fragments_}.first(slots.size()), now);
}
LocalContentResult OriginFragmentWorkspace::validate(std::span<const std::uint8_t> slots,
    std::size_t semantic_octets) noexcept {
  struct Clear { OriginFragmentWorkspace &owner; ~Clear() { owner.reset(); } } clear{*this};
  const auto status = prepare_units(slots, semantic_octets);
  if (status != LocalContentResult::unchanged) return status;
  const auto planned = planner_.compose(units_, semantic_octets, false, std::span{fragments_}.first(slots.size()));
  return planned == FragmentPlanStatus::planned ? LocalContentResult::unchanged :
      planned == FragmentPlanStatus::capacity ? LocalContentResult::capacity : LocalContentResult::invalid;
}
std::optional<std::uint8_t> OriginFragmentWorkspace::previous_link(const LocalLspSet &local,
    std::size_t level, const packet::isis::LanId &source, packet::isis::LanId neighbor,
    std::size_t fragments) noexcept {
  if (fragments > 256U) return std::nullopt;
  packet::isis::LspId id{};
  std::copy(source.begin(), source.end(), id.begin());
  for (std::size_t number{}; number < fragments; ++number) {
    id[7U] = static_cast<std::uint8_t>(number);
    const auto content = local.fragment(level, id);
    if (!content) continue;
    packet::isis::TlvCursor options(content->options);
    while (const auto option = options.next()) if (option->code == 22U) {
      packet::isis::ExtendedNeighborCursor links(*option);
      while (const auto link = links.next()) if (link->id == neighbor) return id[7U];
    }
  }
  return std::nullopt;
}
}
