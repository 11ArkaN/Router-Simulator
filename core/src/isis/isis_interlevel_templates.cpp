// The instance control shard retains copied export provenance across SPF and
// route-installation receipt lifetimes. This bank has no selection policy,
// mutable protocol reference or cross-shard pointer, and cannot emit a frame.
// Source: ietf.isis.selected_interlevel_export
#include "router/isis_interlevel_templates.hpp"
#include <algorithm>
#include <stdexcept>
namespace router::isis {
namespace {
bool device_valid(lab::DeviceHandle device) noexcept {
  return device.generation && device.index < device_catalog::maximum_routers;
}
bool eligible(const PrefixAdvertisement &entry) noexcept { return entry.level == 1U && !entry.down; }
bool valid(const InterlevelTemplate &entry, std::span<const std::uint8_t> attributes) noexcept {
  const auto &advertisement = entry.advertisement;
  const auto &prefix = advertisement.prefix;
  const bool ipv6 = prefix.network.family == ip::AddressFamily::ipv6;
  if ((!ipv6 && prefix.network.family != ip::AddressFamily::ipv4) ||
      prefix.length > (ipv6 ? 128U : 32U) || ip::mask(prefix.network, prefix.length) != prefix.network ||
      (!ipv6 && std::any_of(prefix.network.bytes.begin() + 4U, prefix.network.bytes.end(), [](auto byte) { return byte != 0U; })) ||
      !eligible(advertisement) || advertisement.origin[6U] || advertisement.attributes_size != attributes.size() ||
      entry.distance.rank || entry.distance.internal_metric || advertisement.metric > entry.distance.metric ||
      entry.distance.metric > packet::isis::maximum_path_metric || !entry.owner.admission ||
      entry.owner.entity < entry.owner.admission || entry.owner.instance > device_catalog::isis_instance_last) return false;
  packet::isis::TlvCursor cursor(attributes);
  while (cursor.next()) {}
  return cursor.valid();
}
}
InterlevelTemplates::InterlevelTemplates(InterlevelTemplateBudget budget) : budget_(budget) {
  if (!budget.prefixes || budget.prefixes >= no_template || budget.prefixes > entries_.max_size() ||
      budget.attributes > UINT32_MAX || budget.attributes > attributes_.max_size() ||
      !budget.candidates_per_family || budget.candidates_per_family > device_catalog::maximum_dynamic_routes_per_router)
    throw std::invalid_argument("Invalid IS-IS interlevel template budget");
  entries_.reserve(budget.prefixes);
  attributes_.reserve(budget.attributes);
  for (auto &map : candidates_) map.reserve(budget.candidates_per_family);
}
bool InterlevelTemplates::begin(lab::DeviceHandle device, std::uint64_t publication) noexcept {
  if (!device_valid(device) || !publication) return false;
  device_ = device; publication_ = publication;
  entries_.clear(); attributes_.clear();
  for (auto &map : candidates_) map.clear();
  return true;
}
void InterlevelTemplates::clear() noexcept {
  device_ = {}; publication_ = 0U; entries_.clear(); attributes_.clear();
  for (auto &map : candidates_) map.clear();
}
InterlevelTemplateResult InterlevelTemplates::append(const PrefixAdvertisement &advertisement,
    PrefixDistance distance, InterlevelOwner owner, std::span<const std::uint8_t> attributes) noexcept {
  if (!publication_ || (advertisement.level != 1U && advertisement.level != 2U)) return {};
  if (!eligible(advertisement)) return {InterlevelTemplateStatus::ineligible, no_template};
  InterlevelTemplate entry{advertisement, distance, owner};
  if (!valid(entry, attributes)) return {};
  if (entries_.size() == budget_.prefixes || attributes.size() > budget_.attributes - attributes_.size())
    return {InterlevelTemplateStatus::capacity, no_template};
  entry.advertisement.attributes_offset = static_cast<std::uint32_t>(attributes_.size());
  const auto index = static_cast<std::uint32_t>(entries_.size());
  entries_.push_back(entry);
  attributes_.insert(attributes_.end(), attributes.begin(), attributes.end());
  return {InterlevelTemplateStatus::applied, index};
}
InterlevelTemplateStatus InterlevelTemplates::map_candidate(std::size_t family, std::uint32_t index) noexcept {
  if (!publication_ || family >= candidates_.size() || (index != no_template &&
      (index >= entries_.size() || (entries_[index].advertisement.prefix.network.family == ip::AddressFamily::ipv6) != (family == 1U))))
    return InterlevelTemplateStatus::invalid;
  if (candidates_[family].size() == budget_.candidates_per_family) return InterlevelTemplateStatus::capacity;
  candidates_[family].push_back(index);
  return InterlevelTemplateStatus::applied;
}
bool InterlevelTemplates::select(const routing::IsisRouteSelection &selection, std::span<bool> output) const noexcept {
  if (!routing::valid_isis_route_selection(selection) || selection.identity.device != device_ ||
      selection.identity.publication != publication_ || output.size() != entries_.size()) return false;
  for (std::size_t family{}; family < candidates_.size(); ++family)
    if (selection.counts[family] != candidates_[family].size()) return false;
  std::fill(output.begin(), output.end(), false);
  for (std::size_t family{}; family < candidates_.size(); ++family)
    for (std::size_t ordinal{}; ordinal < candidates_[family].size(); ++ordinal)
      if (selection.contains(family, ordinal) && candidates_[family][ordinal] != no_template)
        output[candidates_[family][ordinal]] = true;
  return true;
}
std::span<const std::uint8_t> InterlevelTemplates::attributes(std::size_t index) const noexcept {
  if (index >= entries_.size()) return {};
  const auto &entry = entries_[index].advertisement;
  return std::span{attributes_}.subspan(entry.attributes_offset, entry.attributes_size);
}
InterlevelTemplatesCheckpoint InterlevelTemplates::checkpoint() const {
  return {1U, budget_, device_, publication_, entries_, attributes_, candidates_};
}
bool InterlevelTemplates::restore(const InterlevelTemplatesCheckpoint &saved, lab::DeviceHandle expected) noexcept {
  if (saved.version != 1U || saved.budget != budget_ || saved.entries.size() > budget_.prefixes ||
      saved.attributes.size() > budget_.attributes ||
      (saved.publication ? (!device_valid(saved.device) || saved.device != expected) :
          (saved.device != lab::DeviceHandle{} || !saved.entries.empty() || !saved.attributes.empty() ||
              !saved.candidates[0U].empty() || !saved.candidates[1U].empty()))) return false;
  std::size_t offset{};
  for (const auto &entry : saved.entries) {
    const auto &advertisement = entry.advertisement;
    if (advertisement.attributes_offset != offset || advertisement.attributes_size > saved.attributes.size() - offset ||
        !valid(entry, std::span{saved.attributes}.subspan(offset, advertisement.attributes_size))) return false;
    offset += advertisement.attributes_size;
  }
  if (offset != saved.attributes.size()) return false;
  for (std::size_t family{}; family < candidates_.size(); ++family) {
    const auto &map = saved.candidates[family];
    if (map.size() > budget_.candidates_per_family) return false;
    for (const auto index : map)
      if (index != no_template && (index >= saved.entries.size() ||
          (saved.entries[index].advertisement.prefix.network.family == ip::AddressFamily::ipv6) != (family == 1U))) return false;
  }
  device_ = saved.device; publication_ = saved.publication;
  entries_.assign(saved.entries.begin(), saved.entries.end());
  attributes_.assign(saved.attributes.begin(), saved.attributes.end());
  for (std::size_t family{}; family < candidates_.size(); ++family)
    candidates_[family].assign(saved.candidates[family].begin(), saved.candidates[family].end());
  return true;
}
}
