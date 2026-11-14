// Source ordinals remain network-owner values across cold candidate filtering.
// Only a real committed RIB cohort is projected. The reverse SPSC and protocol
// template consumers have separate owners; no view survives a method call.
// Source: ietf.isis.selected_interlevel_export
#include "router/isis_selection_producer.hpp"
#include <algorithm>
#include <numeric>
#include <stdexcept>
namespace router::routing {
namespace {
bool ordered(std::span<const std::uint16_t> values, std::uint32_t extent) noexcept {
  return values.empty() || (values.back() < extent && std::adjacent_find(values.begin(), values.end(),
      [](auto left, auto right) { return left >= right; }) == values.end());
}
template <typename Entry> bool retained_matches(std::span<const Entry> retained,
    std::span<const std::uint16_t> ordinals, std::span<const Entry> original, bool filtered) noexcept {
  if (retained.size() != ordinals.size()) return false;
  if (filtered) for (std::size_t index{}; index < retained.size(); ++index)
    if (ordinals[index] >= original.size() || retained[index] != original[ordinals[index]]) return false;
  return true;
}
}
IsisSelectionProducer::IsisSelectionProducer(lab::DeviceHandle device, std::size_t capacity)
    : device_(device), capacity_(capacity) {
  if (!device.generation || device.index >= device_catalog::maximum_routers || !capacity ||
      capacity > device_catalog::maximum_dynamic_routes_per_router)
    throw std::invalid_argument("Invalid IS-IS selection producer admission");
  for (auto &map : ordinals_) map.reserve(capacity);
}
bool IsisSelectionProducer::can_replace(std::uint64_t publication, std::array<std::uint32_t,2U> counts) const noexcept {
  return can_change() && publication > publication_ && counts[0U] <= capacity_ && counts[1U] <= capacity_;
}
bool IsisSelectionProducer::replace(std::uint64_t publication, std::array<std::uint32_t,2U> counts) noexcept {
  if (!can_replace(publication,counts)) return false;
  for (std::size_t family{}; family < ordinals_.size(); ++family) {
    ordinals_[family].resize(counts[family]);
    std::iota(ordinals_[family].begin(),ordinals_[family].end(),std::uint16_t{});
  }
  publication_ = publication; original_counts_ = counts; dirty_ = true; filtered_ = false;
  original_ipv4_.clear(); original_ipv6_.clear();
  return true;
}
bool IsisSelectionProducer::valid_current(std::span<const lab::routing::DynamicInput> ipv4,
    std::span<const lab::routing::Ipv6DynamicInput> ipv6) const noexcept {
  return retained_matches(ipv4,ordinals_[0U],std::span{original_ipv4_},filtered_) &&
      retained_matches(ipv6,ordinals_[1U],std::span{original_ipv6_},filtered_);
}
std::unique_ptr<IsisSelectionProducer::PreparedRetain> IsisSelectionProducer::prepare_retain(
    std::span<const std::uint16_t> ipv4, std::span<const std::uint16_t> ipv6,
    std::span<const lab::routing::DynamicInput> current4,
    std::span<const lab::routing::Ipv6DynamicInput> current6) const noexcept {
  if (!publication_ || !can_change() || !valid_current(current4,current6)) return nullptr;
  const std::array next{ipv4,ipv6};
  for (std::size_t family{}; family < next.size(); ++family)
    if (!ordered(next[family],original_counts_[family]) ||
        !std::includes(ordinals_[family].begin(),ordinals_[family].end(),next[family].begin(),next[family].end())) return nullptr;
  try {
    auto result = std::make_unique<PreparedRetain>();
    result->device = device_; result->publication = publication_; result->revision = revision_;
    result->retained_counts = {ordinals_[0U].size(),ordinals_[1U].size()};
    for (std::size_t family{}; family < next.size(); ++family) {
      result->ordinals[family].reserve(capacity_);
      result->ordinals[family].assign(next[family].begin(),next[family].end());
    }
    result->copy_original = !filtered_ && (next[0U].size() != current4.size() || next[1U].size() != current6.size());
    if (result->copy_original) {
      result->original_ipv4.assign(current4.begin(),current4.end());
      result->original_ipv6.assign(current6.begin(),current6.end());
    }
    return result;
  } catch (...) { return nullptr; }
}
bool IsisSelectionProducer::commit_retain(PreparedRetain &prepared) noexcept {
  if (!prepared.ready || !can_change() || prepared.device != device_ ||
      prepared.publication != publication_ || prepared.revision != revision_ ||
      prepared.retained_counts != std::array{ordinals_[0U].size(),ordinals_[1U].size()}) return false;
  for (std::size_t family{}; family < ordinals_.size(); ++family) ordinals_[family].swap(prepared.ordinals[family]);
  if (prepared.copy_original) {
    original_ipv4_.swap(prepared.original_ipv4); original_ipv6_.swap(prepared.original_ipv6);
    filtered_ = true;
  }
  dirty_ = true; prepared.ready = false;
  return true;
}
bool IsisSelectionProducer::mark_dirty() noexcept {
  if (!publication_ || !can_change()) return false;
  dirty_ = true; return true;
}
IsisSelectionStatus IsisSelectionProducer::project(std::uint64_t epoch,
    std::span<const lab::routing::DynamicInput> competing4, std::span<const lab::routing::DynamicInput> retained4,
    std::span<const lab::routing::Ipv6DynamicInput> competing6, std::span<const lab::routing::Ipv6DynamicInput> retained6,
    const lab::routing::RouteTable &table4, const lab::routing::Ipv6RouteTable &table6, IsisRouteSelection &output) const noexcept {
  if (!ready() || !valid_current(retained4,retained6)) return IsisSelectionStatus::invalid;
  return project_isis_route_selection({device_,publication_,epoch,revision_ + 1U},
      {competing4,retained4,ordinals_[0U],original_counts_[0U]},
      {competing6,retained6,ordinals_[1U],original_counts_[1U]},table4,table6,output);
}
bool IsisSelectionProducer::published(IsisSelectionIdentity identity) noexcept {
  if (!ready() || identity.device != device_ || identity.publication != publication_ ||
      !identity.configuration_epoch || identity.revision != revision_ + 1U) return false;
  revision_ = identity.revision; dirty_ = false; return true;
}
std::optional<std::uint16_t> IsisSelectionProducer::ordinal(std::size_t family, std::size_t index) const noexcept {
  return family < ordinals_.size() && index < ordinals_[family].size() ? std::optional{ordinals_[family][index]} : std::nullopt;
}
IsisSelectionProducerCheckpoint IsisSelectionProducer::checkpoint() const {
  return {1U,device_,capacity_,publication_,revision_,dirty_,filtered_,original_counts_,ordinals_,original_ipv4_,original_ipv6_};
}
bool IsisSelectionProducer::restore(const IsisSelectionProducerCheckpoint &saved,
    std::span<const lab::routing::DynamicInput> retained4, std::span<const lab::routing::Ipv6DynamicInput> retained6) noexcept {
  if (saved.version != 1U || saved.device != device_ || saved.capacity != capacity_ ||
      (saved.revision == UINT64_MAX && saved.dirty) ||
      (!saved.publication && (saved.revision || saved.dirty || saved.filtered || saved.original_counts != std::array<std::uint32_t,2U>{})) ||
      (saved.publication && !saved.revision && !saved.dirty)) return false;
  const std::array original_sizes{saved.original_ipv4.size(),saved.original_ipv6.size()};
  for (std::size_t family{}; family < ordinals_.size(); ++family) {
    const auto &map = saved.ordinals[family];
    if (saved.original_counts[family] > capacity_ || !ordered(map,saved.original_counts[family]) ||
        (saved.filtered ? original_sizes[family] != saved.original_counts[family] :
            (original_sizes[family] || map.size() != saved.original_counts[family]))) return false;
    if (!saved.filtered) for (std::size_t index{}; index < map.size(); ++index)
      if (map[index] != index) return false;
  }
  if (!retained_matches(retained4,saved.ordinals[0U],std::span{saved.original_ipv4},saved.filtered) ||
      !retained_matches(retained6,saved.ordinals[1U],std::span{saved.original_ipv6},saved.filtered)) return false;
  try {
    auto original4 = saved.original_ipv4; auto original6 = saved.original_ipv6;
    original_ipv4_.swap(original4); original_ipv6_.swap(original6);
    for (std::size_t family{}; family < ordinals_.size(); ++family)
      ordinals_[family].assign(saved.ordinals[family].begin(),saved.ordinals[family].end());
    publication_ = saved.publication; revision_ = saved.revision; dirty_ = saved.dirty;
    filtered_ = saved.filtered; original_counts_ = saved.original_counts;
    return true;
  } catch (...) { return false; }
}
}
