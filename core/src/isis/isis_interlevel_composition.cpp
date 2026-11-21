// Derived per-owner export work is bounded before activation. Supported
// attributes and every independently parsable part are copied synchronously;
// the local LSP owner alone decides whether to publish the complete root edit.
// Source: ietf.isis.selected_interlevel_export
#include "router/isis_interlevel_composition.hpp"
#include <algorithm>
#include <stdexcept>
namespace router::isis {
namespace {
InterlevelAttributeResult normalize(const ip::IpPrefix &prefix,std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output,bool generate_flags) noexcept {
  auto result=prepare_interlevel_attributes(prefix,input,output);
  if (result.status!=InterlevelAttributeStatus::applied || generate_flags) return result;
  const auto metadata=packet::isis::prefix_metadata(prefix,input);
  if (!metadata) return {};
  if (!metadata->flags) {
    std::move(output.begin()+3U,output.begin()+result.octets,output.begin());
    result.octets-=3U;
  }
  return result;
}
InterlevelCompositionStatus emit(OriginFragmentWorkspace &workspace,packet::isis::ExtendedPrefix prefix,
    std::uint64_t domain,std::uint64_t &key) noexcept {
  InterlevelPrefixParts parts(prefix);
  if (!parts.valid()) return InterlevelCompositionStatus::invalid;
  std::optional<FragmentUnitId> previous;
  while (const auto part=parts.next()) {
    if (key==UINT64_MAX) return InterlevelCompositionStatus::capacity;
    const FragmentUnitId identity{domain,++key};
    if (!workspace.copy_options(identity,*part,{},previous)) return InterlevelCompositionStatus::capacity;
    previous=identity;
  }
  return InterlevelCompositionStatus::applied;
}
}
std::optional<InterlevelCompositionBounds> interlevel_composition_bounds(InterlevelTemplateBudget budget) noexcept {
  if (!budget.prefixes || budget.prefixes > device_catalog::maximum_dynamic_routes_per_router*2U ||
      budget.attributes > UINT32_MAX || !budget.candidates_per_family ||
      budget.candidates_per_family > device_catalog::maximum_dynamic_routes_per_router) return std::nullopt;
  // The smallest attribute payload capacity is 232 octets (IPv6 /128).
  // A valid source tag list needs at least 234 bytes before splitting adds
  // another two-byte header. Greedy complete-sub-TLV packing makes adjacent
  // part payloads sum to more than that capacity, bounding the part count.
  const std::uint64_t attributes = budget.attributes+2ULL*(budget.attributes/234U)+3ULL*budget.prefixes;
  const std::uint64_t parts = budget.prefixes+2ULL*attributes/232U+1U;
  const auto wire = attributes+25ULL*parts;
  if (wire > SIZE_MAX) return std::nullopt;
  return InterlevelCompositionBounds{static_cast<std::size_t>(attributes),static_cast<std::size_t>(parts),
      static_cast<std::size_t>(wire)};
}
InterlevelComposition::InterlevelComposition(InterlevelTemplateBudget budget) : budget_(budget) {
  if (!interlevel_composition_bounds(budget) || budget.attributes > (SIZE_MAX-3U)/2U) throw std::invalid_argument("Invalid IS-IS export composition budget");
  order_.reserve(budget.prefixes);
  // A local single reachability entry can carry attributes independently of
  // the received-prefix bank's budget. Reserve its wire-sized normalization too.
  for (auto &bytes : attributes_) bytes.resize(std::max(budget.attributes*2U+3U,std::size_t{2U*UINT8_MAX+3U}));
}
InterlevelCompositionStatus InterlevelComposition::append(OriginFragmentWorkspace &workspace,
    const InterlevelExportState &state,std::uint8_t instance,bool generate_flags,InterlevelLocalPrefix local) noexcept {
  using Status = InterlevelCompositionStatus;
  if (instance > device_catalog::isis_instance_last || state.budget() != budget_) return Status::invalid;
  const auto &bank = state.active_templates();
  const auto entries = bank.entries();
  order_.clear();
  for (std::size_t index{}; index < entries.size(); ++index)
    if (entries[index].owner.instance == instance && state.selected(index) &&
        (!local.present || !local.present(local.context,entries[index].advertisement.prefix))) {
      if (order_.size() == order_.capacity()) return Status::capacity;
      order_.push_back(index);
    }
  std::sort(order_.begin(),order_.end(),[&](auto a,auto b) {
    const auto &left = entries[a].advertisement.prefix, &right = entries[b].advertisement.prefix;
    return left != right ? left < right : a < b;
  });
  std::optional<std::size_t> previous;
  std::size_t previous_octets{}, scratch{};
  std::uint64_t key{};
  for (const auto index : order_) {
    const auto &entry = entries[index];
    auto &bytes = attributes_[scratch];
    const auto input = bank.attributes(index);
    const auto normalized = normalize(entry.advertisement.prefix,input,bytes,generate_flags);
    if (normalized.status != InterlevelAttributeStatus::applied)
      return normalized.status == InterlevelAttributeStatus::capacity ? Status::capacity : Status::invalid;
    auto attributes = std::span<const std::uint8_t>{bytes}.first(normalized.octets);
    if (previous && entries[*previous].advertisement.prefix == entry.advertisement.prefix) {
      const auto &old = entries[*previous];
      if (old.distance.metric != entry.distance.metric || old.advertisement.external != entry.advertisement.external ||
          !std::ranges::equal(attributes,std::span<const std::uint8_t>{attributes_[1U-scratch]}.first(previous_octets)))
        return Status::conflicting_attributes;
      continue;
    }
    const auto emitted=emit(workspace,{entry.advertisement.prefix,entry.distance.metric,false,
        entry.advertisement.prefix.network.family==ip::AddressFamily::ipv6 && entry.advertisement.external,
        !attributes.empty(),attributes},5U,key);
    if (emitted!=Status::applied) return emitted;
    previous = index; previous_octets = attributes.size(); scratch = 1U-scratch;
  }
  return Status::applied;
}
InterlevelCompositionStatus InterlevelComposition::append_local(OriginFragmentWorkspace &workspace,
    const LocalPrefixCatalogProgram &catalog,bool generate_flags,LocalPrefixAvailability gate,
    InterlevelLocalPrefix local) noexcept {
  std::uint64_t key{};
  for (const auto &unit : catalog.units) {
    if (unit.level || !local_prefix_unit_available(catalog,unit,gate) ||
        (local.present && local.present(local.context,unit.prefix))) continue;
    packet::isis::TlvCursor options(unit.options);
    const auto option=options.next();
    if (!option) return InterlevelCompositionStatus::invalid;
    packet::isis::ExtendedPrefixCursor entries(*option);
    auto prefix=entries.next();
    if (!prefix || entries.next() || !entries.valid() || prefix->down || prefix->prefix!=unit.prefix)
      return InterlevelCompositionStatus::invalid;
    auto &bytes=attributes_[0U];
    const auto normalized=normalize(prefix->prefix,prefix->sub_tlvs,bytes,generate_flags);
    if (normalized.status!=InterlevelAttributeStatus::applied)
      return normalized.status==InterlevelAttributeStatus::capacity ? InterlevelCompositionStatus::capacity :
          InterlevelCompositionStatus::invalid;
    prefix->sub_tlvs=std::span<const std::uint8_t>{bytes}.first(normalized.octets);
    prefix->sub_tlvs_present=!prefix->sub_tlvs.empty();
    const auto emitted=emit(workspace,*prefix,6U,key);
    if (emitted!=InterlevelCompositionStatus::applied) return emitted;
  }
  return InterlevelCompositionStatus::applied;
}

}
