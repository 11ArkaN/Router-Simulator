// This control-local fixture owns copied banks, selected certificates and
// unpublished fragment workspaces. Capacity distinguishes deduplicated output
// and explicit flag policy without publishing any fabricated peer state.
#include "router/isis_interlevel_composition.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
void require(bool value,std::source_location at=std::source_location::current()) {
  if (!value) throw std::runtime_error("Interlevel composition invariant at "+std::to_string(at.line()));
}
void selected(InterlevelExportState &state,std::span<const std::uint8_t> a,std::span<const std::uint8_t> b) {
  require(state.begin_routes(1U)); auto *bank=state.building_templates();
  PrefixAdvertisement prefix; prefix.origin={1U,2U,3U,4U,5U,6U,0U,0U};
  prefix.prefix=*ip::parse_ip_prefix("192.0.2.1/32"); prefix.level=1U; prefix.metric=10U;
  for (const auto attributes : {a,b}) {
    prefix.attributes_size=static_cast<std::uint16_t>(attributes.size());
    const auto result=bank->append(prefix,{0U,17U,0U},{0U,1U,1U},attributes);
    require(result.status==InterlevelTemplateStatus::applied &&
        bank->map_candidate(0U,result.index)==InterlevelTemplateStatus::applied);
    ++prefix.origin[5U];
  }
  require(state.route_published(1U));
  routing::IsisRouteSelection value; value.identity={{0U,1U},1U,1U,1U};
  value.counts={2U,0U}; value.selected[0U][0U]=3U;
  const std::array owners{InterlevelEligibility{1U,1U,1U}};
  require(state.accept(value,1U,owners).status==InterlevelApplyStatus::applied);
}
}
void isis_interlevel_composition_tests() {
  const InterlevelTemplateBudget budget{4U,64U,4U};
  const auto bounds=interlevel_composition_bounds(budget);
  require(bounds && bounds->attributes==76U && bounds->parts==5U && bounds->wire_octets==201U);
  require(!interlevel_composition_bounds({0U,64U,4U}));
  InterlevelComposition composer(budget);
  InterlevelExportState empty_attributes({0U,1U},budget);
  selected(empty_attributes,{},{});
  const std::array<std::uint8_t,1U> slot{0U};
  OriginFragmentWorkspace without_flags(2U,1U,11U,257U);
  require(composer.append(without_flags,empty_attributes,0U,false)==InterlevelCompositionStatus::applied &&
      without_flags.validate(slot,11U)==LocalContentResult::unchanged);
  OriginFragmentWorkspace flags(2U,1U,15U,257U);
  require(composer.append(flags,empty_attributes,0U,true)==InterlevelCompositionStatus::applied &&
      flags.validate(slot,15U)==LocalContentResult::unchanged);
  const std::array<std::uint8_t,3U> node{4U,1U,0x20U}, external{4U,1U,0x80U};
  InterlevelExportState known({0U,1U},budget); selected(known,node,node);
  OriginFragmentWorkspace preserve(2U,1U,15U,257U);
  require(composer.append(preserve,known,0U,false)==InterlevelCompositionStatus::applied &&
      preserve.validate(slot,15U)==LocalContentResult::unchanged);
  InterlevelExportState conflict({0U,1U},budget); selected(conflict,node,external);
  OriginFragmentWorkspace refused(2U,1U,100U,257U);
  require(composer.append(refused,conflict,0U,true)==InterlevelCompositionStatus::conflicting_attributes);
  LocalPrefixCatalogProgram catalog;
  catalog.interfaces.push_back({1U,{},true});
  std::array<std::uint8_t,32U> local_bytes{};
  packet::isis::TlvWriter local_writer(local_bytes);
  const auto local_prefix=*ip::parse_ip_prefix("198.51.100.1/32");
  require(encode_root_prefix(local_writer,{local_prefix,19U,{}}));
  catalog.units.push_back({0U,local_prefix,{local_writer.bytes().begin(),local_writer.bytes().end()},{1U}});
  require(valid_local_prefix_catalog(catalog));
  OriginFragmentWorkspace local_source(1U,1U,11U,257U);
  require(composer.append_local(local_source,catalog,false)==InterlevelCompositionStatus::applied &&
      local_source.validate(slot,11U)==LocalContentResult::unchanged);
  catalog.interfaces[0U].available=false;
  OriginFragmentWorkspace unavailable(1U,1U,11U,1U);
  require(!local_prefix_unit_available(catalog,catalog.units[0U]) &&
      composer.append_local(unavailable,catalog,false)==InterlevelCompositionStatus::applied);
  catalog.interfaces[0U].available=true;
  const auto deny=[](const void *,std::uint64_t,const ip::IpPrefix &) noexcept { return false; };
  OriginFragmentWorkspace unassigned(1U,1U,11U,1U);
  require(!local_prefix_unit_available(catalog,catalog.units[0U],{nullptr,deny}) &&
      composer.append_local(unassigned,catalog,false,{nullptr,deny})==InterlevelCompositionStatus::applied);
  const auto present=[](const void *,const ip::IpPrefix &) noexcept { return true; };
  OriginFragmentWorkspace local(1U,1U,11U,257U);
  require(composer.append(local,known,0U,true,{nullptr,present})==InterlevelCompositionStatus::applied);
}
