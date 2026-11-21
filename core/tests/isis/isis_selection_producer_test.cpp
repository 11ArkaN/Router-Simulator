// Real RIB commits exercise ordinal retention, coalescing and exact original
// candidate replay after cold filtering. The fixture owns every table and lease;
// no protocol database or foreign device supplies selection information.
#include "router/isis_selection_producer.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::routing;
using namespace router::lab::routing;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS selection producer invariant at " + std::to_string(where.line()));
}
}
void isis_selection_producer_tests() {
  const lab::DeviceHandle device{0U,1U};
  IsisSelectionProducer producer(device,4U);
  require(!producer.ready() && !producer.mark_dirty() && producer.can_change());
  std::array<DynamicInput,3U> candidates{};
  for (std::size_t index{}; index < candidates.size(); ++index) {
    auto &entry = candidates[index];
    entry.configured = entry.operational = true;
    entry.network = ipv4(10U,static_cast<std::uint8_t>(index + 1U),0U,0U);
    entry.next_hop = ipv4(192U,0U,2U,2U); entry.prefix_length = 24U;
    entry.preference = 15U; entry.metric = 17U; entry.source = RouteSource::isis;
    entry.ospf_path_type = OspfPathType::none; entry.isis_path_type = IsisPathType::level1_internal;
    entry.interface_id = 1U; entry.interface_generation = 7U;
  }
  const std::array connected{ConnectedInput{true,true,ipv4(192U,0U,2U,0U),0U,24U,false,1U,7U}};
  auto table4 = std::make_unique<RouteTable>();
  auto table6 = std::make_unique<Ipv6RouteTable>();
  (void)table4->rebuild(connected,{},candidates);
  require(table4->last_rebuild_valid());
  require(producer.can_replace(11U,{3U,0U}) && producer.replace(11U,{3U,0U}));
  IsisRouteSelection selected;
  auto project = [&](std::span<const DynamicInput> retained, std::uint64_t epoch) {
    return producer.project(epoch,{},retained,{},{},*table4,*table6,selected);
  };
  require(project(candidates,7U) == IsisSelectionStatus::applied && producer.ready());
  require(selected.identity.revision == 1U && selected.contains(0U,0U) && selected.contains(0U,1U) && selected.contains(0U,2U));
  require(producer.published(selected.identity) && !producer.ready() && !producer.published(selected.identity));
  const std::array statics{StaticInput{true,candidates[1U].network,candidates[1U].next_hop,24U,false}};
  (void)table4->rebuild(connected,statics,candidates);
  require(producer.mark_dirty() && project(candidates,8U) == IsisSelectionStatus::applied);
  require(selected.identity.publication == 11U && selected.identity.revision == 2U && !selected.contains(0U,1U));
  require(producer.published(selected.identity));
  const std::array<std::uint16_t,2U> keep{0U,2U};
  auto prepared = producer.prepare_retain(keep,{},candidates,{});
  auto superseded = producer.prepare_retain(keep,{},candidates,{});
  require(prepared && superseded && producer.ordinal(0U,1U) == 1U);
  const std::array retained{candidates[0U],candidates[2U]};
  (void)table4->rebuild(connected,{},retained);
  require(producer.commit_retain(*prepared) && !producer.commit_retain(*prepared) && !producer.commit_retain(*superseded));
  require(producer.ordinal(0U,1U) == 2U && !producer.ordinal(0U,2U));
  require(project(retained,9U) == IsisSelectionStatus::applied && selected.counts[0U] == 3U &&
      selected.contains(0U,0U) && !selected.contains(0U,1U) && selected.contains(0U,2U));
  require(producer.published(selected.identity));
  for (const auto invalid : {std::array<std::uint16_t,2U>{2U,0U},{0U,0U},{0U,3U}})
    require(!producer.prepare_retain(invalid,{},retained,{}));
  const std::array<std::uint16_t,1U> missing{1U};
  require(!producer.prepare_retain(missing,{},retained,{}));
  const auto image = producer.checkpoint();
  require(image.filtered && image.original_ipv4.size() == 3U && image.original_ipv4[1U] == candidates[1U]);
  IsisSelectionProducer restored(device,4U);
  require(restored.restore(image,retained,{}) && restored.publication() == 11U && restored.revision() == 3U);
  const auto refuses = [&](auto corrupt) {
    auto changed = image; corrupt(changed);
    require(!restored.restore(changed,retained,{}));
    const auto preserved = restored.checkpoint();
    require(preserved.ordinals == image.ordinals && preserved.original_ipv4 == image.original_ipv4 && preserved.revision == image.revision);
  };
  refuses([](auto &saved) { saved.ordinals[0U][1U] = 1U; });
  refuses([](auto &saved) { saved.original_ipv4[2U].interface_generation += 1U; });
  refuses([](auto &saved) { saved.filtered = false; });
  refuses([](auto &saved) { saved.capacity += 1U; });
  refuses([](auto &saved) { saved.device.generation += 1U; });
  auto exhausted = image; exhausted.revision = UINT64_MAX; exhausted.dirty = true;
  require(!restored.restore(exhausted,retained,{}));
  exhausted.dirty = false;
  require(restored.restore(exhausted,retained,{}) && !restored.can_change() && !restored.mark_dirty() &&
      !restored.can_replace(12U,{2U,0U}) && !restored.prepare_retain({}, {}, retained,{}));
  require(!producer.can_replace(11U,{3U,0U}) && !producer.can_replace(12U,{5U,0U}));
  auto withdrawal = producer.prepare_retain({}, {}, retained,{});
  require(withdrawal != nullptr);
  (void)table4->rebuild(connected,{});
  require(producer.commit_retain(*withdrawal) && project({},10U) == IsisSelectionStatus::applied && selected.counts[0U] == 3U &&
      !selected.contains(0U,0U) && !selected.contains(0U,2U));
  require(producer.published(selected.identity) && producer.replace(12U,{0U,0U}));
  require(project({},11U) == IsisSelectionStatus::applied && selected.counts[0U] == 0U);
  const auto fresh = producer.checkpoint();
  require(!fresh.filtered && fresh.original_ipv4.empty() && fresh.original_ipv6.empty());
  std::array<Ipv6DynamicInput,2U> six{};
  six[0U].configured = six[0U].operational = true;
  six[0U].network = *ip::parse_ipv6("2001:db8:19::");
  six[0U].next_hop = *ip::parse_ipv6("fe80::2");
  six[0U].prefix_length = 64U; six[0U].preference = 15U; six[0U].metric = 17U;
  six[0U].source = RouteSource::isis; six[0U].ospf_path_type = OspfPathType::none;
  six[0U].isis_path_type = IsisPathType::level1_internal;
  six[0U].interface_id = 1U; six[0U].interface_generation = 7U;
  six[1U] = six[0U]; six[1U].next_hop = *ip::parse_ipv6("fe80::3");
  six[1U].interface_id = 2U; six[1U].physical_port_ordinal = 1U;
  IsisSelectionProducer dual(device,4U);
  require(dual.replace(1U,{0U,2U}));
  (void)table6->rebuild({},{},{},six,2U);
  require(table6->last_rebuild_valid());
  const std::array<std::uint16_t,1U> second_hop{1U};
  const auto filter6 = dual.prepare_retain({},second_hop,{},six);
  require(filter6 != nullptr);
  const auto retained6 = std::span{six}.subspan(1U);
  (void)table6->rebuild({},{},{},retained6);
  require(dual.commit_retain(*filter6));
  require(dual.project(13U,{},{},{},retained6,*table4,*table6,selected) == IsisSelectionStatus::applied &&
      selected.counts[1U] == 2U && !selected.contains(1U,0U) && selected.contains(1U,1U));
  require(dual.published(selected.identity));
  const auto saved6 = dual.checkpoint();
  require(saved6.original_ipv4.empty() && saved6.original_ipv6.size() == 2U);
  IsisSelectionProducer restored6(device,4U);
  require(restored6.restore(saved6,{},retained6));
  auto wrong6 = saved6; ++wrong6.original_ipv6[1U].interface_generation;
  require(!restored6.restore(wrong6,{},retained6));

}
