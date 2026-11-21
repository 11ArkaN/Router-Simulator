// Real primary RIB selections drive copied IS-IS feedback. Fixtures own all
// candidates and tables; no protocol database or remote topology is consulted.
#include "router/isis_route_selection.hpp"
#include "router/isis_selection_channel.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::lab::routing;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS selection invariant at " + std::to_string(location.line()));
}
DynamicInput candidate(std::uint32_t network) {
  DynamicInput result{};
  result.configured = result.operational = true;
  result.network = network; result.next_hop = ipv4(192,0,2,2);
  result.prefix_length = 24U; result.preference = 15U; result.metric = 10U;
  result.source = RouteSource::isis; result.ospf_path_type = OspfPathType::none;
  result.isis_path_type = IsisPathType::level1_internal;
  result.interface_id = 1U; result.interface_generation = 7U;
  return result;
}
}
void isis_route_selection_tests() {
  namespace feedback = router::routing;
  auto table4 = std::make_unique<RouteTable>();
  auto table6 = std::make_unique<Ipv6RouteTable>();
  std::array<DynamicInput,8U> candidates{};
  candidates[0] = candidate(ipv4(203,0,113,0));
  candidates[1] = candidate(ipv4(198,51,100,0));
  candidates[1].isis_path_type = IsisPathType::level1_external;
  candidates[1].isis_rank = 3U; candidates[1].preference = 160U;
  candidates[1].metric = 20U; candidates[1].internal_metric = 4U;
  candidates[2] = candidates[1]; candidates[2].internal_metric = 8U;
  candidates[3] = candidate(ipv4(10,0,0,0));
  candidates[4] = candidates[3]; candidates[4].next_hop = ipv4(192,0,2,3);
  candidates[4].interface_id = 2U; candidates[4].port_ordinal = 1U;
  candidates[5] = candidates[3]; candidates[5].loop_free_alternate = true;
  candidates[5].next_hop = ipv4(192,0,2,4);
  candidates[5].interface_id = 3U; candidates[5].port_ordinal = 2U;
  candidates[6] = candidates[3]; candidates[6].isis_path_type = IsisPathType::level2_internal;
  candidates[6].isis_rank = 1U; candidates[6].metric = 1U; candidates[6].preference = 18U;
  candidates[7] = candidate(ipv4(192,0,3,0));
  auto ospf = candidates[0]; ospf.source = RouteSource::ospf;
  ospf.ospf_path_type = OspfPathType::intra_area;
  ospf.isis_path_type = IsisPathType::none; ospf.preference = 10U;
  const std::array competing{ospf};
  const std::array connected{ConnectedInput{true,true,ipv4(192,0,2,0),0U,24U,false,1U,7U}};
  std::array<Ipv6DynamicInput,2U> six{};
  six[0].configured = six[0].operational = true;
  six[0].network = *ip::parse_ipv6("2001:db8:9::");
  six[0].next_hop = *ip::parse_ipv6("fe80::2");
  six[0].interface_id = 1U; six[0].interface_generation = 7U;
  six[0].prefix_length = 64U; six[0].preference = 15U; six[0].metric = 20U;
  six[0].source = RouteSource::isis; six[0].ospf_path_type = OspfPathType::none;
  six[0].isis_path_type = IsisPathType::level1_internal;
  six[1] = six[0]; six[1].next_hop = *ip::parse_ipv6("fe80::3");
  six[1].interface_id = 2U; six[1].physical_port_ordinal = 1U;
  (void)table4->rebuild(connected,{},competing,2U,candidates);
  (void)table6->rebuild({},{},{},six,2U);
  require(table4->last_rebuild_valid() && table6->last_rebuild_valid());
  const feedback::IsisSelectionIdentity identity{{0U,1U},11U,7U,1U};
  feedback::IsisSelectionInput<DynamicInput> input4{competing,candidates,{},8U};
  feedback::IsisSelectionInput<Ipv6DynamicInput> input6{{},six,{},2U};
  feedback::IsisRouteSelection output;
  auto project = [&] { return feedback::project_isis_route_selection(identity,input4,input6,*table4,*table6,output); };
  require(project() == feedback::IsisSelectionStatus::applied);
  require(feedback::valid_isis_route_selection(output));
  for (std::size_t index{}; index < 8U; ++index)
    require(output.contains(0U,index) == (index == 1U || index == 3U || index == 4U || index == 7U));
  require(output.contains(1U,0U) && output.contains(1U,1U));
  const std::array statics{StaticInput{true,ipv4(192,0,3,0),ipv4(192,0,2,2),24U,false}};
  (void)table4->rebuild(connected,statics,competing,2U,candidates);
  (void)table6->rebuild({},{},{},six,1U);
  require(project() == feedback::IsisSelectionStatus::applied && !output.contains(0U,7U));
  require(output.contains(1U,0U) != output.contains(1U,1U));
  const std::array retained{candidates[1],candidates[3]};
  std::array<std::uint16_t,2U> ordinals{1U,3U};
  (void)table4->rebuild(connected,{},competing,2U,retained);
  input4 = {competing,retained,ordinals,8U};
  require(project() == feedback::IsisSelectionStatus::applied);
  require(output.contains(0U,1U) && output.contains(0U,3U) && !output.contains(0U,0U));
  const auto saved = output;
  for (const auto invalid : {std::array<std::uint16_t,2U>{3U,1U}, {1U,1U}, {1U,8U}}) {
    ordinals = invalid;
    require(project() == feedback::IsisSelectionStatus::invalid && output == saved);
  }
  input4 = {{},{},{},8U};
  require(project() == feedback::IsisSelectionStatus::applied && !output.contains(0U,1U));
  const std::array last{candidates[3]};
  const std::array<std::uint16_t,1U> last_ordinal{static_cast<std::uint16_t>(device_catalog::maximum_dynamic_routes_per_router - 1U)};
  (void)table4->rebuild(connected,{},last);
  input4 = {{},last,last_ordinal,device_catalog::maximum_dynamic_routes_per_router};
  require(project() == feedback::IsisSelectionStatus::applied);
  require(output.contains(0U,last_ordinal[0]) && !output.contains(0U,device_catalog::maximum_dynamic_routes_per_router));
  require(feedback::valid_isis_route_selection(output));
  input4.original_count += 1U;
  const auto boundary = output;
  require(project() == feedback::IsisSelectionStatus::capacity && output == boundary);
  auto invalid = output; invalid.version = 2U;
  require(!feedback::valid_isis_route_selection(invalid));
  invalid = output; invalid.identity.configuration_epoch = 0U;
  require(!feedback::valid_isis_route_selection(invalid));
  invalid = output; invalid.selected[1U][0U] |= UINT64_C(1) << 2U;
  require(!feedback::valid_isis_route_selection(invalid));
  auto channel = std::make_unique<feedback::IsisSelectionChannel>();
  const auto first = channel->acquire();
  require(first.has_value());
  *first->value = boundary;
  require(channel->publish(first->handle));
  const auto second = channel->acquire();
  require(second.has_value());
  *second->value = boundary;
  ++second->value->identity.revision;
  second->value->selected = {};
  require(channel->publish(second->handle) && !channel->acquire());
  const auto borrowed = channel->receive();
  require(borrowed && *borrowed->value == boundary);
  const auto image = channel->checkpoint_quiescent(71U);
  auto restored = std::make_unique<feedback::IsisSelectionChannel>();
  const auto prepared = feedback::IsisSelectionChannel::prepare_restore(image,71U);
  require(prepared && restored->commit_quiescent(*prepared,71U));
  require(!restored->acquire());
  const auto copied = *restored->borrowed_value_quiescent(borrowed->handle);
  require(copied == boundary && restored->release(borrowed->handle));
  const auto withdrawal = restored->receive();
  require(withdrawal && withdrawal->value->identity.revision == identity.revision + 1U &&
      !withdrawal->value->contains(0U,last_ordinal[0]));
  require(restored->release(withdrawal->handle));
  const auto credit = restored->acquire();
  require(credit && !credit->value->identity.publication && restored->cancel(credit->handle));

}
