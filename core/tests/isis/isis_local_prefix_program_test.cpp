// Local AF projections and canonical passive policy prepare exact root inputs.
// Tests own every borrowed extent and never introduce peer or topology state.
#include "router/isis_local_prefix_program.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
void require(bool value, std::source_location source = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS local prefix policy invariant at " + std::to_string(source.line()));
}
}
void isis_local_prefix_program_tests() {
  using Status = LocalPrefixProgramStatus;
  InstanceIntent intent;
  intent.admin_enabled = true; intent.ipv6_routing = ConfiguredIpv6Routing::native;
  InterfaceIntent edge; edge.name = "edge";
  InterfaceIntent system; system.name = "system"; system.passive = true;
  intent.interfaces = {edge, system};
  std::array<std::uint8_t, 3U> attributes{4U, 1U, 0U};
  std::array edge_prefixes{RootPrefix{*ip::parse_ip_prefix("192.0.2.0/24"), 20U, std::uint8_t{20U}},
      RootPrefix{*ip::parse_ip_prefix("2001:db8:12::/64"), 30U, {}, attributes, true}};
  const std::array system_prefixes{RootPrefix{*ip::parse_ip_prefix("192.0.2.1/32"), 0U, std::uint8_t{0U}}};
  std::array sources{LocalPrefixSource{"edge", {edge_prefixes, edge_prefixes}, true, false},
      LocalPrefixSource{"system", {system_prefixes, system_prefixes}, true, false}};
  const auto defaults = prepare_local_prefix_program(intent, sources, {3U, 3U});
  require(defaults.status == Status::prepared && defaults.levels[0U].size() == 3U && defaults.levels[1U].size() == 3U);
  require(defaults.levels[0U].back().attributes.data() == attributes.data() && defaults.levels[0U].back().external_ipv6);
  RootContentInput root;
  root.local = {1U, 2U, 3U, 4U, 5U, 6U}; root.flags = 3U;
  root.ipv4 = root.ipv6 = true; root.prefixes = defaults.levels[0U];
  const auto composed = prepare_root_content(root, 1465U, 2U);
  require(composed.status == RootContentStatus::prepared && !composed.records.empty());
  const auto copied = composed.records.front().options;
  attributes[2U] = 0x80U;
  require(composed.records.front().options == copied);
  attributes[2U] = 0U;
  intent.advertise_passive_only = true;
  auto selected = prepare_local_prefix_program(intent, sources, {1U, 1U});
  require(selected.status == Status::prepared && selected.levels[0U].size() == 1U && selected.levels[0U][0U].metric == 0U);
  intent.interfaces[0U].level[0U].present = true;
  intent.interfaces[0U].level[0U].passive = true;
  selected = prepare_local_prefix_program(intent, sources, {3U, 3U});
  require(selected.status == Status::prepared && selected.levels[0U].size() == 3U && selected.levels[1U].size() == 1U);
  intent.interfaces[0U].level[0U].passive = false;
  sources[0U].inherently_passive = true;
  require(prepare_local_prefix_program(intent, sources, {3U, 3U}).levels[1U].size() == 3U);
  sources[0U].inherently_passive = false;
  intent.advertise_passive_only = false;
  const auto exhausted = prepare_local_prefix_program(intent, sources, {1U, 1U});
  require(exhausted.status == Status::capacity && exhausted.levels[0U].empty() && exhausted.levels[1U].empty());
  sources[0U].available = false;
  require(prepare_local_prefix_program(intent, sources, {1U, 1U}).status == Status::prepared);
  sources[0U].available = true;
  intent.interfaces[0U].admin_enabled = false;
  require(prepare_local_prefix_program(intent, sources, {1U, 1U}).levels[0U].size() == 1U);
  intent.interfaces[0U].admin_enabled.reset();
  intent.levels = ConfiguredLevels::level2;
  selected = prepare_local_prefix_program(intent, sources, {3U, 3U});
  require(selected.levels[0U].empty() && selected.levels[1U].size() == 3U);
  intent.levels.reset(); intent.ipv4_routing = false;
  require(prepare_local_prefix_program(intent, sources, {1U, 1U}).levels[0U].size() == 1U);
  intent.ipv4_routing.reset(); intent.ipv6_routing = ConfiguredIpv6Routing::multi_topology;
  require(prepare_local_prefix_program(intent, sources, {3U, 3U}).status == Status::unsupported_topology);
  intent.ipv6_routing = ConfiguredIpv6Routing::native;
  auto invalid = sources; invalid[1U].interface_name = "edge";
  require(prepare_local_prefix_program(intent, invalid, {3U, 3U}).status == Status::invalid_context);
  invalid[1U].interface_name = "missing";
  require(prepare_local_prefix_program(intent, invalid, {3U, 3U}).status == Status::invalid_context);
  require(prepare_local_prefix_program(intent, std::span{sources}.first(1U), {3U, 3U}).status == Status::invalid_context);
  edge_prefixes[0U].prefix = system_prefixes[0U].prefix;
  const auto conflict = prepare_local_prefix_program(intent, sources, {3U, 3U});
  require(conflict.status == Status::conflicting_prefix && conflict.levels[0U].empty() && conflict.levels[1U].empty());
  edge_prefixes[0U] = system_prefixes[0U];
  selected = prepare_local_prefix_program(intent, sources, {2U, 2U});
  require(selected.status == Status::prepared && selected.levels[0U].size() == 2U);
  edge_prefixes[1U].prefix = *ip::parse_ip_prefix("fe80::/64");
  require(prepare_local_prefix_program(intent, sources, {3U, 3U}).status == Status::invalid_context);
  intent.admin_enabled = false;
  selected = prepare_local_prefix_program(intent, {}, {0U, 0U});
  require(selected.status == Status::inactive && selected.levels[0U].empty());
}
