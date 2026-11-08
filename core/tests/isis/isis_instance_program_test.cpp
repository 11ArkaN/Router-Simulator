// Local canonical intent prepares owned instance content and metric policy.
// Tests admit prepared values into actual owners; no remote state is injected.
#include "router/isis_instance_program.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location source = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS instance program invariant at " + std::to_string(source.line()));
}
}
void isis_instance_program_tests() {
  InstanceIntent intent; intent.admin_enabled = true; intent.ipv6_routing = ConfiguredIpv6Routing::native;
  intent.areas = {*parse_configured_area("49.0001")};
  intent.lsp_lifetime_seconds = std::uint16_t{1201U};
  InterfaceIntent edge; edge.name = "edge"; edge.type = ConfiguredInterfaceType::point_to_point;
  edge.level[0U].present = true; edge.level[0U].metric = 30U;
  intent.interfaces.push_back(edge);
  const std::array bindings{InstanceOriginInterface{"edge", 1U, {}, 1U, 8U, true, false}};
  const std::array prefixes{RootPrefix{*ip::parse_ip_prefix("192.0.2.0/24"), 20U, {}},
      RootPrefix{*ip::parse_ip_prefix("2001:db8::/64"), 25U, {}}};
  InstanceProgramContext context;
  context.identity.system_ipv4 = 0xc0000201U; context.maximum_areas = 3U; context.maximum_circuits = 1U;
  const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 128U, 1492U,
      1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
  context.levels = {level, level}; context.fragments = {1U, 1U};
  context.transmission = {1U, 5U, 10U, 1s, 10U, 1492U, 1U};
  context.minimum_generation_interval = 10ms; context.resource_retry = 100ms;
  context.random = 123U; context.interfaces = bindings; context.prefixes = {prefixes, prefixes};
  context.hostname = "R1";
  const auto before = intent;
  auto result = prepare_instance_program(intent, context);
  require(result.status == InstanceProgramStatus::prepared && result.program && intent == before);
  require(result.program->local == *resolve_configured_system_id(intent, context.identity));
  require(result.program->levels[0U]->maximum_age == 1201U && result.program->origination->content.levels[1U]->refresh_interval == 600500ms);
  require(result.program->origination->neighbors->size() == 1U &&
      result.program->origination->neighbors->front().levels[1U] == std::optional{P2pOriginMetric{30U, 30U}});
  require(result.program->origination->content.records.size() == 2U);
  // A real local LSP owner validates lifetime, timers and fully encoded root TLVs.
  auto owner = std::make_unique<LocalLspSet>(result.program->local, result.program->maximum_areas,
      UpdateInstanceSelector{packet::isis::InstanceFormat::standard, 0U},
      result.program->origination->content, RuntimeClock::time_point{100s});
  require(owner->contains(0U, result.program->origination->content.records.front().id));
  intent.admin_enabled = false;
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::inactive);
  intent = before; intent.instance = 1U;
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::unsupported_instance);
  intent = before; intent.ipv6_routing = ConfiguredIpv6Routing::multi_topology;
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::unsupported_topology);
  intent = before; intent.level[0U].present = true; intent.level[0U].lsp_mtu_octets = std::uint16_t{1500U};
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::unresolved_mtu);
  intent = before; intent.interfaces[0U].level[0U].metric = 64U;
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::unresolved_narrow_metric);
  intent.level[0U].present = intent.level[1U].present = true;
  intent.level[0U].wide_metrics_only = intent.level[1U].wide_metrics_only = true;
  result = prepare_instance_program(intent, context);
  require(result.status == InstanceProgramStatus::prepared && !result.program->origination->neighbors->front().levels[0U]->narrow);
  intent = before; intent.interfaces[0U].passive = true;
  result = prepare_instance_program(intent, context);
  require(result.status == InstanceProgramStatus::prepared && result.program->origination->neighbors->empty() &&
      result.program->origination->content.records.size() == 2U);
  intent = before; intent.ipv4_routing = false; intent.ipv6_routing = ConfiguredIpv6Routing::disabled;
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::prepared);
  intent = before; intent.levels = ConfiguredLevels::level2;
  intent.level[1U].present = true; intent.level[1U].preference = std::uint8_t{19U};
  intent.level[1U].external_preference = std::uint8_t{170U};
  context.routing[0U].emplace();
  context.routing[0U]->preferences = {P2pRouteFamilyProgram::Preference{15U, 160U}, P2pRouteFamilyProgram::Preference{18U, 165U}};
  result = prepare_instance_program(intent, context);
  require(result.status == InstanceProgramStatus::prepared && !result.program->levels[0U] && result.program->levels[1U] &&
      result.program->origination->content.records.size() == 1U && result.program->origination->content.records.front().flags == 3U &&
      result.program->routing[0U]->preferences[1U].internal == 19U && result.program->routing[0U]->preferences[1U].external == 170U);
  intent = before; intent.ipv4_routing = false;
  result = prepare_instance_program(intent, context);
  require(result.status == InstanceProgramStatus::prepared && !result.program->routing[0U]);
  intent = before; intent.interfaces[0U].type = ConfiguredInterfaceType::broadcast;
  result = prepare_instance_program(intent, context);
  require(result.status == InstanceProgramStatus::prepared && result.program->origination->neighbors->empty() &&
      result.program->origination->broadcast_neighbors->size() == 1U &&
      result.program->origination->broadcast_neighbors->front().circuit == 1U);
  intent = before; intent.interfaces[0U].type.reset();
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::unresolved_media);
  intent = before; context.fragments[0U] = 9U;
  require(prepare_instance_program(intent, context).status == InstanceProgramStatus::capacity);
}
