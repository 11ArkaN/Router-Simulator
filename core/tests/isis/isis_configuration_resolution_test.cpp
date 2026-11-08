// Configuration resolution tests distinguish absence, explicit defaults and
// level inheritance without constructing a live circuit or changing intent.
#include "router/isis_configuration_resolution.hpp"
#include <stdexcept>
namespace {
void require(bool value) { if (!value) throw std::runtime_error("IS-IS configuration resolution failed"); }
}
void isis_configuration_resolution_tests() {
  using namespace router::isis;
  InstanceIntent instance;
  InterfaceIntent interface; interface.name = "edge";
  const auto initial = resolve_interface(instance, interface);
  require(initial.admin_enabled && !initial.type);
  require(initial.csnp_interval_seconds == 10U && initial.retransmit_interval_seconds == 5U &&
      initial.lsp_pacing_interval_milliseconds == 100U);
  for (const auto &level : initial.level)
    require(level.enabled && !level.passive && level.metric == 10U &&
        level.hello_interval_seconds == 9U && level.hello_multiplier == 3U &&
        level.priority == 64U && level.nominal_holding_seconds == 27U);
  const auto root = resolve_instance_level(instance, 0U);
  require(root.enabled && !root.wide_metrics_only && root.lsp_mtu_octets == 1492U &&
      !root.preference && !root.external_preference);
  instance.level[0].present = true;
  instance.level[0].default_metric = 30U;
  instance.lsp_mtu_octets = std::uint16_t{1200U};
  instance.level[0].lsp_mtu_octets = std::uint16_t{1000U};
  require(resolve_instance_level(instance, 0U).lsp_mtu_octets == 1000U &&
      resolve_instance_level(instance, 1U).lsp_mtu_octets == 1492U);
  require(resolve_interface(instance, interface).level[0].metric == 30U &&
      resolve_interface(instance, interface).level[1].metric == 10U);
  interface.level[0].present = true;
  interface.level[0].metric = 10U;
  require(resolve_interface(instance, interface).level[0].metric == 10U);
  interface.level[0].metric.reset();
  require(resolve_interface(instance, interface).level[0].metric == 30U);
  interface.passive = true;
  interface.level[0].passive = false;
  require(resolve_interface(instance, interface).level[0].passive);
  interface.passive = false;
  interface.level[0].passive = true;
  require(resolve_interface(instance, interface).level[0].passive &&
      !resolve_interface(instance, interface).level[1].passive);
  instance.levels = ConfiguredLevels::level1;
  interface.levels = ConfiguredLevels::level2;
  require(!resolve_interface(instance, interface).level[0].enabled &&
      !resolve_interface(instance, interface).level[1].enabled);
  interface.level[0].hello_interval_seconds = std::uint16_t{20000U};
  interface.level[0].hello_multiplier = std::uint8_t{100U};
  const auto before = interface;
  require(resolve_interface(instance, interface).level[0].nominal_holding_seconds == 2000000U &&
      interface == before);
  InstanceIntent p2p_instance; p2p_instance.levels = ConfiguredLevels::level2;
  InterfaceIntent p2p_interface; p2p_interface.name = "p2p";
  p2p_interface.type = ConfiguredInterfaceType::point_to_point;
  p2p_interface.level[0U].present = p2p_interface.level[1U].present = true;
  p2p_interface.level[0U].hello_interval_seconds = std::uint16_t{7U};
  p2p_interface.level[0U].metric = 25U;
  p2p_interface.level[1U].hello_interval_seconds = std::uint16_t{20U};
  p2p_interface.level[1U].metric = 90U;
  const auto p2p = resolve_interface(p2p_instance, p2p_interface);
  require(p2p.point_to_point && p2p.point_to_point->enabled && !p2p.level[0U].enabled &&
      p2p.point_to_point->hello_interval_seconds == 7U &&
      p2p.point_to_point->nominal_holding_seconds == 21U && p2p.level[1U].metric == 25U);
  p2p_interface.level[0U].metric.reset();
  p2p_instance.level[1U].present = true;
  p2p_instance.level[1U].default_metric = 40U;
  const auto inherited_p2p = resolve_interface(p2p_instance, p2p_interface);
  require(inherited_p2p.level[1U].metric == 40U && inherited_p2p.level[0U].metric == 10U);
  p2p_interface.type = ConfiguredInterfaceType::broadcast;
  const auto lan = resolve_interface(p2p_instance, p2p_interface);
  require(!lan.point_to_point && lan.level[1U].hello_interval_seconds == 20U && lan.level[1U].metric == 90U);
  const auto ordinary_hello = resolve_hello_timing(initial.level[0U], false);
  const auto designated_hello = resolve_hello_timing(initial.level[0U], true);
  require(ordinary_hello.interval == std::chrono::seconds{9} && ordinary_hello.holding_seconds == 27U &&
      designated_hello.interval == std::chrono::seconds{3} && designated_hello.holding_seconds == 9U);
  auto short_hello = initial.level[0U];
  short_hello.hello_interval_seconds = 2U; short_hello.nominal_holding_seconds = 4U;
  const auto fractional_hello = resolve_hello_timing(short_hello, true);
  require(fractional_hello.interval == std::chrono::microseconds{666666} && fractional_hello.holding_seconds == 2U);
  const auto large_hello = resolve_hello_timing(resolve_interface(instance, interface).level[0U], true);
  require(large_hello.holding_seconds == 666667U);
  IdentityContext identity; identity.fallback_router_id = 0xff000000U;
  InstanceIntent disabled, active; active.admin_enabled = true;
  require(instance_transition(nullptr, nullptr, identity, identity) == InstanceTransition::unchanged);
  require(instance_transition(nullptr, &disabled, identity, identity) == InstanceTransition::inactive_edit);
  require(instance_transition(&disabled, &active, identity, identity) == InstanceTransition::activate);
  require(instance_transition(&active, &disabled, identity, identity) == InstanceTransition::deactivate);
  require(instance_transition(&active, nullptr, identity, identity) == InstanceTransition::deactivate);
  require(instance_transition(&active, &active, identity, identity) == InstanceTransition::unchanged);
  for (const auto edit : {0U, 1U, 2U, 3U}) {
    auto changed = active;
    if (edit == 0U) changed.lsp_lifetime_seconds = std::uint16_t{1100U};
    if (edit == 1U) changed.lsp_mtu_octets = std::uint16_t{1200U};
    if (edit == 2U) changed.router_id = 0x0a000001U;
    if (edit == 3U) changed.system_id = *parse_configured_system_id("0001.0002.0003");
    require(instance_transition(&active, &changed, identity, identity) == InstanceTransition::restart);
  }
  auto changed = active;
  changed.level[0U].present = true;
  changed.level[0U].lsp_mtu_octets = std::uint16_t{1200U};
  require(instance_transition(&active, &changed, identity, identity) == InstanceTransition::reconfigure);
  auto different_identity = identity; different_identity.system_ipv4 = 0x0a000001U;
  require(instance_transition(&active, &active, identity, different_identity) == InstanceTransition::restart);
  changed = active; changed.lsp_lifetime_seconds = static_cast<std::uint16_t>(configuration_profile::lsp_lifetime_seconds_default);
  require(instance_transition(&active, &changed, identity, identity) == InstanceTransition::reconfigure);

}
