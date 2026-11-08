// One configuration owner resolves optional intent into release values. The
// protocol runtime consumes this projection and cannot write canonical intent.
#include "router/isis_configuration_resolution.hpp"
namespace router::isis {
ResolvedInstanceLevel resolve_instance_level(const InstanceIntent &instance, std::size_t index) noexcept {
  namespace defaults = configuration_profile;
  const auto &level = instance.level[index];
  return {static_cast<bool>(static_cast<std::uint8_t>(instance.levels.value_or(ConfiguredLevels::both)) & (1U << index)),
      level.wide_metrics_only.value_or(defaults::wide_metrics_only_default),
      level.default_metric.value_or(defaults::default_metric_default),
      level.lsp_mtu_octets.value_or(defaults::level_lsp_mtu_octets_default),
      level.preference, level.external_preference};
}
ResolvedInterface resolve_interface(const InstanceIntent &instance, const InterfaceIntent &interface,
    std::optional<ConfiguredInterfaceType> default_type) noexcept {
  namespace defaults = configuration_profile;
  ResolvedInterface resolved;
  resolved.admin_enabled = interface.admin_enabled.value_or(defaults::interface_admin_enabled_default);
  resolved.type = interface.type ? interface.type : default_type;
  resolved.csnp_interval_seconds = interface.csnp_interval_seconds.value_or(defaults::csnp_interval_seconds_default);
  resolved.retransmit_interval_seconds = interface.retransmit_interval_seconds.value_or(defaults::retransmit_interval_seconds_default);
  resolved.lsp_pacing_interval_milliseconds = interface.lsp_pacing_interval_milliseconds.value_or(defaults::lsp_pacing_interval_milliseconds_default);
  const auto mask = configured_level_mask(instance, interface);
  for (std::size_t index{}; index < resolved.level.size(); ++index) {
    const auto &configured = interface.level[
        resolved.type == ConfiguredInterfaceType::point_to_point ? 0U : index];
    auto &level = resolved.level[index];
    level.enabled = static_cast<bool>(mask & (1U << index));
    level.passive = interface.passive.value_or(defaults::interface_passive_default) ||
        configured.passive.value_or(defaults::interface_level_passive_default);
    level.metric = configured.metric.value_or(resolve_instance_level(instance, index).default_metric);
    level.hello_interval_seconds = configured.hello_interval_seconds.value_or(defaults::hello_interval_seconds_default);
    level.hello_multiplier = configured.hello_multiplier.value_or(defaults::hello_multiplier_default);
    level.priority = configured.priority.value_or(defaults::priority_default);
    level.nominal_holding_seconds = std::uint32_t{level.hello_interval_seconds} * level.hello_multiplier;
  }
  if (resolved.type == ConfiguredInterfaceType::point_to_point) {
    const auto &hello = resolved.level[0U];
    resolved.point_to_point = ResolvedP2pHello{mask != 0U, hello.hello_interval_seconds,
        hello.hello_multiplier, hello.nominal_holding_seconds};
  }
  return resolved;
}
ResolvedHelloTiming resolve_hello_timing(const ResolvedInterfaceLevel &level, bool designated) noexcept {
  const auto divisor = designated ? 3U : 1U;
  return {std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::seconds{level.hello_interval_seconds}) / divisor,
      (level.nominal_holding_seconds + divisor - 1U) / divisor};
}
InstanceTransition instance_transition(const InstanceIntent *before,
    const InstanceIntent *after, const IdentityContext &before_identity,
    const IdentityContext &after_identity) noexcept {
  namespace defaults = configuration_profile;
  // Fail compilation if source lifecycle facts stop covering these bindings.
  constexpr auto requires_restart = [](std::string_view path) {
    for (const auto candidate : defaults::restart_paths)
      if (candidate == path) return true;
    return false;
  };
  static_assert(requires_restart("/configure/router/isis/lsp-lifetime") &&
      requires_restart("/configure/router/isis/lsp-mtu-size") &&
      requires_restart("/configure/router/isis/system-id") &&
      requires_restart("/configure/router/isis/router-id"));
  const bool was_active = before && before->admin_enabled.value_or(defaults::instance_admin_enabled_default);
  const bool active = after && after->admin_enabled.value_or(defaults::instance_admin_enabled_default);
  if (!was_active && active) return InstanceTransition::activate;
  if (was_active && !active) return InstanceTransition::deactivate;
  if (!was_active) {
    if ((!before && !after) || (before && after && *before == *after))
      return InstanceTransition::unchanged;
    return InstanceTransition::inactive_edit;
  }
  const auto old_id = resolve_configured_system_id(*before, before_identity);
  const auto new_id = resolve_configured_system_id(*after, after_identity);
  if (old_id != new_id || before->router_id != after->router_id ||
      before->lsp_lifetime_seconds.value_or(defaults::lsp_lifetime_seconds_default) !=
          after->lsp_lifetime_seconds.value_or(defaults::lsp_lifetime_seconds_default) ||
      before->lsp_mtu_octets.value_or(defaults::lsp_mtu_octets_default) !=
          after->lsp_mtu_octets.value_or(defaults::lsp_mtu_octets_default))
    return InstanceTransition::restart;
  return *before == *after ? InstanceTransition::unchanged : InstanceTransition::reconfigure;
}

}
