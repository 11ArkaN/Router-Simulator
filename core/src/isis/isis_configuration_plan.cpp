// Source-derived lifecycle selection joins canonical intent to local ownership.
// The configuration owner consumes this allocation-free plan before preparing
// any protocol or forwarding transaction. No running state is mutated here.
#include "router/isis_configuration_plan.hpp"
#include <algorithm>
#include <tuple>
namespace router::isis {
namespace {
auto nonadministrative(const InstanceIntent &value) noexcept {
  // Keep the shape check coupled to the complete canonical instance. A new
  // leaf must be classified rather than disappearing in a combined gate edit.
  [[maybe_unused]] const auto &[instance, admin_enabled, ipv4_routing, ipv6_routing, levels,
      system_id, router_id, lsp_lifetime_seconds, lsp_mtu_octets, level, areas, interfaces,
      spf_wait, lsp_wait, advertise_passive_only, strict_adjacency_check, ignore_attached_bit, suppress_attached_bit] = value;
  return std::tie(value.instance, value.ipv4_routing, value.ipv6_routing, value.levels,
      value.system_id, value.router_id, value.lsp_lifetime_seconds, value.lsp_mtu_octets,
      value.level, value.areas, value.interfaces, value.spf_wait, value.lsp_wait, value.advertise_passive_only, value.strict_adjacency_check, value.ignore_attached_bit, value.suppress_attached_bit);
}
const InstanceIntent *find(const RouterConfiguration &value, std::uint8_t key) noexcept {
  const auto entry = std::find_if(value.instances.begin(), value.instances.end(),
      [key](const auto &instance) { return instance.instance == key; });
  return entry == value.instances.end() ? nullptr : &*entry;
}
bool enabled(const InstanceIntent *value) noexcept {
  return value && value->admin_enabled.value_or(configuration_profile::instance_admin_enabled_default);
}
}
ConfigurationPlan plan_configuration(const RouterConfiguration &before, const RouterConfiguration &after,
    std::span<const InstanceOwnerState> owners, const IdentityContext &before_identity,
    const IdentityContext &after_identity) noexcept {
  using Change = ConfigurationChange;
  const auto fail = [](ConfigurationPlanStatus status) { ConfigurationPlan plan; plan.status = status; return plan; };
  if (validate_configuration(before) != ConfigurationError::none || validate_configuration(after) != ConfigurationError::none)
    return fail(ConfigurationPlanStatus::invalid_intent);
  for (std::size_t index{}; index < owners.size(); ++index)
    if (owners[index].instance > configuration_profile::instance_maximum ||
        (index && owners[index - 1U].instance >= owners[index].instance)) return fail(ConfigurationPlanStatus::invalid_ownership);
  ConfigurationPlan result; result.status = ConfigurationPlanStatus::prepared;
  for (std::size_t key{}; key < result.changes.size(); ++key) {
    const auto instance = static_cast<std::uint8_t>(key);
    const auto *old = find(before, instance), *next = find(after, instance);
    const auto owner = std::lower_bound(owners.begin(), owners.end(), instance,
        [](const auto &entry, auto id) { return entry.instance < id; });
    const bool owned = owner != owners.end() && owner->instance == instance;
    if (!old && !next && !owned) continue;
    if ((owned && (!old || owner->admin_enabled != enabled(old))) || (!owned && enabled(old)))
      return fail(ConfigurationPlanStatus::invalid_ownership);
    Change change{Change::unchanged};
    if (!owned) {
      if (enabled(next)) change = Change::create;
      else if ((old && !next) || (!old && next) || (old && next && *old != *next)) change = Change::intent_only;
    } else if (!next) change = Change::retire;
    else {
      const bool edited = nonadministrative(*old) != nonadministrative(*next) ||
          resolve_configured_system_id(*old, before_identity) != resolve_configured_system_id(*next, after_identity);
      if (enabled(old) != enabled(next))
        change = enabled(next) ? (edited ? Change::resume_and_reconfigure : Change::resume) :
            (edited ? Change::suspend_and_reconfigure : Change::suspend);
      else if (!enabled(next)) change = edited ? Change::reconfigure_disabled : Change::unchanged;
      else {
        const auto lifecycle = instance_transition(old, next, before_identity, after_identity);
        change = lifecycle == InstanceTransition::restart ? Change::restart :
            lifecycle == InstanceTransition::unchanged ? Change::unchanged : Change::reconfigure;
      }
    }
    result.changes[result.count++] = {instance, change};
  }
  return result;
}
}
