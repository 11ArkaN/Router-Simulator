// The serialized configuration owner plans instance lifecycle before admission.
// Inputs are local intent and immutable owner-presence values. No protocol,
// packet, timer, topology or mutable shared state is read or changed.
#pragma once
#include "router/isis_configuration_resolution.hpp"
#include <span>
namespace router::isis {
struct InstanceOwnerState {
  std::uint8_t instance{};
  bool admin_enabled{};
};
enum class ConfigurationChange : std::uint8_t {
  unchanged, intent_only, create, retire, suspend, resume, restart,
  reconfigure, reconfigure_disabled, suspend_and_reconfigure, resume_and_reconfigure
};
struct InstanceConfigurationChange {
  std::uint8_t instance{};
  ConfigurationChange change{ConfigurationChange::unchanged};
};
enum class ConfigurationPlanStatus : std::uint8_t { prepared, invalid_intent, invalid_ownership };
struct ConfigurationPlan {
  ConfigurationPlanStatus status{ConfigurationPlanStatus::invalid_intent};
  // This is the YANG key domain, not a supported active-process capacity.
  std::array<InstanceConfigurationChange, configuration_profile::instance_maximum + 1U> changes{};
  std::size_t count{};
};
// Preconditions: owner values are sorted unique keys of this router, and the
// caller's before intent describes their last accepted configuration. Plans
// retain only owned keys and actions. No allocation, clock or protocol calls.
// Success is sorted and covers every present intent/owner key, including
// unchanged entries. Missing enabled owners or gate disagreement refuse with
// no partial plan. Deletion retires a retained disabled owner too. Combined
// gate/configuration changes remain explicit and cannot become gate-only no-ops.
[[nodiscard]] ConfigurationPlan plan_configuration(const RouterConfiguration &before,
    const RouterConfiguration &after, std::span<const InstanceOwnerState> owners,
    const IdentityContext &before_identity, const IdentityContext &after_identity) noexcept;
}
