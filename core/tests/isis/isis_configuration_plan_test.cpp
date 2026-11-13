// Lifecycle plans distinguish actual local owners from merely configured keys.
// Tests own all canonical values; no protocol state or remote data is injected.
#include "router/isis_configuration_plan.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router::isis;
void require(bool value, std::source_location source = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS configuration plan invariant at " + std::to_string(source.line()));
}
}
void isis_configuration_plan_tests() {
  using Change = ConfigurationChange;
  using Status = ConfigurationPlanStatus;
  const IdentityContext identity{{}, 0xc0000201U, 0xff000000U};
  RouterConfiguration before, after;
  auto plan = plan_configuration(before, after, {}, identity, identity);
  require(plan.status == Status::prepared && !plan.count);
  after.instances.emplace_back();
  const auto select = [&](std::span<const InstanceOwnerState> owners) {
    const auto result = plan_configuration(before, after, owners, identity, identity);
    require(result.status == Status::prepared && result.count == 1U && result.changes[0U].instance == 0U);
    return result.changes[0U].change;
  };
  require(select({}) == Change::intent_only);
  before = after;
  require(select({}) == Change::unchanged);
  after.instances[0U].admin_enabled = true;
  require(select({}) == Change::create);
  before = after;
  const std::array active{InstanceOwnerState{0U, true}};
  const std::array suspended{InstanceOwnerState{0U, false}};
  require(select(active) == Change::unchanged);
  after.instances[0U].lsp_lifetime_seconds = std::uint16_t{1200U};
  require(select(active) == Change::reconfigure);
  after.instances[0U].lsp_lifetime_seconds = std::uint16_t{1201U};
  require(select(active) == Change::restart);
  after = before; after.instances[0U].system_id = *parse_configured_system_id("0000.0000.0002");
  require(select(active) == Change::restart);
  after = before; after.instances[0U].advertise_passive_only = true;
  require(select(active) == Change::reconfigure);
  after.instances[0U].admin_enabled = false;
  require(select(active) == Change::suspend_and_reconfigure);
  after = before; after.instances[0U].admin_enabled = false;
  require(select(active) == Change::suspend);
  before = after;
  require(select(suspended) == Change::unchanged);
  after.instances[0U].admin_enabled.reset();
  require(select(suspended) == Change::unchanged);
  after.instances[0U].advertise_passive_only = true;
  require(select(suspended) == Change::reconfigure_disabled);
  after.instances[0U].admin_enabled = true;
  require(select(suspended) == Change::resume_and_reconfigure);
  after = before; after.instances[0U].admin_enabled = true;
  require(select(suspended) == Change::resume);
  after.instances.clear();
  require(select(suspended) == Change::retire);
  require(select({}) == Change::intent_only);
  after = before;
  IdentityContext moved = identity; moved.system_ipv4 = 0xc0000202U;
  plan = plan_configuration(before, after, suspended, identity, moved);
  require(plan.status == Status::prepared && plan.changes[0U].change == Change::reconfigure_disabled);
  after.instances[0U].admin_enabled = true;
  plan = plan_configuration(before, after, suspended, identity, moved);
  require(plan.status == Status::prepared && plan.changes[0U].change == Change::resume_and_reconfigure);
  before = after;
  require(plan_configuration(before, after, {}, identity, identity).status == Status::invalid_ownership);
  require(plan_configuration(before, after, suspended, identity, identity).status == Status::invalid_ownership);
  const std::array duplicate{active[0U], active[0U]};
  require(plan_configuration(before, after, duplicate, identity, identity).status == Status::invalid_ownership);
  const std::array foreign{InstanceOwnerState{1U, true}};
  plan = plan_configuration(before, after, foreign, identity, identity);
  require(plan.status == Status::invalid_ownership && !plan.count);
  after.instances[0U].instance = 128U;
  require(plan_configuration(before, after, active, identity, identity).status == Status::invalid_intent);
  before.instances[0U].admin_enabled = false; after = before;
  const std::array orphan{InstanceOwnerState{2U, false}};
  const auto refused = plan_configuration(before, after, orphan, identity, identity);
  require(refused.status == Status::invalid_ownership && !refused.count);
  after.instances[0U].instance = 127U;
  plan = plan_configuration(before, after, {}, identity, identity);
  require(plan.status == Status::prepared && plan.count == 2U &&
      plan.changes[0U].instance == 0U && plan.changes[1U].instance == 127U);
}
