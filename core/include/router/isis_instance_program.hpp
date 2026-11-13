// The configuration owner prepares one detached instance from local intent.
// This module borrows local projections only and owns no live protocol state.
#pragma once
#include "router/isis_interface_program.hpp"
#include "router/isis_root_content.hpp"
namespace router::isis {
struct InstanceOriginInterface {
  std::string_view name;
  std::uint64_t interface_id{};
  std::optional<ConfiguredInterfaceType> default_type;
  std::uint8_t circuit{};
  std::size_t maximum_neighbors{};
  // Physical carrier does not remove a configured origin binding. Actual Up
  // adjacencies alone contribute edges; resources survive link transitions.
  bool loopback{};
};
struct InstanceProgramContext {
  IdentityContext identity;
  // Explicit emulator resource and transport policy, supplied before admission.
  // No field declares a Nokia platform capacity or an inferred vendor default.
  std::uint8_t maximum_areas{};
  std::size_t maximum_circuits{};
  std::array<UpdateLevelConfiguration, 2U> levels;
  std::array<std::size_t, 2U> fragments{};
  UpdateTransmissionProgram transmission;
  std::chrono::microseconds minimum_generation_interval{};
  std::chrono::milliseconds resource_retry{};
  std::uint64_t random{};
  std::array<std::optional<P2pRouteFamilyProgram>, 2U> routing;
  // Explicit family-independent L2 graph budgets for automatic area attachment.
  std::optional<P2pDecisionProgram> hierarchy_decision;
  std::span<const InstanceOriginInterface> interfaces;
  std::span<const packet::Ipv4> ipv4_addresses;
  std::span<const packet::Ipv6> ipv6_addresses;
  // Local prefix/export ownership has already selected canonical, unique,
  // ordered prefixes per level. Narrow metrics are checked against level mode.
  std::array<std::span<const RootPrefix>, 2U> prefixes;
  std::string_view hostname;
};
enum class InstanceProgramStatus : std::uint8_t {
  prepared, inactive, invalid_context, unresolved_identity, unresolved_media,
  unresolved_mtu, unresolved_narrow_metric, unsupported_instance,
  unsupported_topology, invalid_content, capacity
};
struct InstanceProgramResult {
  InstanceProgramStatus status{InstanceProgramStatus::invalid_context};
  std::optional<UpdateInstanceProgram> program;
};
// Cold control-shard preparation; inputs must be validated canonical intent and
// local interface/export projections, never another router's state. May allocate
// and throw. Returned containers own every byte; borrowed spans expire on return.
// Failure/inactivity returns no program and changes no input. Policy resources
// and timers remain explicit. Unequal global/level MTUs and transitional metrics
// above the narrow range refuse pending a sourced platform projection. Default
// refresh is half the lifetime; subsecond precision survives odd lifetimes.
// This adapter prepares ordinary MT0 instance zero, without publishing anything.
[[nodiscard]] InstanceProgramResult prepare_instance_program(const InstanceIntent &,
    const InstanceProgramContext &);
}
