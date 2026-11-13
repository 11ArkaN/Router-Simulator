// Local media, identity and YANG values become an owned Hello circuit program.
// The datastore control owner retains publication authority and all AF policy.
#include "router/isis_interface_program.hpp"
#include <algorithm>
#include <limits>
namespace router::isis {
InterfaceUpdateResult prepare_interface_update_program(const ResolvedInterface &interface,
    const InterfaceUpdateContext &context) noexcept {
  using Status = InterfaceUpdateStatus;
  if (!interface.type) return {Status::unresolved_media, {}};
  const bool broadcast = *interface.type == ConfiguredInterfaceType::broadcast;
  if ((*interface.type != ConfiguredInterfaceType::point_to_point && !broadcast) ||
      !context.partial_seconds || !context.transit_seconds || !interface.retransmit_interval_seconds ||
      !interface.csnp_interval_seconds || context.maximum_pdu_octets < packet::isis::csnp_header_octets ||
      context.maximum_pdu_octets > packet::maximum_frame_octets - packet::ethernet_header_octets - packet::llc_ui_header_octets ||
      (broadcast && (context.csnp_separation.count() <= 0 || context.csnp_separation > std::chrono::milliseconds{65535})))
    return {Status::invalid_context, {}};
  const auto interval = interface.lsp_pacing_interval_milliseconds;
  const auto period = interval < 100U ? 100U : 1000U;
  if (interval && period % interval) return {Status::unresolved_pacing, {}};
  UpdateTransmissionProgram output{context.partial_seconds, interface.retransmit_interval_seconds,
      interface.csnp_interval_seconds, std::chrono::milliseconds{period}, interval ? period / interval : 0U,
      context.maximum_pdu_octets, context.transit_seconds};
  if (broadcast) output.broadcast = BroadcastTransmissionProgram{
      std::chrono::milliseconds{interval}, context.csnp_separation};
  return {Status::prepared, output};
}
InterfaceProgramResult prepare_interface_program(const InstanceIntent &instance,
    const InterfaceIntent &interface, const InterfaceProgramContext &context) {
  namespace defaults = configuration_profile;
  const auto resolved = resolve_interface(instance, interface, context.default_type);
  if (!instance.admin_enabled.value_or(defaults::instance_admin_enabled_default) ||
      !resolved.admin_enabled || context.loopback || instance.areas.empty())
    return {InterfaceProgramStatus::inactive, {}};
  std::uint8_t mask{};
  for (std::size_t level{}; level < 2U; ++level)
    if (resolved.level[level].enabled && !resolved.level[level].passive) mask |= static_cast<std::uint8_t>(1U << level);
  if (!mask) return {InterfaceProgramStatus::inactive, {}};
  if (instance.instance) return {InterfaceProgramStatus::unsupported_instance, {}};
  if (instance.ipv6_routing == ConfiguredIpv6Routing::multi_topology)
    return {InterfaceProgramStatus::unsupported_topology, {}};
  if (!resolved.type) return {InterfaceProgramStatus::unresolved_media, {}};
  const auto local = resolve_configured_system_id(instance, context.system_identity);
  if (!local) return {InterfaceProgramStatus::unresolved_identity, {}};
  if (context.interface_name != interface.name || !context.identity.device.generation ||
      context.identity.device.index >= device_catalog::maximum_routers || !context.identity.interface_id ||
      !context.identity.configuration_generation || context.identity.instance != instance.instance ||
      context.identity.physical_port_ordinal >= device_catalog::maximum_ports_per_router ||
      !context.random || !context.maximum_areas || instance.areas.size() > context.maximum_areas ||
      !context.maximum_pdu_octets || !context.peer_attribute_octets ||
      !context.destinations.valid() || (context.mac[0U] & 1U) ||
      std::all_of(context.mac.begin(), context.mac.end(), [](auto value) { return value == 0U; }))
    return {InterfaceProgramStatus::invalid_context, {}};
  const auto timing_fits = [](const auto &timing) {
    return timing.holding_seconds <= std::numeric_limits<std::uint16_t>::max();
  };
  const auto common = [&] (CircuitHelloConfiguration &hello, std::size_t level) {
    hello.mac = context.mac; hello.areas = instance.areas;
    hello.protocols.assign(context.protocols.begin(), context.protocols.end());
    hello.ipv4_addresses.assign(context.ipv4_addresses.begin(), context.ipv4_addresses.end());
    hello.ipv6_addresses.assign(context.ipv6_addresses.begin(), context.ipv6_addresses.end());
    hello.ipv6_addresses_ready = context.ipv6_addresses_ready;
    hello.hello_destination = context.destinations.hello;
    hello.update_destinations = context.destinations.levels;
    hello.maximum_area_addresses = context.maximum_areas;
    hello.maximum_pdu_octets = context.maximum_pdu_octets;
    hello.peer_attribute_octets = context.peer_attribute_octets;
    hello.padding = context.padding;
    hello.strict_adjacency_check = instance.strict_adjacency_check.value_or(context.strict_adjacency_check);
    const auto timing = resolve_hello_timing(resolved.level[level], false);
    hello.hello_interval = timing.interval;
    hello.holding_seconds = static_cast<std::uint16_t>(timing.holding_seconds);
  };
  CircuitDefinition output;
  output.carrier = context.operational;
  output.identity = context.identity; output.random_state = context.random;
  const auto levels = static_cast<Levels>(mask);
  if (*resolved.type == ConfiguredInterfaceType::point_to_point) {
    const auto timing = resolve_hello_timing(resolved.level[0U], false);
    if (!timing_fits(timing)) return {InterfaceProgramStatus::unrepresentable_holding, {}};
    if (!context.extended_circuit) return {InterfaceProgramStatus::invalid_context, {}};
    common(output.configuration, 0U);
    output.configuration.local = {*local, context.extended_circuit, context.local_circuit,
        levels, !context.physical_point_to_point};
    output.configuration.physical_point_to_point = context.physical_point_to_point;
  } else {
    if (!context.local_circuit || !context.lan_neighbors || context.physical_point_to_point)
      return {InterfaceProgramStatus::invalid_context, {}};
    for (std::size_t level{}; level < 2U; ++level) if (mask & (1U << level))
      if (!timing_fits(resolve_hello_timing(resolved.level[level], false)) ||
          !timing_fits(resolve_hello_timing(resolved.level[level], true)))
        return {InterfaceProgramStatus::unrepresentable_holding, {}};
    output.broadcast.emplace();
    for (std::size_t level{}; level < 2U; ++level) if (mask & (1U << level)) {
      auto &hello = output.broadcast->levels[level].emplace();
      common(hello, level);
      hello.local = {*local, context.mac, resolved.level[level].priority, context.local_circuit};
      hello.levels = levels;
      hello.type = level ? packet::isis::PduType::lan_hello_l2 : packet::isis::PduType::lan_hello_l1;
      hello.hello_destination = context.destinations.levels[level];
      hello.limits = {context.lan_neighbors, context.maximum_areas};
      const auto timing = resolve_hello_timing(resolved.level[level], true);
      hello.designated_hello_interval = timing.interval;
      hello.designated_holding_seconds = static_cast<std::uint16_t>(timing.holding_seconds);
    }
  }
  return {InterfaceProgramStatus::prepared, std::move(output)};
}
}
