// Control-shard route, neighbor and router probe operations. RuntimeSupervisor owns
// RIB inputs and sends compiled generations toward the network layer.

#include "runtime_supervisor_internal.hpp"

namespace router::lab {

bool RuntimeSupervisor::remove_interface(DeviceHandle device,
                                         std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv4_configured)
    return false;

  // IPv4 and IPv6 are leaves on one routed interface. Removing the IPv4 leaf
  // must not tear down IPv6, DAD, ND or RA state. The physical forwarding port
  // is withdrawn only after the final configured address family is removed.
  port.ipv4_configured = false;
  port.address = 0U;
  port.network = 0U;
  port.prefix_length = 0U;
  state.connected[*ordinal] = {};
  if (!port.ipv6_configured && !state.ies_port_owned[*ordinal]) {
    port = {};
    state.interface_admin[*ordinal] = false;
    state.ipv6_connected[*ordinal] = {};
    rebuild_routes(device);
    auto &remove = prepare(NetworkCommandKind::remove_port);
    remove.device = device;
    remove.port.ordinal = *ordinal;
    const auto result = dispatch(remove);
    return result && result->success;
  }
  if (!port.ipv6_configured) {
    // SAP lookup, not the physical access-port projection, supplies the source
    // identity for service traffic. Keep only carrier, MTU and line rate when
    // the native IPv4 child was the final native address family.
    port.mac = {};
    state.interface_admin[*ordinal] = false;
  }
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::add_static_route(DeviceHandle device,
                                         std::uint32_t network,
                                         std::uint8_t prefix_length,
                                         std::uint32_t next_hop,
                                         bool indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U || !next_hop)
    return false;
  auto &state = *router_network_[device.index];
  routing::StaticInput *target{};
  const auto canonical = network & routing::prefix_mask(prefix_length);
  for (auto &entry : state.statics) {
    if (entry.configured && entry.network == canonical &&
        entry.prefix_length == prefix_length &&
        entry.next_hop == next_hop && entry.indirect == indirect) {
      target = &entry;
      break;
    }
    if (!entry.configured && !target)
      target = &entry;
  }
  if (!target)
    // Exhaustion is explicit. No oldest route is evicted to make the command
    // appear successful.
    return false;
  *target = {.configured = true,
             .network = canonical,
             .next_hop = next_hop,
             .prefix_length = prefix_length,
             .indirect = indirect};
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::remove_static_route(
    DeviceHandle device, std::uint32_t network,
    std::uint8_t prefix_length, std::optional<std::uint32_t> next_hop,
    std::optional<bool> indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U)
    return false;
  auto &state = *router_network_[device.index];
  const auto canonical = network & routing::prefix_mask(prefix_length);
  bool removed{};
  for (auto &entry : state.statics) {
    if (!entry.configured || entry.network != canonical ||
        entry.prefix_length != prefix_length ||
        (next_hop && entry.next_hop != *next_hop) ||
        (indirect && entry.indirect != *indirect))
      continue;
    entry = {};
    removed = true;
  }
  if (!removed)
    return false;
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::configure_ecmp(DeviceHandle device,
                                       std::uint16_t maximum_paths) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || maximum_paths == 0U ||
      maximum_paths > device_catalog::maximum_ecmp_paths)
    return false;
  auto &state = *router_network_[device.index];
  if (state.maximum_ecmp_paths == maximum_paths)
    return true;
  state.maximum_ecmp_paths = maximum_paths;
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::add_ipv6_static_route(
    DeviceHandle device, const packet::Ipv6 &network,
    std::uint8_t prefix_length, const packet::Ipv6 &next_hop,
    std::string_view outgoing_port_id, bool indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits ||
      ip::is_unspecified(next_hop) || ip::is_multicast(next_hop))
    return false;
  auto &state = *router_network_[device.index];
  const auto canonical = ip::mask(network, prefix_length);
  std::optional<std::uint16_t> outgoing_port;
  if (!outgoing_port_id.empty()) {
    const auto *inventory = hardware(device);
    if (!inventory)
      return false;
    outgoing_port = inventory->coordinate_ordinal(outgoing_port_id);
    if (!outgoing_port)
      return false;
  }
  // An indirect address is a routing-table key, not a scoped adjacency. A
  // link-local address cannot be resolved without a zone, while attaching a
  // physical port would turn the command into direct next-hop semantics.
  if ((indirect && (ip::is_link_local(next_hop) || outgoing_port)) ||
      (!indirect && ip::is_link_local(next_hop) && !outgoing_port))
    return false;

  routing::Ipv6StaticInput *target{};
  for (auto &entry : state.ipv6_statics) {
    if (entry.configured && entry.network == canonical &&
        entry.prefix_length == prefix_length && entry.next_hop == next_hop &&
        entry.indirect == indirect) {
      target = &entry;
      break;
    }
    if (!entry.configured && !target)
      target = &entry;
  }
  if (!target)
    return false;
  *target = {.configured = true,
             .indirect = indirect,
             .outgoing_interface_set = outgoing_port.has_value(),
             .network = canonical,
             .next_hop = next_hop,
             .outgoing_interface_id =
                 outgoing_port ? physical_interface_id(*outgoing_port) : 0U,
             .prefix_length = prefix_length};
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::remove_ipv6_static_route(
    DeviceHandle device, const packet::Ipv6 &network,
    std::uint8_t prefix_length, std::optional<packet::Ipv6> next_hop,
    std::optional<bool> indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits)
    return false;
  auto &state = *router_network_[device.index];
  const auto canonical = ip::mask(network, prefix_length);
  bool removed{};
  for (auto &entry : state.ipv6_statics) {
    if (!entry.configured || entry.network != canonical ||
        entry.prefix_length != prefix_length ||
        (next_hop && entry.next_hop != *next_hop) ||
        (indirect && entry.indirect != *indirect))
      continue;
    entry = {};
    removed = true;
  }
  if (!removed)
    return false;
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::install_static_ipv6_neighbor(
    DeviceHandle device, std::string_view port_id, const packet::Ipv6 &address,
    packet::Mac mac) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || ip::is_unspecified(address) ||
      ip::is_multicast(address))
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  const auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  // Forwarding validates the MAC and owns capacity. Control publishes no
  // parallel cache copy, so a rejected full-cache installation cannot appear
  // in management intent until LabRuntime commits the acknowledged change.
  auto &command = prepare(NetworkCommandKind::install_static_ipv6_neighbor);
  command.device = device;
  command.fib = StaticIpv6NeighborProgram{.device = device,
                                          .address = address,
                                          .mac = mac,
                                          .port_ordinal = *ordinal};
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::remove_static_ipv6_neighbor(
    DeviceHandle device, std::string_view port_id,
    const packet::Ipv6 &address) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &command = prepare(NetworkCommandKind::remove_static_ipv6_neighbor);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.ipv6_destination = address;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::install_static_ipv4_neighbor(DeviceHandle device,
                                                     std::string_view port_id,
                                                     std::uint32_t address,
                                                     packet::Mac mac) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || address == 0U || address == 0xffffffffU)
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  const auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv4_configured)
    return false;

  // The forwarding owner performs the final on-link and capacity validation.
  // Intent is committed only after this bounded command is acknowledged.
  auto &command = prepare(NetworkCommandKind::install_static_ipv4_neighbor);
  command.device = device;
  command.fib = StaticIpv4NeighborProgram{.device = device,
                                          .address = address,
                                          .mac = mac,
                                          .port_ordinal = *ordinal};
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::remove_static_ipv4_neighbor(
    DeviceHandle device, std::string_view port_id,
    std::uint32_t address) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &command = prepare(NetworkCommandKind::remove_static_ipv4_neighbor);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.destination = address;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_dynamic_ipv6_neighbors(
    DeviceHandle device, std::optional<std::string_view> port_id,
    std::optional<packet::Ipv6> address) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  std::optional<std::uint16_t> ordinal;
  if (port_id) {
    auto *inventory = hardware(device);
    if (!inventory)
      return false;
    ordinal = inventory->coordinate_ordinal(*port_id);
    if (!ordinal)
      return false;
  }
  auto &command = prepare(NetworkCommandKind::clear_dynamic_ipv6_neighbors);
  command.device = device;
  command.port.ordinal = ordinal.value_or(0U);
  command.ipv6_destination = address.value_or(packet::Ipv6{});
  command.ipv6_neighbor_interface_specific = ordinal.has_value();
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_dynamic_ipv4_neighbors(
    DeviceHandle device, std::optional<std::string_view> port_id,
    std::optional<std::uint32_t> address) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  std::optional<std::uint16_t> ordinal;
  if (port_id) {
    auto *inventory = hardware(device);
    if (!inventory)
      return false;
    ordinal = inventory->coordinate_ordinal(*port_id);
    if (!ordinal)
      return false;
  }
  auto &command = prepare(NetworkCommandKind::clear_dynamic_ipv4_neighbors);
  command.device = device;
  command.port.ordinal = ordinal.value_or(0U);
  command.destination = address.value_or(0U);
  command.ipv4_neighbor_interface_specific = ordinal.has_value();
  const auto result = dispatch(command);
  return result && result->success;
}

void RuntimeSupervisor::refresh_router(DeviceHandle device) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return;
  auto &state = *router_network_[device.index];
  for (std::size_t ordinal = 0; ordinal < state.ports.size(); ++ordinal) {
    if (!state.ports[ordinal].configured)
      continue;
    const auto *physical = inventory->at(static_cast<std::uint16_t>(ordinal));
    const bool operational =
        physical && physical->present && physical->configuration_compatible &&
        physical->hierarchy_enabled && physical->admin_enabled &&
        physical->link_signal &&
        (state.interface_admin[ordinal] || state.ies_port_owned[ordinal]);
    state.ports[ordinal].operational = operational;
    if (physical) {
      state.ports[ordinal].mtu = physical->mtu;
      state.ports[ordinal].speed_mbps = physical->speed_mbps;
    }
    state.connected[ordinal].operational = operational;
    state.ipv6_connected[ordinal].operational =
        operational && state.ports[ordinal].ipv6_configured;
    for (auto &connected : state.native_ipv6_connected)
      if (connected.physical_port_ordinal == ordinal)
        connected.operational =
            operational && state.ports[ordinal].ipv6_configured;
    // Forwarding receives the complete port projection even when down. This
    // preserves address and MTU configuration without granting packet passage.
    auto &configure = prepare(NetworkCommandKind::configure_port);
    configure.device = device;
    configure.port = state.ports[ordinal];
    static_cast<void>(dispatch(configure));
    const auto &advertisement = state.router_advertisements[ordinal];
    if (advertisement.configured) {
      auto &ra = prepare(NetworkCommandKind::configure_router_advertisement);
      ra.device = device;
      ra.fib = RouterAdvertisementProgram{
          .device = device,
          .config = advertisement.config,
          .port_ordinal = static_cast<std::uint16_t>(ordinal),
          .enabled = advertisement.enabled};
      static_cast<void>(dispatch(ra));
    }
    const auto &mld = state.mld_interfaces[ordinal];
    if (mld.configured) {
      // Re-resolve fields that originate outside the MLD configuration tree.
      // Hardware replacement may preserve the stable ordinal while an IPv6
      // address edit changes the local Querier address.
      auto configuration = mld.configuration;
      configuration.port_ordinal = static_cast<std::uint16_t>(ordinal);
      configuration.link_local_address = state.ports[ordinal].ipv6_link_local;
      auto &program = prepare(NetworkCommandKind::configure_mld_interface);
      program.device = device;
      program.fib =
          MldInterfaceProgram{.device = device, .configuration = configuration};
      const auto result = dispatch(program);
      if (result && result->success) {
        state.mld_interfaces[ordinal].configuration = configuration;
        // configure_mld_interface recreates the forwarding-owned protocol
        // object. Reinstall the last committed SSM program before this refresh
        // can be considered complete. The begin/add/commit sequence keeps the
        // previous generation visible until every range-source tuple arrives.
        const auto &translations = mld.ssm_translations;
        const auto submit = [&](MldSsmProgramOperation operation,
                                const MldSsmTranslation &entry = {}) {
          auto &translation =
              prepare(NetworkCommandKind::program_mld_ssm_translation);
          translation.device = device;
          translation.port.ordinal = static_cast<std::uint16_t>(ordinal);
          translation.mld_ssm_operation = operation;
          translation.mld_ssm_translation = entry;
          translation.mld_ssm_expected_entries =
              operation == MldSsmProgramOperation::begin
                  ? static_cast<std::uint32_t>(translations.size())
                  : 0U;
          const auto programmed = dispatch(translation);
          return programmed && programmed->success;
        };
        bool complete = submit(MldSsmProgramOperation::begin);
        for (const auto &translation : translations)
          complete =
              complete && submit(MldSsmProgramOperation::add, translation);
        complete = complete && submit(MldSsmProgramOperation::commit);
        if (!complete)
          static_cast<void>(submit(MldSsmProgramOperation::abort));

        // Reconfiguration constructs a new forwarding MLD owner, so the
        // effective policy generation must follow the same rebuild path as SSM
        // translation. The named policy remains a LabRuntime concern; this
        // transaction restores only its already resolved value program.
        const auto &policy = mld.import_policy;
        const auto submit_policy =
            [&](mld::ImportPolicyProgramOperation operation,
                const mld::ImportPolicyEntry &entry = {}) {
              auto &policy_command =
                  prepare(NetworkCommandKind::program_mld_import_policy);
              policy_command.device = device;
              policy_command.port.ordinal = static_cast<std::uint16_t>(ordinal);
              policy_command.mld_import_policy_operation = operation;
              policy_command.mld_import_policy_entry = entry;
              policy_command.mld_import_policy_default_action =
                  policy.default_action;
              policy_command.mld_import_policy_expected_entries =
                  operation == mld::ImportPolicyProgramOperation::begin
                      ? static_cast<std::uint32_t>(policy.entries.size())
                      : 0U;
              const auto programmed = dispatch(policy_command);
              return programmed && programmed->success;
            };
        bool policy_complete =
            submit_policy(mld::ImportPolicyProgramOperation::begin);
        for (const auto &entry : policy.entries)
          policy_complete =
              policy_complete &&
              submit_policy(mld::ImportPolicyProgramOperation::add, entry);
        policy_complete =
            policy_complete &&
            submit_policy(mld::ImportPolicyProgramOperation::commit);
        if (!policy_complete)
          static_cast<void>(
              submit_policy(mld::ImportPolicyProgramOperation::abort));
      }
    }
    if (state.dhcpv6_relays[ordinal]) {
      // A forwarding port can disappear with a card while committed service
      // intent remains. Reinstall the complete relay generation only after
      // IPv6 and its UDP/FIB prerequisites have been republished.
      static_cast<void>(
          program_dhcpv6_relay(device, static_cast<std::uint16_t>(ordinal),
                               *state.dhcpv6_relays[ordinal]));
    }
  }
  // configure_port carries only the selected-primary compatibility cache.
  // Republish the full generation after all physical projections so secondary
  // addresses cannot disappear during card, link or admin reconciliation.
  static_cast<void>(
      program_ipv6_address_generation(device, state.native_ipv6_addresses));
  if (!state.ies_configuration.ports.empty() ||
      !state.ies_configuration.ies_services.empty()) {
    // Rebuild the entire service generation after all physical port views are
    // current. The call retains configured intent for absent equipment while
    // publishing classifiers only for ports that presently exist.
    static_cast<void>(configure_ies_services(device, state.ies_configuration));
  }
  rebuild_routes(device);
}

void RuntimeSupervisor::rebuild_routes(DeviceHandle device) noexcept {
  if (device.index >= router_network_.size() || !router_network_[device.index])
    return;
  auto &state = *router_network_[device.index];
  // Publish unresolved static intent before either base FIB. The network
  // route-manager is the sole owner that can later resolve an indirect static
  // next hop through an OSPF route without asking control to poll protocol
  // state or letting OSPF bypass RIB selection.
  auto &policy_command = prepare(NetworkCommandKind::program_route_policy);
  policy_command.device = device;
  policy_command.fib =
      RoutePolicyProgram{.ipv4_statics = state.statics,
                         .ipv6_statics = state.ipv6_statics,
                         .maximum_ecmp_paths = state.maximum_ecmp_paths};
  const auto policy_result = dispatch(policy_command);
  if (!policy_result || !policy_result->success)
    return;
  const bool changed = state.rib.rebuild(state.connected, state.statics, {},
                                         state.maximum_ecmp_paths);
  if (!state.rib.last_rebuild_valid())
    return;
  if (changed || !state.fib_generation) {
    // Generation advances only for an installed selection. Rejected rebuilds
    // leave both control RIB and forwarding FIB on their previous generation.
    ++state.fib_generation;
    auto &program = prepare(NetworkCommandKind::program_fib);
    program.device = device;
    program.fib = state.rib.compile(state.fib_generation);
    static_cast<void>(dispatch(program));
  }
  const bool ipv6_changed =
      state.ipv6_rib.rebuild(state.native_ipv6_connected, state.ipv6_statics,
                             state.ies_ipv6_connected, {},
                             state.maximum_ecmp_paths);
  if (!state.ipv6_rib.last_rebuild_valid())
    return;
  if (ipv6_changed || !state.ipv6_fib_generation) {
    ++state.ipv6_fib_generation;
    auto &program = prepare(NetworkCommandKind::program_ipv6_fib);
    program.device = device;
    program.fib = state.ipv6_rib.compile(state.ipv6_fib_generation);
    static_cast<void>(dispatch(program));
  }
}

bool RuntimeSupervisor::start_router_ping(DeviceHandle device,
                                          std::uint32_t destination,
                                          std::uint16_t sequence,
                                          std::uint16_t payload_octets,
                                          bool dont_fragment) noexcept {
  if (!devices_.get(device))
    return false;
  auto &command = prepare(NetworkCommandKind::router_ping);
  command.device = device;
  command.destination = destination;
  command.sequence = sequence;
  command.payload_octets = payload_octets;
  command.dont_fragment = dont_fragment;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::router_ping_reply(DeviceHandle device,
                                          std::uint16_t sequence) noexcept {
  return (router_ping_outcome(device, sequence) & 0xffU) == 1U;
}

std::uint64_t
RuntimeSupervisor::router_ping_outcome(DeviceHandle device,
                                       std::uint16_t sequence) noexcept {
  if (!devices_.get(device))
    return 0U;
  auto &command = prepare(NetworkCommandKind::router_ping_status);
  command.device = device;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0U;
}

bool RuntimeSupervisor::start_router_ipv6_ping(
    DeviceHandle device, const packet::Ipv6 &destination,
    std::uint16_t sequence, std::uint16_t payload_octets) noexcept {
  if (!devices_.get(device) || ip::is_unspecified(destination) ||
      ip::is_multicast(destination))
    return false;
  auto &command = prepare(NetworkCommandKind::router_ipv6_ping);
  command.device = device;
  command.ipv6_destination = destination;
  command.sequence = sequence;
  command.payload_octets = payload_octets;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::router_ipv6_ping_reply(
    DeviceHandle device, std::uint16_t sequence) noexcept {
  return (router_ipv6_ping_outcome(device, sequence) & 0xffU) == 1U;
}

std::uint64_t
RuntimeSupervisor::router_ipv6_ping_outcome(DeviceHandle device,
                                            std::uint16_t sequence) noexcept {
  if (!devices_.get(device))
    return 0U;
  auto &command = prepare(NetworkCommandKind::router_ipv6_ping_status);
  command.device = device;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0U;
}

} // namespace router::lab
