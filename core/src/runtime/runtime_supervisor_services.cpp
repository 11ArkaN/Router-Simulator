// Control-shard IES, DHCPv6 and MLD service configuration. RuntimeSupervisor owns
// committed intent; service and forwarding layers receive complete value projections.

#include "runtime_supervisor_internal.hpp"

namespace router::lab {

bool RuntimeSupervisor::configure_ies_services(
    DeviceHandle device, const service::Configuration &configuration) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      service::validate(configuration) != service::ValidationError::none)
    return false;
  auto &state = *router_network_[device.index];

  service::Configuration candidate_configuration;
  auto candidate_ports = state.ports;
  std::array<bool, device_catalog::maximum_ports_per_router>
      candidate_port_ownership{};
  std::vector<service::SapAttachment> candidate_attachments;
  std::vector<service::ServiceIpv6Interface> candidate_interfaces;
  std::vector<routing::Ipv6ConnectedInput> candidate_connected;
  std::vector<dhcpv6::RelayInterfaceConfig> candidate_relays;
  try {
    candidate_configuration = configuration;
    std::size_t interface_count{};
    for (const auto &service : configuration.ies_services)
      interface_count += service.interfaces.size();
    candidate_attachments.reserve(interface_count);
    candidate_interfaces.reserve(interface_count);
    candidate_connected.reserve(interface_count);
    candidate_relays.reserve(interface_count);

    // Configuration stores both visible card/MDA/port coordinates and the
    // dense runtime ordinal. Validate their relation against this router's
    // hardware owner before allowing either identity to reach forwarding.
    for (const auto &port_configuration : configuration.ports) {
      const auto ordinal = port_configuration.coordinate.ordinal;
      const auto *hardware_port = inventory->at(ordinal);
      if (!hardware_port ||
          hardware_port->card_slot != port_configuration.coordinate.card ||
          hardware_port->mda_slot != port_configuration.coordinate.mda ||
          hardware_port->port_number != port_configuration.coordinate.port)
        return false;

      // Port configuration and a routed interface are separate SR OS
      // objects. An access port therefore needs a forwarding projection even
      // when it has no native IPv4 or IPv6 child. Keep the physical object
      // address-free and let the SAP generation supply each logical L3 MAC
      // and address. This prevents one arbitrary SAP from becoming a fake
      // native interface on a port that can host several tagged services.
      if (!hardware_port->present)
        continue;
      candidate_port_ownership[ordinal] = true;
      auto &candidate_port = candidate_ports[ordinal];
      if (!candidate_port.configured) {
        candidate_port = {};
        candidate_port.configured = true;
        candidate_port.ipv4_configured = false;
        candidate_port.ordinal = ordinal;
      }
      candidate_port.mtu = hardware_port->mtu;
      candidate_port.speed_mbps = hardware_port->speed_mbps;
      candidate_port.operational =
          hardware_port->configuration_compatible &&
          hardware_port->hierarchy_enabled && hardware_port->admin_enabled &&
          hardware_port->link_signal &&
          (state.interface_admin[ordinal] || candidate_port_ownership[ordinal]);
    }

    // Retiring service ownership must not remove a native routed interface.
    // Conversely, a port that existed solely for an old IES generation is
    // cleared in the candidate control image after the new SAP generation has
    // stopped referencing it.
    for (std::size_t ordinal = 0; ordinal < candidate_ports.size(); ++ordinal)
      if (state.ies_port_owned[ordinal] && !candidate_port_ownership[ordinal] &&
          !candidate_ports[ordinal].ipv4_configured &&
          !candidate_ports[ordinal].ipv6_configured)
        candidate_ports[ordinal] = {};

    const auto configured_local_source = [&](const packet::Ipv6 &address) {
      for (const auto &service : configuration.ies_services)
        for (const auto &interface : service.interfaces)
          if (interface.address_configured &&
              (interface.address == address || interface.link_local == address))
            return true;
      for (const auto &port : state.ports)
        if (port.configured && port.ipv6_configured &&
            (port.ipv6_address == address || port.ipv6_link_local == address))
          return true;
      return false;
    };

    for (const auto &ies : configuration.ies_services) {
      for (const auto &interface : ies.interfaces) {
        // Classic CLI permits creation of an IP interface before its SAP.
        // Such intent is real running configuration but owns no forwarding
        // classifier or physical port until the attachment is configured.
        if (interface.sap.port.card == 0U && interface.sap.port.mda == 0U &&
            interface.sap.port.port == 0U)
          continue;
        const auto ordinal = interface.sap.port.ordinal;
        if (ordinal >= state.ports.size())
          return false;
        const auto port_configuration =
            std::find_if(configuration.ports.begin(), configuration.ports.end(),
                         [&](const auto &port) {
                           return port.coordinate == interface.sap.port;
                         });
        if (port_configuration == configuration.ports.end())
          return false;

        // Intent on an unequipped card remains in candidate_configuration but
        // cannot become a live SAP classifier. refresh_router republishes the
        // same retained graph after the physical owner reports the port again.
        const auto &physical = candidate_ports[ordinal];
        if (!candidate_port_ownership[ordinal] || !physical.configured)
          continue;
        candidate_attachments.push_back(
            {.logical_interface_id = interface.logical_id,
             .sap = interface.sap,
             .outer_tpid = port_configuration->outer_tpid,
             .inner_tpid = static_cast<std::uint16_t>(
                 interface.sap.encapsulation ==
                         service::EthernetEncapsulation::qinq
                     ? packet::ethernet_type_customer_vlan
                     : 0U)});
        const bool operational = interface.address_configured &&
                                 ies.admin_enabled && interface.admin_enabled &&
                                 physical.operational;
        candidate_interfaces.push_back(
            {.interface_id = interface.logical_id,
             .physical_port_ordinal = ordinal,
             .mtu = interface.ip_mtu,
             .mac = interface.mac,
             .address = interface.address,
             .network =
                 interface.address_configured
                     ? ip::mask(interface.address, interface.prefix_length)
                     : packet::Ipv6{},
             .link_local = interface.link_local,
             .prefix_length = interface.prefix_length,
             .nd_reachable_time_milliseconds =
                 device_catalog::nd_default_reachable_time_seconds * 1000U,
             .nd_stale_time_seconds =
                 device_catalog::nd_default_stale_time_seconds,
             .neighbor_limit_threshold_percent =
                 device_catalog::nd_default_neighbor_limit_threshold_percent,
             .redirect_maximum = device_catalog::icmp6_redirect_default_maximum,
             .redirect_interval_seconds = static_cast<std::uint16_t>(
                 device_catalog::icmp6_redirect_default_interval.count()),
             .redirects_enabled = true,
             .configured = interface.address_configured,
             .operational = operational});
        if (interface.address_configured)
          candidate_connected.push_back(
              {.configured = true,
               .operational = operational,
               .network = ip::mask(interface.address, interface.prefix_length),
               .interface_id = interface.logical_id,
               .physical_port_ordinal = ordinal,
               .prefix_length = interface.prefix_length});

        const auto &relay_intent = interface.dhcpv6_relay;
        if (!relay_intent.configured || !relay_intent.admin_enabled ||
            relay_intent.servers.empty() || !operational)
          continue;
        const auto interface_id =
            service::relay_interface_id(configuration, ies, interface);
        if (!interface_id ||
            (relay_intent.source_address &&
             !configured_local_source(*relay_intent.source_address)))
          return false;
        dhcpv6::RelayInterfaceConfig relay{
            .interface_id = interface.logical_id,
            .physical_port_ordinal = ordinal,
            .link_address =
                relay_intent.link_address.value_or(interface.address),
            .source_address =
                relay_intent.source_address.value_or(packet::Ipv6{}),
            .has_source_address = relay_intent.source_address.has_value(),
            .relay_interface_id = std::move(*interface_id),
            .server_count = relay_intent.servers.size(),
            .upstream_policy =
                dhcpv6::RelayUpstreamPolicy::explicit_servers_required,
            .client_prefix = {.network = ip::mask(interface.address,
                                                  interface.prefix_length),
                              .length = interface.prefix_length},
            .lease_population_limit = relay_intent.lease_population_limit,
            .neighbor_resolution = relay_intent.neighbor_resolution,
            .route_non_temporary = relay_intent.route_populate_na,
            .route_temporary = relay_intent.route_populate_ta,
            .route_delegated_prefix = relay_intent.route_populate_pd,
            .route_prefix_exclude = relay_intent.route_populate_pd_exclude};
        std::copy(relay_intent.servers.begin(), relay_intent.servers.end(),
                  relay.servers.begin());
        candidate_relays.push_back(std::move(relay));
      }
    }

    // Route admission is checked before any forwarding publication. This
    // prevents a valid SAP generation from becoming live when the combined
    // native, service and static RIB would exceed its profiled capacity.
    auto candidate_rib = std::make_unique<routing::Ipv6RouteTable>();
    static_cast<void>(candidate_rib->rebuild(
        state.native_ipv6_connected, state.ipv6_statics, candidate_connected));
    if (!candidate_rib->last_rebuild_valid())
      return false;
  } catch (const std::bad_alloc &) {
    return false;
  }

  // Publish every physical prerequisite before the atomic SAP generation.
  // Old service-only ports remain installed until after that generation is
  // replaced, so no live classifier ever points at a removed physical port.
  std::array<bool, device_catalog::maximum_ports_per_router>
      candidate_port_published{};
  for (std::size_t ordinal = 0; ordinal < candidate_ports.size(); ++ordinal) {
    if (!candidate_ports[ordinal].configured ||
        (!candidate_port_ownership[ordinal] && !state.ies_port_owned[ordinal]))
      continue;
    auto &configure = prepare(NetworkCommandKind::configure_port);
    configure.device = device;
    configure.port = candidate_ports[ordinal];
    const auto result = dispatch(configure);
    if (!result || !result->success) {
      // Only earlier records were accepted. Restore those exact records in
      // reverse ownership order before reporting a failed transaction.
      for (std::size_t rollback_ordinal = 0;
           rollback_ordinal < candidate_port_published.size();
           ++rollback_ordinal) {
        if (!candidate_port_published[rollback_ordinal])
          continue;
        auto &restore = prepare(state.ports[rollback_ordinal].configured
                                    ? NetworkCommandKind::configure_port
                                    : NetworkCommandKind::remove_port);
        restore.device = device;
        restore.port = state.ports[rollback_ordinal].configured
                           ? state.ports[rollback_ordinal]
                           : ForwardPort{.ordinal = static_cast<std::uint16_t>(
                                             rollback_ordinal)};
        static_cast<void>(dispatch(restore));
      }
      return false;
    }
    candidate_port_published[ordinal] = true;
  }

  const auto rollback = [&]() noexcept {
    // Remove every candidate relay first while its candidate SAP still owns
    // the logical interface. Then restore the prior SAP generation and its
    // complete relay set. Each operation is best effort because the caller
    // already receives failure, but no successful candidate state is retained
    // intentionally.
    for (const auto &relay : candidate_relays) {
      auto &remove = prepare(NetworkCommandKind::remove_dhcpv6_relay);
      remove.device = device;
      remove.logical_interface_id = relay.interface_id;
      static_cast<void>(dispatch(remove));
    }
    // Restore old configured physical records first because the old SAP
    // generation is validated against them. Candidate-only ports deliberately
    // remain until that old generation has displaced every candidate SAP.
    for (std::size_t ordinal = 0; ordinal < state.ports.size(); ++ordinal) {
      if (!candidate_port_published[ordinal] ||
          !state.ports[ordinal].configured)
        continue;
      auto &restore = prepare(NetworkCommandKind::configure_port);
      restore.device = device;
      restore.port = state.ports[ordinal];
      static_cast<void>(dispatch(restore));
    }
    static_cast<void>(program_sap_generation(device, state.ies_sap_attachments,
                                             state.ies_ipv6_interfaces));
    for (std::size_t ordinal = 0; ordinal < state.ports.size(); ++ordinal) {
      if (!candidate_port_published[ordinal] || state.ports[ordinal].configured)
        continue;
      auto &remove = prepare(NetworkCommandKind::remove_port);
      remove.device = device;
      remove.port.ordinal = static_cast<std::uint16_t>(ordinal);
      static_cast<void>(dispatch(remove));
    }
    for (const auto &relay : state.ies_dhcpv6_relays)
      static_cast<void>(program_dhcpv6_relay(
          device, relay.physical_port_ordinal, relay, false));
  };

  if (!program_sap_generation(device, candidate_attachments,
                              candidate_interfaces)) {
    rollback();
    return false;
  }
  for (const auto &relay : candidate_relays)
    if (!program_dhcpv6_relay(device, relay.physical_port_ordinal, relay,
                              false)) {
      rollback();
      return false;
    }
  for (const auto &old : state.ies_dhcpv6_relays) {
    const auto retained =
        std::find_if(candidate_relays.begin(), candidate_relays.end(),
                     [&](const auto &relay) {
                       return relay.interface_id == old.interface_id;
                     });
    if (retained != candidate_relays.end())
      continue;
    auto &remove = prepare(NetworkCommandKind::remove_dhcpv6_relay);
    remove.device = device;
    remove.logical_interface_id = old.interface_id;
    const auto result = dispatch(remove);
    if (!result || !result->success) {
      rollback();
      return false;
    }
  }

  for (std::size_t ordinal = 0; ordinal < candidate_ports.size(); ++ordinal) {
    if (!state.ies_port_owned[ordinal] || candidate_port_ownership[ordinal] ||
        candidate_ports[ordinal].configured)
      continue;
    auto &remove = prepare(NetworkCommandKind::remove_port);
    remove.device = device;
    remove.port.ordinal = static_cast<std::uint16_t>(ordinal);
    const auto result = dispatch(remove);
    if (!result || !result->success) {
      rollback();
      return false;
    }
  }

  // Every move publishes a fully built cold-path value without allocation.
  // The forwarding owner has already acknowledged the corresponding packet
  // generation, so control can now make it the source for CLI and checkpoint.
  state.ies_configuration = std::move(candidate_configuration);
  state.ports = candidate_ports;
  state.ies_port_owned = candidate_port_ownership;
  state.ies_sap_attachments = std::move(candidate_attachments);
  state.ies_ipv6_interfaces = std::move(candidate_interfaces);
  state.ies_ipv6_connected = std::move(candidate_connected);
  state.ies_dhcpv6_relays = std::move(candidate_relays);
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::configure_dhcpv6_relay(
    DeviceHandle device, std::string_view port_id,
    const dhcpv6::RelayInterfaceConfig &configuration) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory)
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  return ordinal && program_dhcpv6_relay(device, *ordinal, configuration);
}

bool RuntimeSupervisor::program_dhcpv6_relay(
    DeviceHandle device, std::uint16_t port_ordinal,
    const dhcpv6::RelayInterfaceConfig &configuration,
    bool retain_legacy_port_intent) noexcept {
  if (device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      port_ordinal >= router_network_[device.index]->ports.size())
    return false;
  const auto &port = router_network_[device.index]->ports[port_ordinal];
  if ((retain_legacy_port_intent &&
       (!port.configured || !port.ipv6_configured)) ||
      configuration.interface_id == 0U ||
      configuration.relay_interface_id.size() >
          std::numeric_limits<std::uint16_t>::max() ||
      configuration.server_count > configuration.servers.size())
    return false;

  // A full IES transaction publishes its candidate physical port and SAP
  // generation before the relay child, while the old control generation stays
  // visible until every forwarding command succeeds. In that path the
  // forwarding owner validates the just-published logical interface. Requiring
  // the old control port here would break transaction atomicity and force a
  // fake native IPv6 child onto a service-only access port.

  // Copy the value before touching the forwarding owner. If allocation fails,
  // the old generation remains active on both owners. Once commit succeeds,
  // moving this staged value into the fixed control slot cannot allocate.
  auto staged = std::optional<dhcpv6::RelayInterfaceConfig>{};
  try {
    staged = configuration;
    // Hardware resolution is authoritative. A caller cannot route the relay
    // through a different physical port by embedding a conflicting ordinal.
    staged->physical_port_ordinal = port_ordinal;
  } catch (const std::bad_alloc &) {
    return false;
  }

  // The begin record declares the complete generation before any variable
  // data is accepted. Every following command is synchronously acknowledged,
  // so failure can abort without publishing a prefix of Interface-Id or a
  // partial server list. The forwarding owner swaps generations only at
  // commit after the declared counts match exactly.
  auto &begin_command = prepare(NetworkCommandKind::begin_dhcpv6_relay);
  begin_command.device = device;
  begin_command.fib = Dhcpv6RelayBegin{
      .interface_id = configuration.interface_id,
      .physical_port_ordinal = port_ordinal,
      .link_address = configuration.link_address,
      .source_address = configuration.source_address,
      .client_prefix = configuration.client_prefix,
      .expected_interface_id_octets =
          static_cast<std::uint32_t>(configuration.relay_interface_id.size()),
      .expected_servers =
          static_cast<std::uint16_t>(configuration.server_count),
      .lease_population_limit = configuration.lease_population_limit,
      .has_source_address = configuration.has_source_address,
      .neighbor_resolution = configuration.neighbor_resolution,
      .route_non_temporary = configuration.route_non_temporary,
      .route_temporary = configuration.route_temporary,
      .route_delegated_prefix = configuration.route_delegated_prefix,
      .route_prefix_exclude = configuration.route_prefix_exclude,
      .upstream_policy = configuration.upstream_policy};
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;

  for (std::size_t offset = 0; offset < configuration.relay_interface_id.size();
       offset += dhcpv6_relay_program_chunk_octets) {
    Dhcpv6RelayInterfaceIdChunk chunk;
    chunk.size = static_cast<std::uint16_t>(
        std::min(dhcpv6_relay_program_chunk_octets,
                 configuration.relay_interface_id.size() - offset));
    std::copy_n(configuration.relay_interface_id.begin() + offset, chunk.size,
                chunk.octets.begin());
    auto &command = prepare(NetworkCommandKind::add_dhcpv6_relay_interface_id);
    command.device = device;
    command.fib = chunk;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_relay;
  }
  for (std::size_t index = 0; index < configuration.server_count; ++index) {
    auto &command = prepare(NetworkCommandKind::add_dhcpv6_relay_server);
    command.device = device;
    command.fib = configuration.servers[index];
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_relay;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_dhcpv6_relay);
    command.device = device;
    result = dispatch(command);
    if (result && result->success) {
      if (!retain_legacy_port_intent)
        return true;
      auto &state = *router_network_[device.index];
      state.dhcpv6_relays[port_ordinal] = std::move(staged);
      // Regular relay is an IES-interface child, not an independent port
      // protocol. Publish the same stable logical identity to the RIB so ND,
      // PMTU, UDP metadata and Relay-reply all use one RFC 4007 zone.
      state.ipv6_connected[port_ordinal].interface_id =
          configuration.interface_id;
      rebuild_routes(device);
      return true;
    }
  }

abort_relay: {
  // Abort is idempotent after a rejected commit. Keeping it on all failure
  // paths also protects future workers that retain a rejected generation for
  // diagnostics instead of discarding it inside commit handling.
  auto &command = prepare(NetworkCommandKind::abort_dhcpv6_relay);
  command.device = device;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::remove_dhcpv6_relay(DeviceHandle device,
                                            std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->ports[*ordinal].ipv6_configured ||
      !router_network_[device.index]->dhcpv6_relays[*ordinal])
    return false;
  auto &command = prepare(NetworkCommandKind::remove_dhcpv6_relay);
  command.device = device;
  command.logical_interface_id =
      router_network_[device.index]->dhcpv6_relays[*ordinal]->interface_id;
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  router_network_[device.index]->dhcpv6_relays[*ordinal].reset();
  // The current native-interface API has no remaining service object after
  // relay removal. Restore its collision-free native identity. Full IES
  // ownership keeps the service ID independently when only its relay child is
  // removed.
  router_network_[device.index]->ipv6_connected[*ordinal].interface_id =
      physical_interface_id(*ordinal);
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::clear_dhcpv6_relay_leases(
    DeviceHandle device, const Dhcpv6RelayLeaseClearProgram &program) noexcept {
  if (!device || program.filter.interface_id == 0U ||
      device.index >= router_network_.size() || !router_network_[device.index])
    return false;
  const auto &state = *router_network_[device.index];
  const auto owns_interface = [&](const auto &relay) {
    return relay.interface_id == program.filter.interface_id;
  };
  const bool configured =
      std::any_of(state.ies_dhcpv6_relays.begin(),
                  state.ies_dhcpv6_relays.end(), owns_interface) ||
      std::any_of(
          state.dhcpv6_relays.begin(), state.dhcpv6_relays.end(),
          [&](const auto &relay) { return relay && owns_interface(*relay); });
  if (!configured)
    return false;
  auto &command = prepare(NetworkCommandKind::clear_dhcpv6_relay_leases);
  command.device = device;
  command.fib = program;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_database(
    DeviceHandle device, std::string_view port_id,
    const std::optional<packet::Ipv6> &group) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;

  // The group selector is validated before crossing the shard boundary. An
  // all-interface clear is intentionally performed by LabRuntime as one
  // command per configured interface, preserving each interface owner.
  if (group && !ip::is_multicast(*group))
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_database);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.ipv6_destination = group.value_or(packet::Ipv6{});
  command.mld_group_specific = group.has_value();
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_database_all(DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_database_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv4_statistics_all(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv4_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv4_global_statistics(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv4_global_statistics);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv4_interface_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal || !router_network_[device.index]->ports[*ordinal].configured)
    return false;
  auto &command =
      prepare(NetworkCommandKind::clear_icmpv4_interface_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv6_statistics_all(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv6_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv6_global_statistics(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv6_global_statistics);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv6_interface_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal || !router_network_[device.index]->ports[*ordinal].configured)
    return false;
  auto &command =
      prepare(NetworkCommandKind::clear_icmpv6_interface_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_router_advertisement_statistics_all(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command =
      prepare(NetworkCommandKind::clear_router_advertisement_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_router_advertisement_interface_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal || !router_network_[device.index]->ports[*ordinal].configured)
    return false;
  auto &command = prepare(
      NetworkCommandKind::clear_router_advertisement_interface_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_version(DeviceHandle device,
                                          std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_version);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_statistics_all(DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  // A router-wide clear is one bounded mailbox command. A sequence of
  // per-interface requests could otherwise stop halfway when the ring fills.
  auto &command = prepare(NetworkCommandKind::clear_mld_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::edit_mld_static(DeviceHandle device,
                                        std::string_view port_id,
                                        MldStaticOperation operation,
                                        const packet::Ipv6 &group,
                                        const packet::Ipv6 &source) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;
  if (!ip::is_multicast(group))
    return false;
  const bool needs_source = operation == MldStaticOperation::add_source ||
                            operation == MldStaticOperation::remove_source;
  if (needs_source && (ip::is_unspecified(source) || ip::is_multicast(source)))
    return false;
  auto &command = prepare(NetworkCommandKind::edit_mld_static);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.ipv6_destination = group;
  command.ipv6_source = source;
  command.mld_static_operation = operation;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::replace_mld_ssm_translations(
    DeviceHandle device, std::string_view port_id,
    std::span<const MldSsmTranslation> translations) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      translations.size() >
          device_catalog::mld_router_group_sources_per_interface)
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;

  // Validate the complete value program before opening forwarding staging.
  // This keeps malformed or duplicate candidate state on the control owner and
  // guarantees that every accepted add in the transaction has one meaning.
  for (std::size_t index = 0; index < translations.size(); ++index) {
    const auto &entry = translations[index];
    if (!ip::is_multicast(entry.start) || !ip::is_multicast(entry.end) ||
        entry.end < entry.start || ip::is_unspecified(entry.source) ||
        ip::is_multicast(entry.source) ||
        std::find(translations.begin(),
                  translations.begin() + static_cast<std::ptrdiff_t>(index),
                  entry) !=
            translations.begin() + static_cast<std::ptrdiff_t>(index))
      return false;
  }
  std::vector<MldSsmTranslation> control_program;
  try {
    control_program.assign(translations.begin(), translations.end());
  } catch (...) {
    return false;
  }

  const auto submit = [&](MldSsmProgramOperation operation,
                          const MldSsmTranslation &entry = {}) {
    auto &command = prepare(NetworkCommandKind::program_mld_ssm_translation);
    command.device = device;
    command.port.ordinal = *ordinal;
    command.mld_ssm_operation = operation;
    command.mld_ssm_translation = entry;
    command.mld_ssm_expected_entries =
        operation == MldSsmProgramOperation::begin
            ? static_cast<std::uint32_t>(translations.size())
            : 0U;
    const auto result = dispatch(command);
    return result && result->success;
  };

  if (!submit(MldSsmProgramOperation::begin))
    return false;
  for (const auto &entry : translations) {
    if (submit(MldSsmProgramOperation::add, entry))
      continue;
    static_cast<void>(submit(MldSsmProgramOperation::abort));
    return false;
  }
  if (!submit(MldSsmProgramOperation::commit)) {
    static_cast<void>(submit(MldSsmProgramOperation::abort));
    return false;
  }

  // Control updates its checkpointable projection only after forwarding has
  // atomically published the complete generation.
  router_network_[device.index]->mld_interfaces[*ordinal].ssm_translations.swap(
      control_program);
  return true;
}

bool RuntimeSupervisor::replace_mld_import_policy(
    DeviceHandle device, std::string_view port_id,
    std::span<const mld::ImportPolicyEntry> entries,
    mld::ImportPolicyAction default_action) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      entries.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;

  // Compile into detached control memory first. This validates canonical
  // prefixes, numeric ordering and terminal action before opening forwarding
  // staging. It also creates the exact checkpoint projection that will be
  // published only after the network owner acknowledges commit.
  mld::ImportPolicyProgram validator;
  if (!validator.replace(entries, default_action))
    return false;
  mld::ImportPolicyCheckpoint control_program;
  try {
    control_program = validator.checkpoint();
  } catch (const std::bad_alloc &) {
    return false;
  }

  const auto submit = [&](mld::ImportPolicyProgramOperation operation,
                          const mld::ImportPolicyEntry &entry = {}) {
    auto &command = prepare(NetworkCommandKind::program_mld_import_policy);
    command.device = device;
    command.port.ordinal = *ordinal;
    command.mld_import_policy_operation = operation;
    command.mld_import_policy_entry = entry;
    command.mld_import_policy_default_action = default_action;
    command.mld_import_policy_expected_entries =
        operation == mld::ImportPolicyProgramOperation::begin
            ? static_cast<std::uint32_t>(entries.size())
            : 0U;
    const auto result = dispatch(command);
    return result && result->success;
  };

  if (!submit(mld::ImportPolicyProgramOperation::begin))
    return false;
  for (const auto &entry : entries) {
    if (submit(mld::ImportPolicyProgramOperation::add, entry))
      continue;
    static_cast<void>(submit(mld::ImportPolicyProgramOperation::abort));
    return false;
  }
  if (!submit(mld::ImportPolicyProgramOperation::commit)) {
    static_cast<void>(submit(mld::ImportPolicyProgramOperation::abort));
    return false;
  }

  router_network_[device.index]->mld_interfaces[*ordinal].import_policy =
      std::move(control_program);
  return true;
}

} // namespace router::lab
