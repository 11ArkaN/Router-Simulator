// Control-shard checkpoint capture, validation and atomic restoration.
// RuntimeSupervisor owns the restored graph and publishes it only after validation.

#include "runtime_supervisor_internal.hpp"

namespace router::lab {

std::unique_ptr<RuntimeSupervisorCheckpoint> RuntimeSupervisor::checkpoint() {
  auto &barrier = prepare(NetworkCommandKind::prepare_checkpoint);
  const auto result = dispatch(barrier);
  if (!result || !result->success)
    return nullptr;
  auto network = network_worker_->take_prepared_checkpoint();
  if (!network)
    return nullptr;
  try {
    auto state = std::make_unique<RuntimeSupervisorCheckpoint>();
    state->devices = devices_.checkpoint();
    state->hosts = hosts_.checkpoint();
    state->switches = switches_.checkpoint();
    state->topology = topology_.checkpoint();
    state->sessions = sessions_.checkpoint();
    state->workflows = session_workflows_.checkpoint();
    state->hardware.reserve(state->devices.entries.size());
    state->control.reserve(state->devices.entries.size());
    for (const auto &device : state->devices.entries) {
      const auto *inventory = hardware(device.handle);
      const auto *control = device.handle.index < router_network_.size()
                                ? router_network_[device.handle.index].get()
                                : nullptr;
      if (!inventory || !control)
        return nullptr;
      state->hardware.emplace_back();
      inventory->checkpoint(state->hardware.back());
      // RouterControlCheckpoint contains full fixed-capacity route and RA
      // projections. Construct it directly in the reserved heap vector so the
      // one MiB Wasm stack never receives a second temporary copy.
      state->control.emplace_back();
      auto &router = state->control.back();
      router.device = device.handle;
      router.maximum_ecmp_paths = control->maximum_ecmp_paths;
      router.connected = control->connected;
      router.statics = control->statics;
      router.ipv6_connected = control->ipv6_connected;
      router.native_ipv6_addresses = control->native_ipv6_addresses;
      router.native_ipv6_connected = control->native_ipv6_connected;
      router.ipv6_statics = control->ipv6_statics;
      router.ports = control->ports;
      router.interface_admin = control->interface_admin;
      router.ies_port_owned = control->ies_port_owned;
      router.router_advertisements = control->router_advertisements;
      router.mld_interfaces = control->mld_interfaces;
      for (const auto &relay : control->dhcpv4_relays)
        if (relay)
          router.dhcpv4_relays.push_back(*relay);
      for (const auto &relay : control->dhcpv6_relays)
        if (relay)
          router.dhcpv6_relays.push_back(*relay);
      router.ies_configuration = control->ies_configuration;
      router.ies_sap_attachments = control->ies_sap_attachments;
      router.ies_ipv6_interfaces = control->ies_ipv6_interfaces;
      router.ies_ipv6_connected = control->ies_ipv6_connected;
      router.ies_dhcpv6_relays = control->ies_dhcpv6_relays;
      router.fib_generation = control->fib_generation;
      router.selected_rib = control->rib.compile(control->fib_generation);
      router.ipv6_fib_generation = control->ipv6_fib_generation;
      router.selected_ipv6_rib =
          control->ipv6_rib.compile(control->ipv6_fib_generation);
    }
    state->network = std::move(*network);
    state->next_network_command_id = next_network_command_id_;
    return state;
  } catch (const std::bad_alloc &) {
    return nullptr;
  }
}

bool checkpoint_validation::base_fib_preserved(
    const routing::FibProgram &base,
    const routing::FibProgram &selected) noexcept {
      // The route manager checkpoint owns connected and static intent. OSPF
      // routes are owned and validated by the network-plane checkpoint below,
      // so rebuilding only the base RIB cannot legitimately be byte-equal to
      // a selected FIB that contains converged dynamic routes. Require every
      // independently rebuilt base route and permit only typed OSPF additions.
      if (base.generation != selected.generation ||
          base.count > selected.count)
        return false;
      const auto equal_route = [](const auto &a, const auto &b) {
        return a.network == b.network && a.next_hop == b.next_hop &&
               a.port_ordinal == b.port_ordinal &&
               a.prefix_length == b.prefix_length &&
               a.preference == b.preference && a.metric == b.metric &&
               a.source == b.source && a.local_system == b.local_system;
      };
      const auto selected_end =
          selected.routes.begin() + selected.count;
      for (auto route = base.routes.begin();
           route != base.routes.begin() + base.count; ++route)
        if (std::find_if(selected.routes.begin(), selected_end,
                         [&](const auto &candidate) {
                           return equal_route(*route, candidate);
                         }) == selected_end)
          return false;
      return std::all_of(
          selected.routes.begin(), selected_end, [&](const auto &route) {
            return route.source == routing::RouteSource::ospf ||
                   route.source == routing::RouteSource::ospf3 ||
                   std::find_if(base.routes.begin(),
                                base.routes.begin() + base.count,
                                [&](const auto &candidate) {
                                  return equal_route(route, candidate);
                                }) != base.routes.begin() + base.count;
          });
}

bool checkpoint_validation::base_fib_preserved(
    const routing::Ipv6FibProgram &base,
    const routing::Ipv6FibProgram &selected) noexcept {
      // IPv6 follows the same ownership split as IPv4. The exact saved FIB is
      // later checked by RouterForwarder and NetworkWorker restore; this check
      // proves that protocol routes did not replace required local intent.
      if (base.generation != selected.generation ||
          base.count > selected.count)
        return false;
      const auto equal_route = [](const auto &a, const auto &b) {
        return a.network == b.network && a.next_hop == b.next_hop &&
               a.interface_id == b.interface_id &&
               a.physical_port_ordinal == b.physical_port_ordinal &&
               a.prefix_length == b.prefix_length &&
               a.preference == b.preference && a.metric == b.metric &&
               a.source == b.source;
      };
      const auto selected_end =
          selected.routes.begin() + selected.count;
      for (auto route = base.routes.begin();
           route != base.routes.begin() + base.count; ++route)
        if (std::find_if(selected.routes.begin(), selected_end,
                         [&](const auto &candidate) {
                           return equal_route(*route, candidate);
                         }) == selected_end)
          return false;
      return std::all_of(
          selected.routes.begin(), selected_end, [&](const auto &route) {
            return route.source == routing::RouteSource::ospf ||
                   route.source == routing::RouteSource::ospf3 ||
                   std::find_if(base.routes.begin(),
                                base.routes.begin() + base.count,
                                [&](const auto &candidate) {
                                  return equal_route(route, candidate);
                                }) != base.routes.begin() + base.count;
          });
}

bool RuntimeSupervisor::restore(RuntimeSupervisorCheckpoint state) {
  try {
    auto devices = std::make_unique<DeviceRegistry>();
    auto hosts = std::make_unique<HostRegistry>();
    auto switches = std::make_unique<SwitchRegistry>();
    auto topology = std::make_unique<TopologyRegistry>();
    auto sessions = std::make_unique<SessionRegistry>();
    if (!devices->restore(state.devices) || !hosts->restore(state.hosts) ||
        !switches->restore(state.switches) ||
        !topology->restore(state.topology) ||
        !sessions->restore(state.sessions))
      return false;
    for (const auto &device : state.devices.entries)
      if (hosts->find(device.node_id) || switches->find(device.node_id))
        return false;
    for (const auto &host : state.hosts.entries)
      if (switches->find(host.node_id))
        return false;
    for (const auto &session : state.sessions.entries)
      if (!devices->get(session.record.device))
        return false;
    for (const auto &link : state.topology.entries)
      for (const auto &endpoint : link.record.endpoints) {
        bool exists{};
        if (endpoint.node.kind == NodeKind::router)
          exists = devices->get(
                       {endpoint.node.index, endpoint.node.generation}) !=
                   nullptr;
        else if (endpoint.node.kind == NodeKind::host)
          exists =
              hosts->get({endpoint.node.index, endpoint.node.generation}) !=
              nullptr;
        else if (endpoint.node.kind == NodeKind::ethernet_switch)
          exists = switches->get(
                       {endpoint.node.index, endpoint.node.generation}) !=
                   nullptr;
        if (!exists)
          return false;
      }

    auto hardware = std::make_unique<decltype(hardware_)>();
    auto control = std::make_unique<decltype(router_network_)>();
    std::array<bool, device_catalog::maximum_routers> hardware_seen{};
    std::array<bool, device_catalog::maximum_routers> control_seen{};
    for (const auto &source : state.hardware) {
      const auto *device = devices->get(source.device);
      if (!device || source.device.index >= hardware_seen.size() ||
          hardware_seen[source.device.index] ||
          source.profile_id != device->profile->id)
        return false;
      auto restored = std::make_unique<RouterHardwareInventory>();
      if (!restored->restore(source))
        return false;
      (*hardware)[source.device.index] = std::move(*restored);
      hardware_seen[source.device.index] = true;
    }
    for (const auto &source : state.control) {
      if (!devices->get(source.device) ||
          source.device.index >= control_seen.size() ||
          control_seen[source.device.index] ||
          source.selected_rib.generation != source.fib_generation ||
          source.selected_rib.count > source.selected_rib.routes.size() ||
          source.selected_ipv6_rib.generation != source.ipv6_fib_generation ||
          source.selected_ipv6_rib.count >
              source.selected_ipv6_rib.routes.size() ||
          source.maximum_ecmp_paths == 0U ||
          source.maximum_ecmp_paths > device_catalog::maximum_ecmp_paths)
        return false;
      auto restored = std::make_unique<RouterNetworkState>();
      restored->connected = source.connected;
      restored->statics = source.statics;
      restored->ipv6_connected = source.ipv6_connected;
      restored->native_ipv6_addresses = source.native_ipv6_addresses;
      restored->native_ipv6_connected = source.native_ipv6_connected;
      restored->ipv6_statics = source.ipv6_statics;
      restored->maximum_ecmp_paths = source.maximum_ecmp_paths;
      restored->ports = source.ports;
      restored->interface_admin = source.interface_admin;
      restored->ies_port_owned = source.ies_port_owned;
      restored->router_advertisements = source.router_advertisements;
      restored->mld_interfaces = source.mld_interfaces;
      if (source.dhcpv4_relays.size() >
              device_catalog::maximum_ports_per_router ||
          source.dhcpv6_relays.size() >
              device_catalog::maximum_ports_per_router)
        return false;
      for (const auto &relay : source.dhcpv4_relays) {
        if (relay.physical_port_ordinal >= restored->dhcpv4_relays.size() ||
            restored->dhcpv4_relays[relay.physical_port_ordinal])
          return false;
        restored->dhcpv4_relays[relay.physical_port_ordinal] = relay;
      }
      for (const auto &relay : source.dhcpv6_relays) {
        if (relay.physical_port_ordinal >= restored->dhcpv6_relays.size() ||
            restored->dhcpv6_relays[relay.physical_port_ordinal])
          return false;
        restored->dhcpv6_relays[relay.physical_port_ordinal] = relay;
      }
      restored->ies_configuration = source.ies_configuration;
      restored->ies_sap_attachments = source.ies_sap_attachments;
      restored->ies_ipv6_interfaces = source.ies_ipv6_interfaces;
      restored->ies_ipv6_connected = source.ies_ipv6_connected;
      restored->ies_dhcpv6_relays = source.ies_dhcpv6_relays;
      restored->fib_generation = source.fib_generation;
      restored->ipv6_fib_generation = source.ipv6_fib_generation;
      service::SapForwardingTable service_validation;
      dhcpv6::RelayAgent service_relay_validation;
      if (service::validate(source.ies_configuration) !=
              service::ValidationError::none ||
          service_validation.replace(source.ies_sap_attachments,
                                     source.ies_ipv6_interfaces) !=
              service::SapProgramStatus::accepted ||
          !service_relay_validation.restore(source.ies_dhcpv6_relays))
        return false;
      for (std::size_t ordinal = 0; ordinal < source.ies_port_owned.size();
           ++ordinal) {
        if (!source.ies_port_owned[ordinal])
          continue;
        // A serialized forwarding owner must be backed by both the physical
        // projection and the service configuration object that created it.
        // Otherwise removing a native interface after restore could preserve
        // an orphan port indefinitely.
        if (!source.ports[ordinal].configured ||
            std::none_of(source.ies_configuration.ports.begin(),
                         source.ies_configuration.ports.end(),
                         [ordinal](const auto &port) {
                           return port.coordinate.ordinal == ordinal;
                         }))
          return false;
      }
      auto advertisement_validation =
          std::make_unique<Ipv6RouterAdvertisementTable>();
      for (std::size_t ordinal = 0;
           ordinal < source.router_advertisements.size(); ++ordinal) {
        const auto &advertisement = source.router_advertisements[ordinal];
        if (!advertisement.configured) {
          if (advertisement.enabled)
            return false;
          continue;
        }
        if (!source.ports[ordinal].configured ||
            !source.ports[ordinal].ipv6_configured ||
            !advertisement_validation->configure(
                static_cast<std::uint16_t>(ordinal), false,
                advertisement.config))
          return false;
      }
      for (std::size_t ordinal = 0; ordinal < source.mld_interfaces.size();
           ++ordinal) {
        const auto &mld = source.mld_interfaces[ordinal];
        if (!mld.configured)
          continue;
        const auto &port = source.ports[ordinal];
        if (!port.configured || !port.ipv6_configured ||
            mld.configuration.port_ordinal != ordinal ||
            mld.configuration.link_local_address != port.ipv6_link_local ||
            !MldRouterInterface{}.configure(mld.configuration))
          return false;
        if (mld.ssm_translations.size() >
            device_catalog::mld_router_group_sources_per_interface)
          return false;
        for (std::size_t index = 0; index < mld.ssm_translations.size();
             ++index) {
          const auto &translation = mld.ssm_translations[index];
          if (!ip::is_multicast(translation.start) ||
              !ip::is_multicast(translation.end) ||
              translation.end < translation.start ||
              ip::is_unspecified(translation.source) ||
              ip::is_multicast(translation.source) ||
              std::find(mld.ssm_translations.begin(),
                        mld.ssm_translations.begin() +
                            static_cast<std::ptrdiff_t>(index),
                        translation) != mld.ssm_translations.begin() +
                                            static_cast<std::ptrdiff_t>(index))
            return false;
        }
      }
      std::vector<dhcpv4::RelayInterfaceConfiguration>
          dhcpv4_relay_validation_values;
      for (const auto &relay : source.dhcpv4_relays) {
        const auto ordinal = relay.physical_port_ordinal;
        if (ordinal >= source.ports.size())
          return false;
        const auto &port = source.ports[ordinal];
        const packet::Ipv4 port_address{
            static_cast<std::uint8_t>(port.address >> 24U),
            static_cast<std::uint8_t>(port.address >> 16U),
            static_cast<std::uint8_t>(port.address >> 8U),
            static_cast<std::uint8_t>(port.address)};
        dhcpv4::RelayAgent validation;
        if (!port.configured || !port.ipv4_configured ||
            relay.interface_id != physical_interface_id(ordinal) ||
            relay.physical_port_ordinal != ordinal ||
            relay.relay.gateway_address != port_address ||
            !validation.configure(relay.relay))
          return false;
        for (const auto &prior : dhcpv4_relay_validation_values)
          if (prior.interface_id == relay.interface_id ||
              prior.relay.gateway_address == relay.relay.gateway_address)
            return false;
        dhcpv4_relay_validation_values.push_back(relay);
      }
      std::vector<dhcpv6::RelayInterfaceConfig> relay_validation_values;
      for (const auto &relay : source.dhcpv6_relays) {
        const auto ordinal = relay.physical_port_ordinal;
        if (ordinal >= source.ports.size())
          return false;
        const auto &port = source.ports[ordinal];
        if (!port.configured || !port.ipv6_configured ||
            relay.interface_id == 0U || relay.physical_port_ordinal != ordinal)
          return false;
        relay_validation_values.push_back(relay);
      }
      dhcpv6::RelayAgent relay_validation;
      if (!relay_validation.restore(relay_validation_values))
        return false;
      static_cast<void>(
          restored->rib.rebuild(restored->connected, restored->statics, {},
                                restored->maximum_ecmp_paths));
      if (!restored->rib.last_rebuild_valid() ||
          !checkpoint_validation::base_fib_preserved(
              restored->rib.compile(source.fib_generation),
              source.selected_rib))
        return false;
      static_cast<void>(restored->ipv6_rib.rebuild(
          restored->native_ipv6_connected, restored->ipv6_statics,
          restored->ies_ipv6_connected, {},
          restored->maximum_ecmp_paths));
      if (!restored->ipv6_rib.last_rebuild_valid() ||
          !checkpoint_validation::base_fib_preserved(
              restored->ipv6_rib.compile(source.ipv6_fib_generation),
              source.selected_ipv6_rib))
        return false;
      RouterForwarderCheckpoint forwarding_validation;
      forwarding_validation.fib = source.selected_rib;
      forwarding_validation.ipv6_fib = source.selected_ipv6_rib;
      // Route age vectors are members of the selected FIB generation. The
      // control-only validator has no operational installation history, so a
      // zero age is the sole truthful synthetic value for every selected row.
      forwarding_validation.ipv4_route_ages_seconds.assign(
          forwarding_validation.fib.count, 0U);
      forwarding_validation.ipv6_route_ages_seconds.assign(
          forwarding_validation.ipv6_fib.count, 0U);
      forwarding_validation.sap_attachments = source.ies_sap_attachments;
      forwarding_validation.service_ipv6_interfaces =
          source.ies_ipv6_interfaces;
      forwarding_validation.native_ipv6_addresses =
          source.native_ipv6_addresses;
      for (const auto &port : source.ports)
        if (port.configured) {
          forwarding_validation.ports.push_back(port);
          // Validation uses a minimal synthetic forwarding image rather than
          // the live network checkpoint. Every configured interface still
          // requires independent zero-valued ICMPv4 and ICMPv6 rows because
          // restore rejects counters detached from physical inventory.
          forwarding_validation.icmpv4_interface_statistics.push_back(
              {.port_ordinal = port.ordinal});
          forwarding_validation.icmpv6_interface_statistics.push_back(
              {.port_ordinal = port.ordinal});
          if (port.ipv6_configured) {
            // The synthetic image validates control intent only, but the
            // forwarding checkpoint contract also requires one operational
            // ReachableTime variable per IPv6 interface. Use a canonical
            // in-range sample and nonzero continuation state. Live random
            // state is validated separately in state.network below.
            forwarding_validation.ipv6_reachable_times.push_back(
                {.port_ordinal = port.ordinal,
                 .base_milliseconds = port.nd_reachable_time_milliseconds,
                 .effective_milliseconds = port.nd_reachable_time_milliseconds,
                 .random_state = 1U,
                 .remaining_refresh_nanoseconds = 0});
          }
        }
      if (!RouterForwarder::validate_checkpoint(forwarding_validation))
        return false;
      (*control)[source.device.index] = std::move(restored);
      control_seen[source.device.index] = true;
    }
    for (const auto &device : state.devices.entries)
      if (!hardware_seen[device.handle.index] ||
          !control_seen[device.handle.index])
        return false;

    if (state.network.routers.size() != state.devices.entries.size() ||
        state.network.hosts.size() != state.hosts.entries.size() ||
        state.network.switches.size() != state.switches.entries.size())
      return false;
    for (const auto &router : state.network.routers) {
      if (!devices->get(router.device) ||
          router.device.index >= control->size() ||
          !(*control)[router.device.index])
        return false;
      const auto &intent = *(*control)[router.device.index];
      if (router.forwarding.sap_attachments != intent.ies_sap_attachments)
        return false;
      if (router.forwarding.service_ipv6_interfaces !=
          intent.ies_ipv6_interfaces)
        return false;
      // Control preserves operator insertion order because that order is part
      // of configuration presentation. The forwarding owner deliberately
      // canonicalizes the same generation by interface, primary preference and
      // address for contiguous packet-path lookup. Comparing the two vectors
      // byte-for-byte therefore rejects a valid multi-interface router merely
      // because the owners use different orderings. Reuse the forwarding
      // table's atomic validator and canonicalizer before comparing values, so
      // malformed records are still rejected without requiring identical
      // presentation order across ownership domains.
      RouterIpv6AddressTable canonical_addresses;
      if (canonical_addresses.program(intent.native_ipv6_addresses) !=
              RouterIpv6AddressProgramStatus::accepted ||
          router.forwarding.native_ipv6_addresses.size() !=
              canonical_addresses.records().size() ||
          !std::equal(router.forwarding.native_ipv6_addresses.begin(),
                      router.forwarding.native_ipv6_addresses.end(),
                      canonical_addresses.records().begin()))
        return false;
      for (const auto &relay : intent.ies_dhcpv6_relays)
        if (std::find(router.forwarding.dhcpv6_relay_interfaces.begin(),
                      router.forwarding.dhcpv6_relay_interfaces.end(),
                      relay) == router.forwarding.dhcpv6_relay_interfaces.end())
          return false;
      const auto intended_dhcpv4_relays = static_cast<std::size_t>(std::count_if(
          intent.dhcpv4_relays.begin(), intent.dhcpv4_relays.end(),
          [](const auto &relay) { return relay.has_value(); }));
      if (router.forwarding.dhcpv4_relay_interfaces.size() !=
          intended_dhcpv4_relays)
        return false;
      for (const auto &relay : intent.dhcpv4_relays)
        if (relay &&
            std::find(router.forwarding.dhcpv4_relay_interfaces.begin(),
                      router.forwarding.dhcpv4_relay_interfaces.end(),
                      *relay) ==
                router.forwarding.dhcpv4_relay_interfaces.end())
          return false;
    }
    for (const auto &host : state.network.hosts)
      if (!hosts->get(host.host))
        return false;
    for (const auto &saved : state.network.switches) {
      const auto *record = switches->get(saved.handle);
      const auto profile_index =
          record ? device_catalog::ethernet_switch_profile_index(
                       record->profile->id)
                 : std::nullopt;
      if (!record || !profile_index ||
          *profile_index != saved.profile_index ||
          saved.forwarding.ports.size() != record->ports.size())
        return false;
      for (std::size_t port{}; port < record->ports.size(); ++port) {
        const auto &intent = record->ports[port];
        const auto &operational =
            saved.forwarding.ports[port].configuration;
        if (!saved.forwarding.ports[port].configured ||
            intent.speed_mbps != operational.speed_mbps ||
            intent.mtu != operational.mtu ||
            intent.admin_enabled != operational.admin_enabled)
          return false;
      }
    }
    for (const auto &workflow : state.workflows.routers)
      if (!devices->get(workflow.device))
        return false;

    SessionWorkflowController workflows{*sessions};
    if (!workflows.restore(state.workflows) ||
        !network_worker_->stage_restore(std::move(state.network)))
      return false;
    auto &restore_command = prepare(NetworkCommandKind::restore_checkpoint);
    const auto network_result = dispatch(restore_command);
    if (!network_result || !network_result->success) {
      network_worker_->cancel_staged_restore();
      return false;
    }

    // NetworkPlane intentionally reconstructs route managers without a second
    // checkpoint copy of control-owned policy, connected routes or static
    // intent. Republish those already validated values now. The restored OSPF
    // owner independently republishes its LSDB-derived generation; whichever
    // arrives first is retained, and the second input triggers one complete
    // RIB selection. Without this handoff, a browser reload could restore a
    // Full adjacency and 34 calculated routes while leaving the manager
    // permanently unconfigured and the forwarding table empty.
    //
    // Network restore above is the owner commit point. Every command below is
    // infallible for the validated, preallocated records staged in `control`;
    // failure is therefore an internal invariant violation, just like a
    // post-swap forwarder restore failure inside NetworkPlane.
    for (const auto &device : state.devices.entries) {
      const auto &router = (*control)[device.handle.index];
      if (!router)
        std::terminate();
      auto &policy = prepare(NetworkCommandKind::program_route_policy);
      policy.device = device.handle;
      policy.fib =
          RoutePolicyProgram{.ipv4_statics = router->statics,
                             .ipv6_statics = router->ipv6_statics,
                             .maximum_ecmp_paths =
                                 router->maximum_ecmp_paths};
      const auto policy_result = dispatch(policy);
      if (!policy_result || !policy_result->success)
        std::terminate();

      auto &ipv4 = prepare(NetworkCommandKind::program_fib);
      ipv4.device = device.handle;
      ipv4.fib = router->rib.compile(router->fib_generation);
      const auto ipv4_result = dispatch(ipv4);
      if (!ipv4_result || !ipv4_result->success)
        std::terminate();

      auto &ipv6 = prepare(NetworkCommandKind::program_ipv6_fib);
      ipv6.device = device.handle;
      ipv6.fib =
          router->ipv6_rib.compile(router->ipv6_fib_generation);
      const auto ipv6_result = dispatch(ipv6);
      if (!ipv6_result || !ipv6_result->success)
        std::terminate();
    }

    // All allocating and fallible work completed before this commit. Registry
    // object addresses stay stable, preserving the workflow controller's
    // reference to sessions_ while their validated contents are replaced.
    devices_ = std::move(*devices);
    hosts_ = std::move(*hosts);
    switches_ = std::move(*switches);
    topology_ = std::move(*topology);
    sessions_ = std::move(*sessions);
    for (std::size_t index = 0; index < hardware_.size(); ++index) {
      hardware_[index] = std::move((*hardware)[index]);
      router_network_[index] = std::move((*control)[index]);
    }
    session_workflows_.swap_state(workflows);
    next_network_command_id_ =
        std::max(next_network_command_id_, state.next_network_command_id);
    return true;
  } catch (const std::bad_alloc &) {
    network_worker_->cancel_staged_restore();
    return false;
  }
}

} // namespace router::lab
