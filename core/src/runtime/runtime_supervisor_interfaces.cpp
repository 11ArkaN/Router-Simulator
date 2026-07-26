// Control-shard routed-interface and protocol configuration. RuntimeSupervisor owns
// intent and publishes immutable projections toward forwarding and protocol shards.

#include "runtime_supervisor_internal.hpp"

namespace router::lab {

bool RuntimeSupervisor::configure_interface(
    DeviceHandle device, std::string_view port_id, packet::Mac mac,
    std::uint32_t address, std::uint8_t prefix_length, bool admin_enabled,
    std::uint32_t arp_timeout_seconds,
    std::uint16_t arp_retry_deciseconds) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U ||
      arp_timeout_seconds > device_catalog::arp_timeout_maximum_seconds ||
      arp_retry_deciseconds < device_catalog::arp_retry_minimum_deciseconds ||
      arp_retry_deciseconds > device_catalog::arp_retry_maximum_deciseconds)
    return false;
  const auto ordinal_value = inventory->coordinate_ordinal(port_id);
  const auto *physical = inventory->find(port_id);
  if (!ordinal_value || !physical || !physical->speed_mbps)
    return false;
  auto &network = *router_network_[device.index];
  const auto ordinal = *ordinal_value;
  // The interface key is the stable physical ordinal. Removing its MDA leaves
  // control intent in this slot while forwarding operational state becomes
  // down. IPv4 and IPv6 are leaves of one routed interface. Updating one family
  // must preserve the other family's addresses and ND state projection.
  auto &port = network.ports[ordinal];
  port.configured = true;
  port.operational = false;
  port.ordinal = ordinal;
  port.mtu = physical->mtu;
  port.address = address;
  port.network = address & routing::prefix_mask(prefix_length);
  port.speed_mbps = physical->speed_mbps;
  port.prefix_length = prefix_length;
  port.mac = mac;
  port.arp_timeout_seconds = arp_timeout_seconds;
  port.arp_retry_deciseconds = arp_retry_deciseconds;
  port.ipv4_configured = true;
  network.interface_admin[ordinal] = admin_enabled;
  network.connected[ordinal] = {.configured = true,
                                .operational = false,
                                .network = address &
                                           routing::prefix_mask(prefix_length),
                                .port_ordinal = ordinal,
                                .prefix_length = prefix_length};
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_system_interface(
    DeviceHandle device, std::uint32_t address, bool admin_enabled) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  // Zero, multicast and the limited broadcast value cannot identify a local
  // unicast endpoint. The /32 length is structural in this API, so callers
  // cannot accidentally create a connected subnet without a physical medium.
  const bool multicast = (address & 0xf0000000U) == 0xe0000000U;
  if (!address || address == 0xffffffffU || multicast)
    return false;

  auto &state = *router_network_[device.index];
  auto &system = state.connected[routing::system_ipv4_connected_index];
  system = {.configured = true,
            .operational = admin_enabled,
            .network = address,
            // The ordinal is deliberately meaningless for a local route. The
            // local_system discriminator prevents every consumer from using it.
            .port_ordinal = 0U,
            .prefix_length = 32U,
            .local_system = true};
  rebuild_routes(device);
  return state.rib.last_rebuild_valid();
}

bool RuntimeSupervisor::remove_system_interface(DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &state = *router_network_[device.index];
  auto &system = state.connected[routing::system_ipv4_connected_index];
  if (!system.configured || !system.local_system)
    return false;
  system = {};
  rebuild_routes(device);
  return state.rib.last_rebuild_valid();
}

bool RuntimeSupervisor::configure_system_ipv6_addresses(
    DeviceHandle device, std::span<const RouterIpv6Address> addresses,
    bool admin_enabled) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      addresses.size() > device_catalog::network_interface_ip_addresses)
    return false;
  if (std::any_of(addresses.begin(), addresses.end(), [](const auto &entry) {
        return entry.interface_id != system_interface_id ||
               entry.port_ordinal != system_interface_port_ordinal ||
               entry.prefix_length != ip::ipv6_address_bits ||
               ip::is_unspecified(entry.address) ||
               ip::is_multicast(entry.address) ||
               entry.network != entry.address;
      }))
    return false;

  auto &state = *router_network_[device.index];
  try {
    auto candidate_addresses = state.native_ipv6_addresses;
    std::erase_if(candidate_addresses, [](const auto &entry) {
      return entry.interface_id == system_interface_id;
    });
    candidate_addresses.insert(candidate_addresses.end(), addresses.begin(),
                               addresses.end());

    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    if (!build_native_ipv6_connected(candidate_addresses, state.ports,
                                     admin_enabled, candidate_connected))
      return false;
    auto candidate_rib = std::unique_ptr<routing::Ipv6RouteTable>{
        new (std::nothrow) routing::Ipv6RouteTable{}};
    if (!candidate_rib)
      return false;
    static_cast<void>(candidate_rib->rebuild(
        candidate_connected, state.ipv6_statics, state.ies_ipv6_connected,
        {}, state.maximum_ecmp_paths));
    if (!candidate_rib->last_rebuild_valid() ||
        !program_ipv6_address_generation(device, candidate_addresses))
      return false;

    state.native_ipv6_addresses.swap(candidate_addresses);
    state.native_ipv6_connected.swap(candidate_connected);
    rebuild_routes(device);
    return state.ipv6_rib.last_rebuild_valid();
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RuntimeSupervisor::configure_ipv6_interface(
    DeviceHandle device, std::string_view port_id, packet::Mac mac,
    const packet::Ipv6 &address, std::uint8_t prefix_length,
    const packet::Ipv6 &link_local, bool admin_enabled) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits ||
      ip::is_unspecified(address) || ip::is_multicast(address) ||
      !ip::is_link_local(link_local))
    return false;
  const auto ordinal_value = inventory->coordinate_ordinal(port_id);
  const auto *physical = inventory->find(port_id);
  if (!ordinal_value || !physical || !physical->speed_mbps ||
      physical->mtu < packet::ipv6_minimum_ethernet_mtu)
    return false;

  auto &network = *router_network_[device.index];
  const auto ordinal = *ordinal_value;
  auto candidate_port = network.ports[ordinal];
  const bool previously_configured = candidate_port.configured;
  if (!previously_configured)
    candidate_port.ipv4_configured = false;
  candidate_port.configured = true;
  candidate_port.operational = false;
  candidate_port.ordinal = ordinal;
  candidate_port.mtu = physical->mtu;
  candidate_port.speed_mbps = physical->speed_mbps;
  candidate_port.mac = mac;
  candidate_port.ipv6_configured = true;
  candidate_port.ipv6_address = address;
  candidate_port.ipv6_network = ip::mask(address, prefix_length);
  candidate_port.ipv6_link_local = link_local;
  candidate_port.ipv6_prefix_length = prefix_length;
  const routing::Ipv6ConnectedInput selected_connected{
      .configured = true,
      .operational = false,
      .network = candidate_port.ipv6_network,
      .interface_id = physical_interface_id(ordinal),
      .physical_port_ordinal = ordinal,
      .prefix_length = prefix_length};
  try {
    auto candidate_addresses = network.native_ipv6_addresses;
    candidate_addresses.erase(
        std::remove_if(candidate_addresses.begin(), candidate_addresses.end(),
                       [&](const auto &configured) {
                         return configured.interface_id ==
                                physical_interface_id(ordinal);
                       }),
        candidate_addresses.end());
    candidate_addresses.push_back(
        {.address = address,
         .network = candidate_port.ipv6_network,
         .interface_id = physical_interface_id(ordinal),
         .primary_preference = 0U,
         .port_ordinal = ordinal,
         .prefix_length = prefix_length});
    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    const bool system_operational = std::any_of(
        network.native_ipv6_connected.begin(),
        network.native_ipv6_connected.end(), [](const auto &entry) {
          return entry.interface_id == system_interface_id &&
                 entry.operational;
        });
    if (!build_native_ipv6_connected(candidate_addresses, network.ports,
                                     system_operational,
                                     candidate_connected))
      return false;
    for (auto &connected : candidate_connected)
      if (connected.interface_id == physical_interface_id(ordinal))
        connected.operational = false;

    // Allocation and derivation are complete. Publish all control-owned
    // fields together before reconciliation emits the forwarding generation.
    network.ports[ordinal] = candidate_port;
    network.interface_admin[ordinal] = admin_enabled;
    network.ipv6_connected[ordinal] = selected_connected;
    network.native_ipv6_addresses.swap(candidate_addresses);
    network.native_ipv6_connected.swap(candidate_connected);
  } catch (const std::bad_alloc &) {
    return false;
  }
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv6_address(
    DeviceHandle device, std::string_view port_id, const packet::Ipv6 &address,
    std::uint8_t prefix_length, std::uint32_t primary_preference,
    bool duplicate_address_detection,
    std::optional<std::uint32_t> tag) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits ||
      ip::is_unspecified(address) || ip::is_multicast(address) ||
      ip::is_link_local(address))
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  const auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  try {
    auto candidate_addresses = state.native_ipv6_addresses;
    auto existing = std::find_if(
        candidate_addresses.begin(), candidate_addresses.end(),
        [&](const auto &configured) { return configured.address == address; });
    if (existing != candidate_addresses.end() &&
        existing->interface_id != physical_interface_id(*ordinal))
      return false;
    const auto on_interface = static_cast<std::size_t>(std::count_if(
        candidate_addresses.begin(), candidate_addresses.end(),
        [&](const auto &configured) {
          return configured.interface_id == physical_interface_id(*ordinal);
        }));
    // The documented sixteen-address ceiling is shared with IPv4. Updating an
    // existing record consumes no resource; a new IPv6 record accounts for the
    // native IPv4 address already present on the same routed interface.
    if (existing == candidate_addresses.end() &&
        on_interface + (port.ipv4_configured ? 1U : 0U) >=
            device_catalog::network_interface_ip_addresses)
      return false;
    const RouterIpv6Address replacement{
        .address = address,
        .network = ip::mask(address, prefix_length),
        .interface_id = physical_interface_id(*ordinal),
        .primary_preference = primary_preference,
        .tag = tag.value_or(0U),
        .port_ordinal = *ordinal,
        .prefix_length = prefix_length,
        .duplicate_address_detection = duplicate_address_detection,
        .tag_configured = tag.has_value()};
    if (existing == candidate_addresses.end())
      candidate_addresses.push_back(replacement);
    else
      *existing = replacement;

    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    const bool system_operational = std::any_of(
        state.native_ipv6_connected.begin(),
        state.native_ipv6_connected.end(), [](const auto &entry) {
          return entry.interface_id == system_interface_id &&
                 entry.operational;
        });
    if (!build_native_ipv6_connected(candidate_addresses, state.ports,
                                     system_operational,
                                     candidate_connected))
      return false;
    auto candidate_rib = std::unique_ptr<routing::Ipv6RouteTable>{
        new (std::nothrow) routing::Ipv6RouteTable{}};
    if (!candidate_rib)
      return false;
    static_cast<void>(candidate_rib->rebuild(
        candidate_connected, state.ipv6_statics, state.ies_ipv6_connected));
    if (!candidate_rib->last_rebuild_valid() ||
        !program_ipv6_address_generation(device, candidate_addresses))
      return false;
    state.native_ipv6_addresses.swap(candidate_addresses);
    state.native_ipv6_connected.swap(candidate_connected);

    // The lowest preference cache is updated only after the complete address
    // generation is live. A leaf edit can never expose a port primary that the
    // forwarding table rejected.
    const RouterIpv6Address *primary{};
    for (const auto &configured : state.native_ipv6_addresses)
      if (configured.interface_id == physical_interface_id(*ordinal) &&
          (!primary ||
           configured.primary_preference < primary->primary_preference ||
           (configured.primary_preference == primary->primary_preference &&
            configured.address < primary->address)))
        primary = &configured;
    if (primary) {
      state.ports[*ordinal].ipv6_address = primary->address;
      state.ports[*ordinal].ipv6_network = primary->network;
      state.ports[*ordinal].ipv6_prefix_length = primary->prefix_length;
    }
    rebuild_routes(device);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RuntimeSupervisor::remove_ipv6_address(
    DeviceHandle device, std::string_view port_id,
    const packet::Ipv6 &address) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  try {
    auto candidate = state.native_ipv6_addresses;
    const auto removed = std::erase_if(candidate, [&](const auto &configured) {
      return configured.interface_id == physical_interface_id(*ordinal) &&
             configured.address == address;
    });
    if (removed != 1U || std::none_of(candidate.begin(), candidate.end(),
                                      [&](const auto &value) {
                                        return value.interface_id ==
                                               physical_interface_id(*ordinal);
                                      }))
      return false;
    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    const bool system_operational = std::any_of(
        state.native_ipv6_connected.begin(),
        state.native_ipv6_connected.end(), [](const auto &entry) {
          return entry.interface_id == system_interface_id &&
                 entry.operational;
        });
    if (!build_native_ipv6_connected(candidate, state.ports,
                                     system_operational,
                                     candidate_connected))
      return false;
    auto candidate_rib = std::unique_ptr<routing::Ipv6RouteTable>{
        new (std::nothrow) routing::Ipv6RouteTable{}};
    if (!candidate_rib)
      return false;
    static_cast<void>(candidate_rib->rebuild(
        candidate_connected, state.ipv6_statics, state.ies_ipv6_connected));
    if (!candidate_rib->last_rebuild_valid() ||
        !program_ipv6_address_generation(device, candidate))
      return false;
    state.native_ipv6_addresses.swap(candidate);
    state.native_ipv6_connected.swap(candidate_connected);
    const auto *primary = [&]() -> const RouterIpv6Address * {
      const RouterIpv6Address *selected{};
      for (const auto &configured : state.native_ipv6_addresses)
        if (configured.interface_id == physical_interface_id(*ordinal) &&
            (!selected ||
             configured.primary_preference < selected->primary_preference ||
             (configured.primary_preference == selected->primary_preference &&
              configured.address < selected->address)))
          selected = &configured;
      return selected;
    }();
    state.ports[*ordinal].ipv6_address = primary->address;
    state.ports[*ordinal].ipv6_network = primary->network;
    state.ports[*ordinal].ipv6_prefix_length = primary->prefix_length;
    rebuild_routes(device);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RuntimeSupervisor::remove_ipv6_interface(
    DeviceHandle device, std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  // RA is an IPv6-interface child. Remove the forwarding-owned timer before
  // clearing the address family so no advertisement can be emitted between
  // the two owner turns. Failure leaves every control-owned field unchanged.
  if (state.router_advertisements[*ordinal].configured) {
    auto &remove_ra = prepare(NetworkCommandKind::remove_router_advertisement);
    remove_ra.device = device;
    remove_ra.port.ordinal = *ordinal;
    const auto result = dispatch(remove_ra);
    if (!result || !result->success)
      return false;
    state.router_advertisements[*ordinal] = {};
  }
  // MLD is also bound to the routed IPv6 interface, but it is a distinct
  // protocol context in SR OS. Withdraw it explicitly before its source
  // link-local address disappears. This prevents a final Query from being
  // emitted with an address that control has already removed.
  if (state.mld_interfaces[*ordinal].configured) {
    auto &remove_mld = prepare(NetworkCommandKind::remove_mld_interface);
    remove_mld.device = device;
    remove_mld.port.ordinal = *ordinal;
    const auto result = dispatch(remove_mld);
    if (!result || !result->success)
      return false;
    state.mld_interfaces[*ordinal] = {};
  }
  if (state.dhcpv6_relays[*ordinal] && !remove_dhcpv6_relay(device, port_id))
    return false;
  port.ipv6_configured = false;
  port.ipv6_address = {};
  port.ipv6_network = {};
  port.ipv6_link_local = {};
  port.ipv6_prefix_length = 0;
  port.ipv6_unsolicited_learning = Ipv6UnsolicitedLearning::none;
  port.nd_reachable_time_milliseconds = static_cast<std::uint32_t>(
      device_catalog::nd_base_reachable_time.count());
  port.nd_stale_time_seconds = device_catalog::nd_default_stale_time_seconds;
  port.ipv6_proactive_refresh = Ipv6UnsolicitedLearning::none;
  port.ipv6_neighbor_limit = 0U;
  port.ipv6_neighbor_limit_threshold_percent =
      device_catalog::nd_default_neighbor_limit_threshold_percent;
  port.ipv6_neighbor_limit_configured = false;
  port.ipv6_neighbor_limit_log_only = false;
  state.ipv6_connected[*ordinal] = {};
  std::erase_if(state.native_ipv6_addresses, [&](const auto &configured) {
    return configured.interface_id == physical_interface_id(*ordinal);
  });
  std::erase_if(state.native_ipv6_connected, [&](const auto &configured) {
    return configured.interface_id == physical_interface_id(*ordinal);
  });
  if (!port.ipv4_configured && !state.ies_port_owned[*ordinal]) {
    port = {};
    state.interface_admin[*ordinal] = false;
    auto &remove = prepare(NetworkCommandKind::remove_port);
    remove.device = device;
    remove.port.ordinal = *ordinal;
    const auto result = dispatch(remove);
    rebuild_routes(device);
    return result && result->success;
  }
  if (!port.ipv4_configured) {
    // Removing the final native address family must not remove a physical
    // access port still owned by IES. A service interface carries its own MAC,
    // so retaining the former native source MAC here would create an identity
    // that no longer exists in configuration.
    port.mac = {};
    state.interface_admin[*ordinal] = false;
  }
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv6_redirects(
    DeviceHandle device, std::string_view port_id, bool enabled,
    std::uint16_t maximum, std::uint16_t interval_seconds) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      maximum < device_catalog::icmp6_redirect_minimum_maximum ||
      maximum > device_catalog::icmp6_redirect_maximum_maximum ||
      interval_seconds <
          device_catalog::icmp6_redirect_minimum_interval.count() ||
      interval_seconds >
          device_catalog::icmp6_redirect_maximum_interval.count())
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  // The control owner changes the complete tuple before one refresh command.
  // RouterForwarder validates it again and resets only the affected port's
  // rate window, while an unchanged IPv6 identity keeps its completed DAD.
  port.icmp6_redirects_enabled = enabled;
  port.icmp6_redirect_maximum = maximum;
  port.icmp6_redirect_interval_seconds = interval_seconds;
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv4_redirects(
    DeviceHandle device, std::string_view port_id, bool enabled,
    std::uint16_t maximum, std::uint16_t interval_seconds) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      maximum < device_catalog::icmp_redirect_minimum_maximum ||
      maximum > device_catalog::icmp_redirect_maximum_maximum ||
      interval_seconds <
          device_catalog::icmp_redirect_minimum_interval.count() ||
      interval_seconds > device_catalog::icmp_redirect_maximum_interval.count())
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv4_configured)
    return false;

  // The complete policy tuple crosses the existing whole-port projection.
  // No separate mutable limiter state is exposed to the control shard.
  port.icmp_redirects_enabled = enabled;
  port.icmp_redirect_maximum = maximum;
  port.icmp_redirect_interval_seconds = interval_seconds;
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv6_neighbor_policy(
    DeviceHandle device, std::string_view port_id,
    std::uint32_t reachable_time_seconds, std::uint32_t stale_time_seconds,
    Ipv6UnsolicitedLearning unsolicited_learning,
    Ipv6UnsolicitedLearning proactive_refresh, bool limit_configured,
    std::uint32_t limit, bool limit_log_only,
    std::uint8_t limit_threshold_percent) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      reachable_time_seconds <
          device_catalog::nd_minimum_reachable_time_seconds ||
      reachable_time_seconds >
          device_catalog::nd_maximum_reachable_time_seconds ||
      stale_time_seconds < device_catalog::nd_minimum_stale_time_seconds ||
      stale_time_seconds > device_catalog::nd_maximum_stale_time_seconds ||
      unsolicited_learning > Ipv6UnsolicitedLearning::both ||
      proactive_refresh > Ipv6UnsolicitedLearning::both ||
      limit > device_catalog::nd_maximum_neighbor_limit ||
      limit_threshold_percent > 100U ||
      (!limit_configured &&
       (limit != 0U || limit_log_only ||
        limit_threshold_percent !=
            device_catalog::nd_default_neighbor_limit_threshold_percent)))
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;
  // The complete policy tuple is replaced before one forwarding refresh.
  // Packet processing can therefore see either the old or new settings but
  // never a reachable timer paired with stale limit metadata from another
  // configuration generation.
  port.nd_reachable_time_milliseconds = reachable_time_seconds * 1000U;
  port.nd_stale_time_seconds = stale_time_seconds;
  port.ipv6_unsolicited_learning = unsolicited_learning;
  port.ipv6_proactive_refresh = proactive_refresh;
  port.ipv6_neighbor_limit_configured = limit_configured;
  port.ipv6_neighbor_limit = limit;
  port.ipv6_neighbor_limit_log_only = limit_log_only;
  port.ipv6_neighbor_limit_threshold_percent = limit_threshold_percent;
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_router_advertisement(
    DeviceHandle device, std::string_view port_id, bool enabled,
    const packet::nd::RouterAdvertisementConfig &config) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  if (!state.ports[*ordinal].configured ||
      !state.ports[*ordinal].ipv6_configured)
    return false;

  // Forwarding validates wire fields and interval relationships before the
  // control owner publishes intent. A rejected command leaves the prior
  // configuration untouched in both owners.
  auto &command = prepare(NetworkCommandKind::configure_router_advertisement);
  command.device = device;
  command.fib = RouterAdvertisementProgram{.device = device,
                                           .config = config,
                                           .port_ordinal = *ordinal,
                                           .enabled = enabled};
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.router_advertisements[*ordinal] = {
      .config = config, .configured = true, .enabled = enabled};
  return true;
}

bool RuntimeSupervisor::remove_router_advertisement(
    DeviceHandle device, std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  if (!state.router_advertisements[*ordinal].configured)
    return false;

  // The forwarding owner acknowledges removal before control drops its copy.
  // This ordering makes a failed transaction observable and checkpoint-safe.
  auto &command = prepare(NetworkCommandKind::remove_router_advertisement);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.router_advertisements[*ordinal] = {};
  return true;
}

bool RuntimeSupervisor::configure_mld_interface(
    DeviceHandle device, std::string_view port_id,
    const MldRouterConfiguration &configuration) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  const auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv6_configured ||
      !ip::is_link_local(port.ipv6_link_local))
    return false;

  // Interface identity is owned by the inventory and IPv6 interface owners.
  // Replace both derived fields so a caller cannot aim MLD at another port or
  // advertise a fabricated Querier address. Timer, version and admin intent
  // remain caller supplied and are validated by MldRouterInterface.
  auto resolved = configuration;
  resolved.port_ordinal = *ordinal;
  resolved.link_local_address = port.ipv6_link_local;
  auto &command = prepare(NetworkCommandKind::configure_mld_interface);
  command.device = device;
  command.fib =
      MldInterfaceProgram{.device = device, .configuration = resolved};
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.mld_interfaces[*ordinal] = {.configuration = resolved,
                                    .ssm_translations = {},
                                    .import_policy = {},
                                    .configured = true};
  return true;
}

bool RuntimeSupervisor::configure_ospf_generation(
    DeviceHandle device, std::span<const OspfProcessProgram> processes,
    std::span<const OspfInterfaceProgram> interfaces,
    std::span<const OspfAuthenticationProgram> authentications,
    std::span<const OspfNbmaNeighborProgram> nbma_neighbors,
    std::span<const OspfVirtualLinkProgram> virtual_links,
    std::span<const OspfAreaRangeProgram> ranges,
    std::span<const OspfExternalRouteProgram> external_routes) noexcept {
  if (!devices_.get(device) ||
      processes.size() > std::numeric_limits<std::uint32_t>::max() ||
      interfaces.size() > std::numeric_limits<std::uint32_t>::max() ||
      authentications.size() > std::numeric_limits<std::uint32_t>::max() ||
      nbma_neighbors.size() > std::numeric_limits<std::uint32_t>::max() ||
      virtual_links.size() > std::numeric_limits<std::uint32_t>::max() ||
      ranges.size() > std::numeric_limits<std::uint32_t>::max() ||
      external_routes.size() > std::numeric_limits<std::uint32_t>::max())
    return false;

  auto &begin = prepare(NetworkCommandKind::begin_ospf_generation);
  begin.device = device;
  begin.fib = NetworkOspfGenerationBegin{
      .expected_processes =
          static_cast<std::uint32_t>(processes.size()),
      .expected_interfaces =
          static_cast<std::uint32_t>(interfaces.size()),
      .expected_authentications =
          static_cast<std::uint32_t>(authentications.size()),
      .expected_nbma_neighbors =
          static_cast<std::uint32_t>(nbma_neighbors.size()),
      .expected_virtual_links =
          static_cast<std::uint32_t>(virtual_links.size()),
      .expected_ranges =
          static_cast<std::uint32_t>(ranges.size()),
      .expected_external_routes =
          static_cast<std::uint32_t>(external_routes.size())};
  auto result = dispatch(begin);
  for (const auto &process : processes) {
    if (!result || !result->success || process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_process);
    add.device = device;
    add.fib = process;
    result = dispatch(add);
  }
  for (const auto &interface : interfaces) {
    if (!result || !result->success ||
        interface.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_interface);
    add.device = device;
    add.fib = interface;
    result = dispatch(add);
  }
  for (const auto &authentication : authentications) {
    if (!result || !result->success ||
        authentication.process.device != device)
      break;
    auto &add =
        prepare(NetworkCommandKind::add_ospf_authentication);
    add.device = device;
    add.fib = authentication;
    result = dispatch(add);
  }
  for (const auto &neighbor : nbma_neighbors) {
    if (!result || !result->success ||
        neighbor.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_nbma_neighbor);
    add.device = device;
    add.fib = neighbor;
    result = dispatch(add);
  }
  for (const auto &virtual_link : virtual_links) {
    if (!result || !result->success ||
        virtual_link.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_virtual_link);
    add.device = device;
    add.fib = virtual_link;
    result = dispatch(add);
  }
  for (const auto &range : ranges) {
    if (!result || !result->success ||
        range.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_area_range);
    add.device = device;
    add.fib = range;
    result = dispatch(add);
  }
  for (const auto &external : external_routes) {
    if (!result || !result->success ||
        external.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_external_route);
    add.device = device;
    add.fib = external;
    result = dispatch(add);
  }
  if (result && result->success) {
    auto &commit = prepare(NetworkCommandKind::commit_ospf_generation);
    commit.device = device;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }

  // Abort is idempotent and never touches the active generation. The result is
  // deliberately ignored because the original rejected transaction is the
  // caller-visible failure.
  auto &abort = prepare(NetworkCommandKind::abort_ospf_generation);
  abort.device = device;
  static_cast<void>(dispatch(abort));
  return false;
}

std::optional<ospf::ControlResult>
RuntimeSupervisor::query_ospf(
    DeviceHandle device, const OspfOperationalQuery &query) noexcept {
  if (!devices_.get(device))
    return std::nullopt;
  auto &command = prepare(NetworkCommandKind::query_ospf);
  command.device = device;
  command.fib = query;
  const auto result = dispatch(command);
  return result && result->success
             ? std::optional<ospf::ControlResult>{result->ospf}
             : std::nullopt;
}

bool RuntimeSupervisor::remove_mld_interface(
    DeviceHandle device, std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  if (!state.mld_interfaces[*ordinal].configured)
    return false;

  // Acknowledgement precedes intent removal, preserving an exact rollback
  // point when the bounded cross-shard command cannot be accepted.
  auto &command = prepare(NetworkCommandKind::remove_mld_interface);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.mld_interfaces[*ordinal] = {};
  return true;
}

bool RuntimeSupervisor::program_sap_generation(
    DeviceHandle device, std::span<const service::SapAttachment> attachments,
    std::span<const service::ServiceIpv6Interface> interfaces) noexcept {
  if (!devices_.get(device) ||
      attachments.size() > std::numeric_limits<std::uint32_t>::max() ||
      interfaces.size() > std::numeric_limits<std::uint32_t>::max())
    return false;

  // Begin declares both cardinalities before one value is copied. The network
  // worker reserves its private staging vectors once, acknowledges each SPSC
  // record in order, and publishes only when Commit observes both exact sets.
  auto &begin = prepare(NetworkCommandKind::begin_sap_generation);
  begin.device = device;
  begin.fib = SapGenerationBegin{
      .expected_attachments = static_cast<std::uint32_t>(attachments.size()),
      .expected_interfaces = static_cast<std::uint32_t>(interfaces.size())};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;

  for (const auto &attachment : attachments) {
    auto &command = prepare(NetworkCommandKind::add_sap_attachment);
    command.device = device;
    command.fib = attachment;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_sap_generation;
  }
  for (const auto &interface : interfaces) {
    auto &command = prepare(NetworkCommandKind::add_service_ipv6_interface);
    command.device = device;
    command.fib = interface;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_sap_generation;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_sap_generation);
    command.device = device;
    result = dispatch(command);
    if (result && result->success)
      return true;
  }

abort_sap_generation: {
  // Abort is idempotent after a failed Commit and is mandatory after a
  // rejected value record. A later candidate can never inherit a prefix of
  // this generation from the network owner's private staging storage.
  auto &command = prepare(NetworkCommandKind::abort_sap_generation);
  command.device = device;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::program_ipv6_address_generation(
    DeviceHandle device,
    std::span<const RouterIpv6Address> addresses) noexcept {
  if (!device || addresses.size() > RouterIpv6AddressTable::capacity)
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_ipv6_address_generation);
  begin.device = device;
  begin.fib =
      Ipv6AddressGenerationBegin{static_cast<std::uint32_t>(addresses.size())};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &address : addresses) {
    auto &add = prepare(NetworkCommandKind::add_ipv6_interface_address);
    add.device = device;
    add.fib = address;
    result = dispatch(add);
    if (!result || !result->success)
      goto abort_ipv6_addresses;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_ipv6_address_generation);
    commit.device = device;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }

abort_ipv6_addresses: {
  // Abort is safe after a failed Commit. Both lower owners treat it as a
  // terminal cleanup and never retain a prefix for a later generation.
  auto &abort = prepare(NetworkCommandKind::abort_ipv6_address_generation);
  abort.device = device;
  static_cast<void>(dispatch(abort));
}
  return false;
}

} // namespace router::lab
