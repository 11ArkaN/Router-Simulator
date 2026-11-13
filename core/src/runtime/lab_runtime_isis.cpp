// The serialized datastore owner compiles local IS-IS intent and admits one
// atomic network generation. Protocol state stays on the control pthread;
// hardware and AF projections are local, and peer state never configures it.
#include "router/lab_runtime.hpp"
#include "router/interface_identity.hpp"
#include "router/isis_configuration_plan.hpp"
#include "router/isis_instance_program.hpp"
#include "router/isis_local_prefix_catalog_program.hpp"
#include "router/isis_local_ipv6_address_catalog.hpp"
#include <algorithm>
#include <limits>
#include <tuple>
namespace router::lab {
namespace {
using namespace std::chrono_literals;
// Explicit experimental emulator budgets, not SR OS platform capacities.
constexpr std::size_t circuits = 8U, neighbors = 8U, records = 128U;
packet::Ipv4 octets(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24U), static_cast<std::uint8_t>(value >> 16U),
      static_cast<std::uint8_t>(value >> 8U), static_cast<std::uint8_t>(value)};
}
struct RouterPrefixProjection {
  isis::LocalPrefixCatalogStatus status{isis::LocalPrefixCatalogStatus::invalid_context};
  std::optional<isis::LocalPrefixCatalogProgram> program;
  std::vector<packet::Ipv4> addresses;
  std::optional<isis::LocalIpv6AddressCatalog> ipv6_addresses;
};
RouterPrefixProjection router_prefixes(const auto &interfaces,
    const isis::InstanceIntent &intent, const RouterHardwareInventory &hardware,
    const RouterForwarderCheckpoint &forwarding) {
  using namespace isis;
  const bool ipv4 = intent.ipv4_routing.value_or(configuration_profile::ipv4_routing_default);
  const bool ipv6 = intent.ipv6_routing == ConfiguredIpv6Routing::native;
  std::vector<LocalIpv4PrefixSource> ipv4_sources; ipv4_sources.reserve(intent.interfaces.size());
  std::vector<std::vector<LocalIpPrefixAddress>> storage(intent.interfaces.size());
  std::vector<LocalIpPrefixSource> sources; sources.reserve(intent.interfaces.size());
  std::vector<LocalIpv6Address> candidates;
  for (std::size_t index{}; index < intent.interfaces.size(); ++index) {
    const auto &attached = intent.interfaces[index];
    const auto base = std::find_if(interfaces.begin(), interfaces.end(), [&](const auto &entry) { return entry.name == attached.name; });
    if (base == interfaces.end()) return {};
    LocalPrefixInterface binding;
    const bool system = base->name == "system";
    const ForwardPort *port{};
    if (system) { binding.interface_id = system_interface_id; binding.available = base->admin_enabled; }
    else {
      if (!base->port_configured) return {};
      const auto ordinal = hardware.coordinate_ordinal(base->port_id);
      if (!ordinal) return {};
      binding.interface_id = physical_interface_id(*ordinal); binding.physical_port = *ordinal;
      const auto live = std::find_if(forwarding.ports.begin(), forwarding.ports.end(),
          [&](const auto &entry) { return entry.ordinal == *ordinal && entry.configured; });
      if (live != forwarding.ports.end()) port = &*live;
      binding.available = port && port->operational;
    }
    ipv4_sources.push_back({attached.name, binding, base->address, base->prefix_length, base->address_configured, system});
    if (!ipv6) continue;
    auto &addresses = storage[index];
    const auto resolved = resolve_interface(intent, attached, ConfiguredInterfaceType::broadcast);
    if (system) for (std::size_t level{}; level < 2U; ++level)
      if (resolved.level[level].enabled && (attached.level[level].metric || intent.level[level].default_metric))
        return {LocalPrefixCatalogStatus::unresolved_system_metric, {}, {}, {}};
    if (ipv4 && base->address_configured) {
      if (base->prefix_length > 32U || (system && base->prefix_length != 32U)) return {};
      LocalIpPrefixAddress address; address.prefix_length = base->prefix_length;
      const auto bytes = octets(base->address); std::copy(bytes.begin(), bytes.end(), address.address.bytes.begin());
      for (std::size_t level{}; level < 2U; ++level)
        address.metrics[level] = system ? 0U : resolved.level[level].metric;
      addresses.push_back(address);
    }
    const auto append = [&](const packet::Ipv6 &address, std::uint8_t length) {
      const bool preferred = system || std::any_of(forwarding.ipv6_dad.begin(), forwarding.ipv6_dad.end(), [&](const auto &dad) {
        return dad.interface_id == binding.interface_id && dad.port_ordinal == *binding.physical_port &&
            dad.address == address && dad.state == Ipv6DadState::preferred;
      });
      candidates.push_back({binding.interface_id, binding.physical_port, address, length, preferred});
      std::array<std::uint32_t, 2U> metrics{};
      for (std::size_t level{}; level < metrics.size(); ++level) metrics[level] = system ? 0U : resolved.level[level].metric;
      addresses.push_back({ip::IpAddress{ip::AddressFamily::ipv6, address}, length, metrics});
    };
    if (system) {
      for (const auto &address : forwarding.native_ipv6_addresses) if (address.interface_id == system_interface_id)
        append(address.address, address.prefix_length);
    } else if (port && port->ipv6_configured) {
      if (!ip::is_link_local(port->ipv6_link_local)) return {};
      append(port->ipv6_link_local, 64U);
      bool native{};
      for (const auto &address : forwarding.native_ipv6_addresses)
        if (address.interface_id == binding.interface_id && address.port_ordinal == *binding.physical_port &&
            !ip::is_link_local(address.address)) { append(address.address, address.prefix_length); native = true; }
      if (!native) append(port->ipv6_address, port->ipv6_prefix_length);
    }
    sources.push_back({attached.name, binding, addresses});
  }
  auto retained = intent; retained.admin_enabled = true;
  if (!ipv6) {
    auto selected = prepare_local_ipv4_prefix_catalog(retained, ipv4_sources, {128U, 128U});
    return {selected.status, std::move(selected.program), std::move(selected.addresses), {}};
  }
  auto selected = prepare_local_ip_prefix_catalog(retained, sources, {128U, 128U});
  if (selected.status != LocalPrefixCatalogStatus::prepared || !selected.program) return {selected.status, {}, {}, {}};
  if (ipv4 && selected.ipv4_addresses.empty()) return {};
  auto availability = prepare_local_ipv6_address_catalog(candidates,
      Ipv6DadTable::capacity + device_catalog::network_interface_ip_addresses);
  if (!availability || !valid_local_ipv6_address_catalog(*availability, *selected.program)) return {};
  return {selected.status, std::move(selected.program), std::move(selected.ipv4_addresses), std::move(availability)};
}
isis::IdentityContext identity(const auto &interfaces) noexcept {
  isis::IdentityContext result;
  result.fallback_router_id = 0xff000000U;
  const auto system = std::find_if(interfaces.begin(), interfaces.end(),
      [](const auto &entry) { return entry.name == "system"; });
  if (system != interfaces.end() && system->address_configured) result.system_ipv4 = system->address;
  return result;
}
}
bool LabRuntime::apply_isis_configuration(const RouterIntent &before,
    const ConfigurationIntent &after, const RuntimeSupervisorCheckpoint &saved) {
  using namespace isis;
  const ControlDeviceCheckpoint *owner{};
  if (saved.network.isis) {
    const auto &devices = saved.network.isis->control.devices;
    const auto found = std::find_if(devices.begin(), devices.end(),
        [&](const auto &entry) { return entry.handle == before.handle; });
    if (found != devices.end()) owner = &*found;
  }
  if (!owner && before.isis.instances.empty() && after.isis.instances.empty()) return true;
  std::vector<InstanceOwnerState> ownership;
  if (owner) for (const auto &entry : owner->instances) ownership.push_back({entry.instance, entry.admin_enabled});
  std::sort(ownership.begin(), ownership.end(), [](const auto &a, const auto &b) { return a.instance < b.instance; });
  const auto old_identity = identity(before.interfaces), new_identity = identity(after.interfaces);
  const auto plan = plan_configuration(before.isis, after.isis, ownership, old_identity, new_identity);
  if (plan.status != ConfigurationPlanStatus::prepared) return false;
  // Live local-prefix and hostname edits need a dedicated in-place consumer.
  // Refuse them before claiming a successful unchanged protocol generation.
  if (!ownership.empty() && (before.interfaces != after.interfaces || before.system_name != after.system_name)) return false;
  NetworkIsisGeneration generation;
  generation.device = before.handle;
  bool changed{};
  std::uint64_t epoch = owner ? owner->retired_epoch_floor : 0U;
  if (owner) for (const auto &entry : owner->circuits) epoch = std::max(epoch, entry.definition.identity.configuration_generation);
  const auto *hardware = supervisor_.hardware(before.handle);
  if (!hardware) return false;
  auto operational = supervisor_.router_operational_state(before.handle);
  if (!operational) return false;
  for (std::size_t index{}; index < plan.count; ++index) {
    const auto action = plan.changes[index];
    const auto configured = std::find_if(after.isis.instances.begin(), after.isis.instances.end(),
        [&](const auto &entry) { return entry.instance == action.instance; });
    const auto retain = [&] {
      if (!owner) return true;
      for (const auto &entry : owner->circuits) if (entry.definition.identity.instance == action.instance) {
        const auto &ports = saved.network.isis->ports;
        const auto port = std::find_if(ports.begin(), ports.end(),
            [&](const auto &binding) { return binding.identity == entry.definition.identity; });
        if (port == ports.end()) return false;
        auto definition = entry.definition;
        const auto live = std::find_if(operational->ports.begin(), operational->ports.end(),
            [&](const auto &value) { return value.ordinal == definition.identity.physical_port_ordinal; });
        definition.carrier = live != operational->ports.end() && live->configured && live->operational;
        generation.circuits.push_back({std::move(definition), port->port});
      }
      return true;
    };
    switch (action.change) {
    case ConfigurationChange::unchanged:
      if (!retain()) return false;
      continue;
    case ConfigurationChange::intent_only: continue;
    case ConfigurationChange::retire:
      generation.retired_instances.push_back(action.instance); changed = true; continue;
    case ConfigurationChange::suspend: case ConfigurationChange::resume:
      if (!retain()) return false;
      generation.administrative.push_back({action.instance, action.change == ConfigurationChange::resume});
      changed = true; continue;
    case ConfigurationChange::reconfigure: case ConfigurationChange::reconfigure_disabled:
    case ConfigurationChange::suspend_and_reconfigure: case ConfigurationChange::resume_and_reconfigure: {
      const auto previous = std::find_if(before.isis.instances.begin(), before.isis.instances.end(),
          [&](const auto &entry) { return entry.instance == action.instance; });
      if (previous == before.isis.instances.end() || configured == after.isis.instances.end()) return false;
      auto compare = *previous;
      compare.strict_adjacency_check = configured->strict_adjacency_check;
      compare.advertise_passive_only = configured->advertise_passive_only;
      compare.admin_enabled = configured->admin_enabled;
      if (compare != *configured || !retain()) return false;
      auto prefixes = router_prefixes(after.interfaces, *configured, *hardware, *operational);
      if (prefixes.status != LocalPrefixCatalogStatus::prepared || !prefixes.program) return false;
      if (!owner) return false;
      const auto prior = std::find_if(owner->instances.begin(), owner->instances.end(),
          [&](const auto &entry) { return entry.instance == action.instance; });
      if (prior == owner->instances.end() || !prior->configuration.origination) return false;
      if (!prior->configuration.origination->prefixes || *prior->configuration.origination->prefixes != *prefixes.program)
        generation.prefix_catalogs.push_back({action.instance, std::move(*prefixes.program)});
      generation.adjacency_policies.push_back({action.instance,
          configured->strict_adjacency_check.value_or(configuration_profile::strict_adjacency_check_default)});
      if (action.change == ConfigurationChange::suspend_and_reconfigure ||
          action.change == ConfigurationChange::resume_and_reconfigure)
        generation.administrative.push_back({action.instance, action.change == ConfigurationChange::resume_and_reconfigure});
      changed = true; continue;
    }
    case ConfigurationChange::create: case ConfigurationChange::restart: break;
    default: return false;
    }
    if (configured == after.isis.instances.end() || action.instance ||
        configured->levels != ConfiguredLevels::level2 ||
        (!configured->ipv4_routing.value_or(configuration_profile::ipv4_routing_default) &&
         configured->ipv6_routing != ConfiguredIpv6Routing::native) ||
        configured->ipv6_routing == ConfiguredIpv6Routing::multi_topology ||
        !resolve_instance_level(*configured, 1U).wide_metrics_only || configured->areas.empty()) return false;
    const auto wait = resolve_wait_timer(WaitTimerKind::lsp, configured->lsp_wait);
    // A fixed hold policy has no unresolved adaptive growth/reset behavior.
    if (!wait || wait->initial != 0ms || wait->second != wait->maximum || wait->maximum <= 0ms) return false;
    if (epoch >= std::numeric_limits<std::uint64_t>::max() - circuits) return false;
    ++epoch;
    const auto mtu = configured->lsp_mtu_octets.value_or(configuration_profile::lsp_mtu_octets_default);
    InstanceProgramContext context;
    context.identity = new_identity; context.maximum_areas = configuration_profile::area_addresses_maximum;
    context.maximum_circuits = circuits;
    const UpdateLevelConfiguration level{{records, records * 1492U}, records, records, mtu,
        1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
    context.levels = {level, level}; context.fragments = {8U, 8U};
    context.transmission = {2U, 5U, 10U, 100ms, 10U, mtu, 1U};
    context.minimum_generation_interval = wait->maximum; context.resource_retry = 100ms;
    context.random = epoch; context.hostname = after.system_name;
    if (configured->ipv4_routing.value_or(configuration_profile::ipv4_routing_default)) {
      context.routing[0U].emplace();
      context.routing[0U]->calculation = {64U, 256U, 512U, packet::isis::ipv4_nlpid, PrefixCollectionBudget{128U, 4096U}};
      context.routing[0U]->preferences = {P2pRouteFamilyProgram::Preference{15U, 160U}, {18U, 165U}};
    }
    if (configured->ipv6_routing == ConfiguredIpv6Routing::native) {
      context.routing[1U].emplace();
      context.routing[1U]->calculation = {64U, 256U, 512U, packet::isis::ipv6_nlpid, PrefixCollectionBudget{128U, 4096U}};
      context.routing[1U]->preferences = {P2pRouteFamilyProgram::Preference{15U, 160U}, {18U, 165U}};
    }
    std::vector<InstanceOriginInterface> origins;
    std::uint8_t local_circuit{};
    for (const auto &attached : configured->interfaces) {
      const auto base = std::find_if(after.interfaces.begin(), after.interfaces.end(),
          [&](const auto &entry) { return entry.name == attached.name; });
      if (base == after.interfaces.end()) return false;
      const bool system = base->name == "system";
      const auto resolved = resolve_interface(*configured, attached, ConfiguredInterfaceType::broadcast);
      if (system) {
        origins.push_back({attached.name, system_interface_id, {}, 0U, 0U, true});
        continue;
      }
      if (!base->port_configured) return false;
      const auto ordinal = hardware->coordinate_ordinal(base->port_id);
      if (!ordinal) return false;
      const bool active = resolved.admin_enabled && std::any_of(resolved.level.begin(), resolved.level.end(),
          [](const auto &level) { return level.enabled && !level.passive; });
      if (active && configured->ipv4_routing.value_or(configuration_profile::ipv4_routing_default) && !base->address_configured)
        return false;
      if (!active) {
        origins.push_back({attached.name, physical_interface_id(*ordinal), ConfiguredInterfaceType::broadcast,
            0U, neighbors, false});
        continue;
      }
      const auto port = hardware->handle(base->port_id);
      const auto mac = hardware->physical_mac(base->port_id);
      if (!port || !mac || local_circuit == circuits) return false;
      ++local_circuit;
      const auto live = std::find_if(operational->ports.begin(), operational->ports.end(),
          [&](const auto &entry) { return entry.ordinal == *ordinal && entry.configured; });
      if (live == operational->ports.end()) return false;
      std::vector<std::uint8_t> protocols;
      if (configured->ipv4_routing.value_or(configuration_profile::ipv4_routing_default)) protocols.push_back(packet::isis::ipv4_nlpid);
      if (configured->ipv6_routing == ConfiguredIpv6Routing::native) protocols.push_back(packet::isis::ipv6_nlpid);
      const std::array<packet::Ipv4, 1U> addresses{octets(base->address)};
      const std::array<packet::Ipv6, 1U> link_local{live->ipv6_link_local};
      InterfaceProgramContext hello;
      hello.identity = {before.handle, physical_interface_id(*ordinal), epoch, *ordinal, action.instance};
      hello.interface_name = attached.name; hello.system_identity = new_identity;
      hello.default_type = ConfiguredInterfaceType::broadcast; hello.mac = *mac;
      hello.destinations = {{0x09U, 0x00U, 0x2bU, 0x00U, 0x00U, 0x05U},
          {packet::Mac{0x01U, 0x80U, 0xc2U, 0x00U, 0x00U, 0x14U}, packet::Mac{0x01U, 0x80U, 0xc2U, 0x00U, 0x00U, 0x15U}}};
      hello.extended_circuit = static_cast<std::uint32_t>(*ordinal) + 1U;
      hello.local_circuit = local_circuit; hello.maximum_areas = context.maximum_areas;
      hello.random = epoch + local_circuit; hello.maximum_pdu_octets = mtu;
      hello.peer_attribute_octets = 4096U; hello.lan_neighbors = neighbors;
      hello.protocols = protocols;
      if (base->address_configured && configured->ipv4_routing.value_or(configuration_profile::ipv4_routing_default))
        hello.ipv4_addresses = addresses;
      if (live->ipv6_configured && configured->ipv6_routing == ConfiguredIpv6Routing::native) hello.ipv6_addresses = link_local;
      hello.ipv6_addresses_ready = live->operational && std::any_of(operational->ipv6_dad.begin(), operational->ipv6_dad.end(),
          [&](const auto &dad) { return dad.interface_id == hello.identity.interface_id && dad.address == live->ipv6_link_local &&
              dad.port_ordinal == *ordinal && dad.state == Ipv6DadState::preferred; });
      hello.operational = live->operational;
      hello.strict_adjacency_check = configured->strict_adjacency_check.value_or(configuration_profile::strict_adjacency_check_default);
      auto prepared = prepare_interface_program(*configured, attached, hello);
      if (prepared.status != InterfaceProgramStatus::prepared && prepared.status != InterfaceProgramStatus::inactive) return false;
      if (prepared.circuit) {
        const auto transmission = prepare_interface_update_program(resolved, {2U, mtu, 1U, 1ms});
        if (transmission.status != InterfaceUpdateStatus::prepared) return false;
        prepared.circuit->update_transmission = transmission.program;
        generation.circuits.push_back({std::move(*prepared.circuit), *port});
      }
      origins.push_back({attached.name, physical_interface_id(*ordinal), ConfiguredInterfaceType::broadcast,
          local_circuit, neighbors, false});
    }
    auto prefixes = router_prefixes(after.interfaces, *configured, *hardware, *operational);
    if (prefixes.status != LocalPrefixCatalogStatus::prepared || !prefixes.program) return false;
    context.interfaces = origins; context.ipv4_addresses = prefixes.addresses;
    auto prepared = prepare_instance_program(*configured, context);
    if (prepared.status != InstanceProgramStatus::prepared || !prepared.program) return false;
    prepared.program->origination->prefixes = std::move(prefixes.program);
    prepared.program->origination->ipv6_addresses = std::move(prefixes.ipv6_addresses);
    const bool replacement = action.change == ConfigurationChange::restart;
    if (replacement) generation.retired_instances.push_back(action.instance);
    generation.new_instances.push_back({action.instance, std::move(*prepared.program), replacement, true});
    changed = true;
  }
  if (!changed) return true;
  std::sort(generation.circuits.begin(), generation.circuits.end(), [](const auto &a, const auto &b) {
    return std::tie(a.circuit.identity.interface_id, a.circuit.identity.instance) <
        std::tie(b.circuit.identity.interface_id, b.circuit.identity.instance);
  });
  generation.ipv6_watches.emplace();
  const auto collect = [&](const UpdateInstanceProgram &program) {
    if (program.origination && program.origination->ipv6_addresses)
      for (const auto &unit : program.origination->ipv6_addresses->units) if (unit.source.physical_port)
        generation.ipv6_watches->push_back({unit.source.interface_id, *unit.source.physical_port, unit.source.address});
  };
  for (const auto &entry : generation.new_instances) collect(entry.program);
  if (owner) for (const auto &entry : owner->instances)
    if (std::find(generation.retired_instances.begin(), generation.retired_instances.end(), entry.instance) == generation.retired_instances.end())
      collect(entry.configuration);
  auto &watches = *generation.ipv6_watches;
  std::sort(watches.begin(), watches.end(), [](const auto &a, const auto &b) {
    return std::tie(a.interface_id, a.address, a.port_ordinal) < std::tie(b.interface_id, b.address, b.port_ordinal);
  });
  watches.erase(std::unique(watches.begin(), watches.end()), watches.end());
  return supervisor_.admit_isis_generation(std::move(generation));
}
bool LabRuntime::validate_isis_prefix_checkpoint(const RouterIntent &router,
    const RuntimeSupervisorCheckpoint &saved) const {
  if (router.isis.instances.empty() || !saved.network.isis) return true;
  const auto device = std::find_if(saved.network.isis->control.devices.begin(), saved.network.isis->control.devices.end(),
      [&](const auto &entry) { return entry.handle == router.handle && entry.active; });
  if (device == saved.network.isis->control.devices.end()) return true;
  const auto hardware_image = std::find_if(saved.hardware.begin(), saved.hardware.end(),
      [&](const auto &entry) { return entry.device == router.handle; });
  const auto network = std::find_if(saved.network.routers.begin(), saved.network.routers.end(),
      [&](const auto &entry) { return entry.device == router.handle; });
  if (hardware_image == saved.hardware.end() || network == saved.network.routers.end()) return false;
  auto hardware = std::make_unique<RouterHardwareInventory>();
  if (!hardware->restore(*hardware_image)) return false;
  for (const auto &intent : router.isis.instances) {
    const auto owner = std::find_if(device->instances.begin(), device->instances.end(),
        [&](const auto &entry) { return entry.instance == intent.instance; });
    if (owner == device->instances.end()) continue;
    if (!owner->configuration.origination || !owner->configuration.origination->prefixes) return false;
    const auto expected = router_prefixes(router.interfaces, intent, *hardware, network->forwarding);
    if (expected.status != isis::LocalPrefixCatalogStatus::prepared || !expected.program ||
        *expected.program != *owner->configuration.origination->prefixes ||
        expected.ipv6_addresses != owner->configuration.origination->ipv6_addresses) return false;
  }
  return true;
}

}
