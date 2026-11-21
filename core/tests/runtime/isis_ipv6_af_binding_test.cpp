// Detached owner images must agree on address ownership, DAD and Hello gates.
// Forged assignment or address bindings refuse before a restored publisher can
// produce events. The test owns all cold values and uses canonical DAD images.
#include "router/isis_ipv6_af_binding.hpp"
#include "router/isis_local_prefix_catalog_program.hpp"
#include "router/interface_identity.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace router::lab;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS IPv6 AF binding invariant at " + std::to_string(at.line()));
}
}
void isis_ipv6_af_binding_tests() {
  const auto interface_id = physical_interface_id(0U);
  const auto global = *ip::parse_ipv6("2001:db8:12::1");
  const auto ll = *ip::parse_ipv6("fe80::1");
  InstanceIntent intent; intent.admin_enabled = true; intent.ipv6_routing = ConfiguredIpv6Routing::native;
  intent.ipv4_routing = false; intent.levels = ConfiguredLevels::level2;
  intent.level[1U].wide_metrics_only = true;
  InterfaceIntent attached; attached.name = "edge"; intent.interfaces.push_back(attached);
  const std::array prefix{RootPrefix{*ip::parse_ip_prefix("2001:db8:12::/64"), 20U, {}}};
  const std::array sources{LocalPrefixSource{"edge", {std::span<const RootPrefix>{}, prefix}, true, false}};
  const std::array interfaces{LocalPrefixInterface{interface_id, std::uint16_t{0U}, true}};
  auto prefixes = prepare_local_prefix_catalog(intent, sources, interfaces, {1U, 1U}); require(prefixes.program.has_value());
  const std::array candidates{LocalIpv6Address{interface_id, std::uint16_t{0U}, global, 64U, false},
      LocalIpv6Address{interface_id, std::uint16_t{0U}, ll, 64U, true}};
  auto addresses = prepare_local_ipv6_address_catalog(candidates, 2U); require(addresses.has_value());
  auto forwarding = std::make_unique<RouterForwarderCheckpoint>();
  ForwardPort port; port.configured = port.operational = port.ipv6_configured = true;
  port.ordinal = 0U; port.ipv6_address = global; port.ipv6_link_local = ll; port.ipv6_prefix_length = 64U;
  forwarding->ports.push_back(port);
  const auto now = Ipv6DadTable::Clock::time_point{};
  Ipv6DadTable dad;
  require(dad.configure(interface_id, 0U, ll, 0U, {}, now) && dad.configure(interface_id, 0U, global, 1U, {}, now));
  forwarding->ipv6_dad = dad.checkpoint(now);
  ControlDeviceCheckpoint device; device.handle = {0U, 1U}; device.active = true;
  auto &instance = device.instances.emplace_back(); instance.configuration.origination.emplace();
  auto &origin = *instance.configuration.origination;
  origin.prefixes = std::move(prefixes.program); origin.ipv6_addresses = std::move(addresses);
  auto &circuit = device.circuits.emplace_back();
  circuit.definition.identity = {device.handle, interface_id, 9U, 0U, 0U};
  circuit.definition.configuration.ipv6_addresses = {ll};
  circuit.definition.configuration.ipv6_addresses_ready = true;
  const auto watches = prepare_isis_ipv6_af_binding(device, *forwarding);
  require(watches && watches->size() == 2U && watches->front().address == global && watches->back().address == ll);
  auto invalid = device;
  invalid.instances.front().configuration.origination->ipv6_addresses->units.front().source.preferred = true;
  require(!prepare_isis_ipv6_af_binding(invalid, *forwarding));
  forwarding->ports.front().ipv6_address = *ip::parse_ipv6("2001:db8:12::2");
  require(!prepare_isis_ipv6_af_binding(device, *forwarding));
  forwarding->ports.front().ipv6_address = global;
  circuit.definition.configuration.ipv6_addresses_ready = false;
  require(!prepare_isis_ipv6_af_binding(device, *forwarding));
  circuit.definition.configuration.ipv6_addresses_ready = true;
  circuit.definition.configuration.ipv6_addresses = {*ip::parse_ipv6("fe80::2")};
  require(!prepare_isis_ipv6_af_binding(device, *forwarding));
  circuit.definition.configuration.ipv6_addresses = {ll};
  dad.remove(interface_id, ll); forwarding->ipv6_dad = dad.checkpoint(now);
  require(!prepare_isis_ipv6_af_binding(device, *forwarding));
  require(set_local_ipv6_address_ready(*origin.ipv6_addresses, interface_id, 0U, ll, false));
  circuit.definition.configuration.ipv6_addresses_ready = false;
  require(prepare_isis_ipv6_af_binding(device, *forwarding).has_value());
  // Identical candidates in another local instance do not multiply the AF
  // subscriber set or consume another DAD address budget.
  auto second = instance; second.instance = 1U; device.instances.push_back(std::move(second));
  const auto shared = prepare_isis_ipv6_af_binding(device, *forwarding);
  require(shared && *shared == *watches);
  auto &logical_origin = *device.instances.front().configuration.origination;
  logical_origin.prefixes->interfaces.push_back({system_interface_id, {}, false});
  const auto system = *ip::parse_ipv6("2001:db8:ffff::1");
  std::vector<LocalIpv6Address> complete;
  for (const auto &unit : logical_origin.ipv6_addresses->units) complete.push_back(unit.source);
  complete.push_back({system_interface_id, {}, system, 128U, true});
  logical_origin.ipv6_addresses = prepare_local_ipv6_address_catalog(complete, 3U);
  require(logical_origin.ipv6_addresses.has_value());
  require(!prepare_isis_ipv6_af_binding(device, *forwarding));
  RouterIpv6Address system_address; system_address.address = system_address.network = system;
  system_address.interface_id = system_interface_id; system_address.port_ordinal = system_interface_port_ordinal;
  system_address.prefix_length = 128U; system_address.duplicate_address_detection = false;
  forwarding->native_ipv6_addresses.push_back(system_address);
  const auto logical = prepare_isis_ipv6_af_binding(device, *forwarding);
  require(logical && *logical == *watches);
}
