// Detached AF ownership validates restored advertisement gates before any
// publisher or protocol owner is installed. Only immutable checkpoint values
// are borrowed here; the result owns local subscription keys.
#include "router/isis_ipv6_af_binding.hpp"
#include "router/interface_identity.hpp"
#include <algorithm>
#include <tuple>
namespace router::lab {
std::optional<std::vector<Ipv6ReadinessWatch>> prepare_isis_ipv6_af_binding(
    const isis::ControlDeviceCheckpoint &device, const RouterForwarderCheckpoint &forwarding) noexcept {
  if (!device.handle || device.handle.index >= device_catalog::maximum_routers) return {};
  try {
    std::vector<Ipv6ReadinessWatch> watches;
    const auto key = [](const Ipv6ReadinessWatch &watch) { return std::tie(watch.interface_id, watch.address); };
    for (const auto &instance : device.instances) {
      if (!instance.configuration.origination || !instance.configuration.origination->ipv6_addresses) continue;
      const auto &origin = *instance.configuration.origination;
      if (!origin.prefixes || !isis::valid_local_ipv6_address_catalog(*origin.ipv6_addresses, *origin.prefixes)) return {};
      for (const auto &unit : origin.ipv6_addresses->units) {
        const auto &source = unit.source;
        if (!source.physical_port) {
          const bool configured = source.interface_id == system_interface_id && source.prefix_length == 128U &&
              std::any_of(forwarding.native_ipv6_addresses.begin(), forwarding.native_ipv6_addresses.end(), [&](const auto &address) {
                return address.interface_id == system_interface_id && address.port_ordinal == system_interface_port_ordinal &&
                    address.address == source.address && address.prefix_length == source.prefix_length;
              });
          if (!configured || !source.preferred) return {};
          continue;
        }
        const auto port = std::find_if(forwarding.ports.begin(), forwarding.ports.end(), [&](const auto &entry) {
          return entry.ordinal == *source.physical_port && entry.configured && entry.ipv6_configured;
        });
        if (port == forwarding.ports.end() || source.interface_id != physical_interface_id(*source.physical_port)) return {};
        const bool link_local = ip::is_link_local(source.address);
        const bool configured = link_local ? port->ipv6_link_local == source.address :
            (port->ipv6_address == source.address && port->ipv6_prefix_length == source.prefix_length) ||
            std::any_of(forwarding.native_ipv6_addresses.begin(), forwarding.native_ipv6_addresses.end(), [&](const auto &address) {
              return address.interface_id == source.interface_id && address.port_ordinal == *source.physical_port &&
                  address.address == source.address && address.prefix_length == source.prefix_length;
            });
        if (!configured) return {};
        const bool assigned = std::any_of(forwarding.ipv6_dad.begin(), forwarding.ipv6_dad.end(), [&](const auto &dad) {
          return dad.interface_id == source.interface_id && dad.port_ordinal == *source.physical_port &&
              dad.address == source.address && dad.state == Ipv6DadState::preferred;
        });
        if (source.preferred != assigned) return {};
        if (!watches.capacity()) watches.reserve(device_catalog::ipv6_dad_entries_per_node);
        const Ipv6ReadinessWatch watch{source.interface_id, *source.physical_port, source.address};
        const auto at = std::lower_bound(watches.begin(), watches.end(), watch, [&](const auto &a, const auto &b) { return key(a) < key(b); });
        if (at != watches.end() && key(*at) == key(watch)) { if (*at != watch) return {}; }
        else {
          if (watches.size() == device_catalog::ipv6_dad_entries_per_node) return {};
          watches.insert(at, watch);
        }
      }
      for (const auto &circuit : device.circuits) if (circuit.definition.identity.instance == instance.instance) {
        const auto *hello = circuit.definition.common();
        if (!hello) return {};
        for (const auto &address : hello->ipv6_addresses)
          if (std::none_of(origin.ipv6_addresses->units.begin(), origin.ipv6_addresses->units.end(), [&](const auto &unit) {
            return unit.source.interface_id == circuit.definition.identity.interface_id && unit.source.address == address &&
                unit.source.physical_port == circuit.definition.identity.physical_port_ordinal;
          })) return {};
        const bool ready = circuit.definition.carrier && isis::local_ipv6_hello_available(*origin.ipv6_addresses,
            circuit.definition.identity.interface_id, hello->ipv6_addresses);
        if (hello->ipv6_addresses_ready != ready) return {};
      }
    }
    return watches;
  } catch (const std::bad_alloc &) { return {}; }
}
}
