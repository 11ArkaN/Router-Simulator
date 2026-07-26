// Atomic implementation of SR OS 26.7.R1 customer, service-port, IES, routed
// service-interface, SAP and DHCPv6-relay CLI edits. Both terminal grammars
// map into one canonical model, while their creation and deletion semantics
// remain distinct. All visible port coordinates come from installed hardware.

#include "ies_cli_configuration.hpp"

#include "cli_internal.hpp"
#include "router/interface_identity.hpp"
#include "router/ip_address.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace router::lab::ies_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;
using service::Configuration;
using service::CustomerConfiguration;
using service::Dhcpv6RelayConfiguration;
using service::EthernetEncapsulation;
using service::EthernetPortConfiguration;
using service::EthernetPortMode;
using service::IesConfiguration;
using service::IesInterfaceConfiguration;
using service::PhysicalPortCoordinate;
using service::RelayInterfaceIdKind;
using service::SapKey;

std::string_view value(const cli_detail::ParsedCommand &command,
                       TokenKind kind) {
  const auto raw = cli_detail::argument(command, kind);
  return raw ? cli_detail::unquote(*raw) : std::string_view{};
}

template <typename Integer>
std::optional<Integer> decimal(std::string_view text) noexcept {
  // from_chars is locale independent and cannot allocate. Requiring complete
  // consumption prevents forms such as `10x` from becoming valid identifiers.
  Integer parsed{};
  const auto converted =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (text.empty() || converted.ec != std::errc{} ||
      converted.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

template <typename Value>
bool set_distinct(Value &destination, Value next) {
  if (destination == next)
    return false;
  destination = std::move(next);
  return true;
}

CustomerConfiguration *customer_by_name(Configuration &configuration,
                                        std::string_view name) noexcept {
  const auto found = std::find_if(configuration.customers.begin(),
                                  configuration.customers.end(),
                                  [name](const auto &customer) {
                                    return customer.name == name;
                                  });
  return found == configuration.customers.end() ? nullptr : &*found;
}

CustomerConfiguration *customer_by_id(Configuration &configuration,
                                      std::uint32_t id) noexcept {
  const auto found = std::find_if(configuration.customers.begin(),
                                  configuration.customers.end(),
                                  [id](const auto &customer) {
                                    return customer.customer_id == id;
                                  });
  return found == configuration.customers.end() ? nullptr : &*found;
}

IesConfiguration *service_by_name(Configuration &configuration,
                                  std::string_view name) noexcept {
  const auto found = std::find_if(configuration.ies_services.begin(),
                                  configuration.ies_services.end(),
                                  [name](const auto &service) {
                                    return service.name == name;
                                  });
  return found == configuration.ies_services.end() ? nullptr : &*found;
}

IesConfiguration *service_by_id(Configuration &configuration,
                                std::uint32_t id) noexcept {
  const auto found = std::find_if(configuration.ies_services.begin(),
                                  configuration.ies_services.end(),
                                  [id](const auto &service) {
                                    return service.service_id == id;
                                  });
  return found == configuration.ies_services.end() ? nullptr : &*found;
}

IesInterfaceConfiguration *interface_by_name(IesConfiguration &service,
                                             std::string_view name) noexcept {
  const auto found = std::find_if(service.interfaces.begin(),
                                  service.interfaces.end(),
                                  [name](const auto &interface) {
                                    return interface.name == name;
                                  });
  return found == service.interfaces.end() ? nullptr : &*found;
}

std::optional<std::uint64_t>
next_logical_id(const Configuration &configuration) noexcept {
  // Logical service IDs occupy the namespace below bit 63. Scanning all IES
  // interfaces prevents deletion or vector reordering from aliasing retained
  // ND, FIB, lease or checkpoint references.
  std::uint64_t highest{};
  for (const auto &service : configuration.ies_services)
    for (const auto &interface : service.interfaces)
      highest = std::max(highest, interface.logical_id);
  if (highest + 1U >= physical_interface_namespace)
    return std::nullopt;
  return highest + 1U;
}

IesConfiguration *md_service(Configuration &configuration,
                             std::string_view name) {
  if (auto *existing = service_by_name(configuration, name))
    return existing;
  if (name.empty() || name.size() > service::maximum_service_name_octets)
    return nullptr;
  // MD list entry creation may precede its mandatory service-id and customer
  // leaves. Zero represents only that candidate-only absence and can never be
  // accepted by the running validator at commit.
  configuration.ies_services.push_back(
      {.service_id = 0U, .customer_id = 0U, .name = std::string{name}});
  return &configuration.ies_services.back();
}

IesInterfaceConfiguration *md_interface(Configuration &configuration,
                                        IesConfiguration &service,
                                        std::string_view name) {
  if (auto *existing = interface_by_name(service, name))
    return existing;
  const auto id = next_logical_id(configuration);
  if (!id || name.empty() ||
      name.size() > service::maximum_interface_name_octets)
    return nullptr;
  service.interfaces.push_back({.logical_id = *id,
                                .name = std::string{name},
                                .ip_mtu = 1500U,
                                .admin_enabled = false});
  return &service.interfaces.back();
}

std::optional<PhysicalPortCoordinate>
physical_coordinate(const RouterHardwareInventory &inventory,
                    std::string_view port_id) noexcept {
  const auto *port = inventory.find(port_id);
  const auto ordinal = inventory.coordinate_ordinal(port_id);
  if (!port || !ordinal)
    return std::nullopt;
  return PhysicalPortCoordinate{.ordinal = *ordinal,
                                .card = port->card_slot,
                                .mda = port->mda_slot,
                                .port = port->port_number};
}

EthernetPortConfiguration *service_port(
    Configuration &configuration, const RouterHardwareInventory &inventory,
    std::string_view port_id, bool create) {
  const auto coordinate = physical_coordinate(inventory, port_id);
  if (!coordinate)
    return nullptr;
  const auto found = std::find_if(configuration.ports.begin(),
                                  configuration.ports.end(),
                                  [&](const auto &port) {
                                    return port.coordinate == *coordinate;
                                  });
  if (found != configuration.ports.end())
    return &*found;
  if (!create)
    return nullptr;
  configuration.ports.push_back({.coordinate = *coordinate,
                                 .mode = EthernetPortMode::network,
                                 .encapsulation = EthernetEncapsulation::null,
                                 .outer_tpid = 0U});
  return &configuration.ports.back();
}

std::optional<SapKey> parse_sap(const Configuration &configuration,
                                const RouterHardwareInventory &inventory,
                                std::string_view text) noexcept {
  // SAP grammar is derived from the configured port encapsulation. This avoids
  // treating `1/1/1:10` as dot1q merely because the text has one VLAN field.
  const auto colon = text.find(':');
  const auto port_text = text.substr(0U, colon);
  const auto coordinate = physical_coordinate(inventory, port_text);
  if (!coordinate)
    return std::nullopt;
  const auto configured_port = std::find_if(
      configuration.ports.begin(), configuration.ports.end(),
      [&](const auto &port) { return port.coordinate == *coordinate; });
  if (configured_port == configuration.ports.end() ||
      configured_port->mode == EthernetPortMode::network)
    return std::nullopt;

  SapKey result{.port = *coordinate,
                .encapsulation = configured_port->encapsulation};
  if (configured_port->encapsulation == EthernetEncapsulation::null)
    return colon == std::string_view::npos ? std::optional<SapKey>{result}
                                           : std::nullopt;
  if (colon == std::string_view::npos)
    return std::nullopt;
  const auto tags = text.substr(colon + 1U);
  const auto dot = tags.find('.');
  const auto outer = decimal<std::uint16_t>(tags.substr(0U, dot));
  if (!outer || *outer > service::maximum_vlan_identifier)
    return std::nullopt;
  result.outer_vlan = *outer;
  if (configured_port->encapsulation == EthernetEncapsulation::dot1q)
    return dot == std::string_view::npos ? std::optional<SapKey>{result}
                                         : std::nullopt;
  if (dot == std::string_view::npos)
    return std::nullopt;
  const auto inner = decimal<std::uint16_t>(tags.substr(dot + 1U));
  if (!inner || *inner > service::maximum_vlan_identifier)
    return std::nullopt;
  result.inner_vlan = *inner;
  return result;
}

std::string instance_path(std::string_view service_name,
                          std::string_view interface_name = {}) {
  std::string path{"/service/ies/"};
  path.append(service_name);
  if (!interface_name.empty()) {
    path.append("/interface/");
    path.append(interface_name);
  }
  return path;
}

bool set_address(IesInterfaceConfiguration &interface, packet::Ipv6 address,
                 std::uint8_t prefix_length) {
  if (ip::is_unspecified(address) || ip::is_multicast(address) ||
      prefix_length > 128U)
    return false;
  if (interface.address_configured && interface.address == address &&
      interface.prefix_length == prefix_length)
    return false;
  interface.address = address;
  interface.prefix_length = prefix_length;
  interface.address_configured = true;
  if (std::any_of(interface.mac.begin(), interface.mac.end(),
                  [](std::uint8_t byte) { return byte != 0U; }))
    interface.link_local = ip::link_local_from_mac(interface.mac);
  return true;
}

bool clear_address(IesInterfaceConfiguration &interface) {
  if (!interface.address_configured)
    return false;
  interface.address = {};
  interface.link_local = {};
  interface.prefix_length = 0U;
  interface.address_configured = false;
  // DHCPv6 relay depends on an addressed routed interface. Removing the
  // address while retaining an active child would create invalid running
  // state, so the command is rejected by final validation unless relay was
  // removed first. We deliberately do not cascade-delete operator intent.
  return true;
}

bool configure_relay_leaf(Dhcpv6RelayConfiguration &relay) noexcept {
  relay.configured = true;
  return true;
}

std::optional<dhcpv6::RelayDestination>
relay_destination(const Configuration &configuration,
                  std::string_view text) noexcept {
  const auto separator = text.find('-');
  const auto address = ip::parse_ipv6(text.substr(0U, separator));
  if (!address || ip::is_unspecified(*address) || ip::is_multicast(*address))
    return std::nullopt;
  if (!ip::is_link_local(*address))
    return separator == std::string_view::npos
               ? std::optional<dhcpv6::RelayDestination>{
                     {.address = *address, .scope_interface_id = 0U}}
               : std::nullopt;
  if (separator == std::string_view::npos)
    return std::nullopt;
  const auto zone = text.substr(separator + 1U);
  std::uint64_t resolved{};
  for (const auto &service : configuration.ies_services) {
    const auto found = std::find_if(
        service.interfaces.begin(), service.interfaces.end(),
        [&](const auto &interface) { return interface.name == zone; });
    if (found == service.interfaces.end())
      continue;
    // More than one matching interface name makes the RFC 4007 zone
    // ambiguous. Reject it rather than selecting by vector order.
    if (resolved != 0U)
      return std::nullopt;
    resolved = found->logical_id;
  }
  return resolved != 0U
             ? std::optional<dhcpv6::RelayDestination>{
                   {.address = *address, .scope_interface_id = resolved}}
             : std::nullopt;
}

std::optional<bool> boolean_value(const cli_detail::ParsedCommand &command) {
  const auto text = value(command, TokenKind::boolean);
  if (text == "true")
    return true;
  if (text == "false")
    return false;
  return std::nullopt;
}

struct InterfaceAddress {
  packet::Ipv6 address{};
  std::uint8_t prefix_length{};
};

std::optional<InterfaceAddress>
parse_interface_address(std::string_view text) noexcept {
  // The generic prefix parser intentionally rejects host bits because it is
  // used for route destinations. A routed interface address normally contains
  // host bits, so split the same textual form while retaining the exact host
  // address in the service datastore.
  const auto slash = text.rfind('/');
  if (slash == std::string_view::npos)
    return std::nullopt;
  const auto address = ip::parse_ipv6(text.substr(0U, slash));
  const auto prefix = decimal<std::uint8_t>(text.substr(slash + 1U));
  if (!address || !prefix || *prefix > 128U)
    return std::nullopt;
  return InterfaceAddress{.address = *address, .prefix_length = *prefix};
}

bool edit_relay(const Configuration &configuration,
                Dhcpv6RelayConfiguration &relay,
                IesInterfaceConfiguration &, CommandId id,
                const cli_detail::ParsedCommand &command) {
  using enum CommandId;
  if (id == md_delete_ies_relay || id == classic_ies_relay_remove) {
    if (!relay.configured)
      return false;
    relay = {};
    return true;
  }
  configure_relay_leaf(relay);
  if (id == md_ies_relay_admin_enable || id == classic_ies_relay_no_shutdown)
    return set_distinct(relay.admin_enabled, true);
  if (id == md_ies_relay_admin_disable || id == classic_ies_relay_shutdown)
    return set_distinct(relay.admin_enabled, false);

  if (id == md_ies_relay_server || id == classic_ies_relay_server ||
      id == md_delete_ies_relay_server) {
    const auto destination = relay_destination(
        configuration, value(command, TokenKind::ipv6_with_zone));
    if (!destination)
      return false;
    const auto found = std::find(relay.servers.begin(), relay.servers.end(),
                                 *destination);
    if (id == md_delete_ies_relay_server) {
      if (found == relay.servers.end())
        return false;
      relay.servers.erase(found);
      return true;
    }
    if (found != relay.servers.end() ||
        relay.servers.size() >=
            device_catalog::dhcpv6_relay_servers_per_interface)
      return false;
    relay.servers.push_back(*destination);
    return true;
  }
  if (id == classic_ies_relay_no_server) {
    if (relay.servers.empty())
      return false;
    relay.servers.clear();
    return true;
  }

  const auto address_leaf = [&](std::optional<packet::Ipv6> &leaf,
                                bool deleting) {
    if (deleting) {
      if (!leaf)
        return false;
      leaf.reset();
      return true;
    }
    const auto address = ip::parse_ipv6(value(command, TokenKind::ipv6));
    if (!address || ip::is_unspecified(*address) || ip::is_multicast(*address))
      return false;
    return set_distinct(leaf, std::optional<packet::Ipv6>{*address});
  };
  if (id == md_ies_relay_link_address ||
      id == md_delete_ies_relay_link_address ||
      id == classic_ies_relay_link_address ||
      id == classic_ies_relay_no_link_address)
    return address_leaf(relay.link_address,
                        id == md_delete_ies_relay_link_address ||
                            id == classic_ies_relay_no_link_address);
  if (id == md_ies_relay_source_address ||
      id == md_delete_ies_relay_source_address ||
      id == classic_ies_relay_source_address ||
      id == classic_ies_relay_no_source_address)
    return address_leaf(relay.source_address,
                        id == md_delete_ies_relay_source_address ||
                            id == classic_ies_relay_no_source_address);

  if (id == md_ies_relay_neighbor_resolution) {
    const auto enabled = boolean_value(command);
    return enabled && set_distinct(relay.neighbor_resolution, *enabled);
  }
  if (id == md_delete_ies_relay_neighbor_resolution ||
      id == classic_ies_relay_no_neighbor_resolution)
    return set_distinct(relay.neighbor_resolution, false);
  if (id == classic_ies_relay_neighbor_resolution)
    return set_distinct(relay.neighbor_resolution, true);

  if (id == md_delete_ies_relay_interface_id ||
      id == classic_ies_relay_no_interface_id) {
    if (relay.interface_id_kind == RelayInterfaceIdKind::absent)
      return false;
    relay.interface_id_kind = RelayInterfaceIdKind::absent;
    relay.interface_id_string.clear();
    return true;
  }
  if (id == md_ies_relay_interface_id_ascii ||
      id == classic_ies_relay_interface_id_ascii) {
    const bool changed = relay.interface_id_kind !=
                             RelayInterfaceIdKind::ascii_tuple ||
                         !relay.interface_id_string.empty();
    relay.interface_id_kind = RelayInterfaceIdKind::ascii_tuple;
    relay.interface_id_string.clear();
    return changed;
  }
  if (id == md_ies_relay_interface_id_sap ||
      id == classic_ies_relay_interface_id_sap) {
    const bool changed = relay.interface_id_kind != RelayInterfaceIdKind::sap_id ||
                         !relay.interface_id_string.empty();
    relay.interface_id_kind = RelayInterfaceIdKind::sap_id;
    relay.interface_id_string.clear();
    return changed;
  }
  if (id == md_ies_relay_interface_id_string ||
      id == classic_ies_relay_interface_id_string) {
    const auto text = value(command, TokenKind::relay_interface_id_string);
    if (text.empty() || text.size() > service::maximum_relay_interface_id_octets)
      return false;
    const bool changed = relay.interface_id_kind != RelayInterfaceIdKind::string ||
                         relay.interface_id_string != text;
    relay.interface_id_kind = RelayInterfaceIdKind::string;
    relay.interface_id_string.assign(text);
    return changed;
  }

  if (id == md_delete_ies_relay_lease_population ||
      id == classic_ies_relay_no_lease_population) {
    if (relay.lease_population_limit == 0U)
      return false;
    relay.lease_population_limit = 0U;
    relay.route_populate_na = false;
    relay.route_populate_pd = false;
    relay.route_populate_ta = false;
    relay.route_populate_pd_exclude = false;
    return true;
  }
  if (id == classic_ies_relay_lease_population) {
    // The classic command reference makes the count optional and defines one
    // entry when it is omitted. This is a semantic default of the command,
    // not an emulator resource default, so it is deliberately applied only
    // by the no-argument classic form.
    return set_distinct(relay.lease_population_limit, std::uint16_t{1U});
  }
  if (id == md_ies_relay_lease_limit || id == classic_ies_relay_lease_limit) {
    const auto limit = decimal<std::uint16_t>(
        value(command, TokenKind::relay_lease_limit));
    return limit && *limit != 0U && *limit <= service::maximum_relay_leases &&
           set_distinct(relay.lease_population_limit, *limit);
  }

  const auto set_route = [&](bool &leaf, bool next) {
    if (relay.lease_population_limit == 0U)
      return false;
    return set_distinct(leaf, next);
  };
  if (id == md_ies_relay_route_na) {
    const auto enabled = boolean_value(command);
    return enabled && set_route(relay.route_populate_na, *enabled);
  }
  if (id == md_delete_ies_relay_route_na ||
      id == classic_ies_relay_no_route_na)
    return set_route(relay.route_populate_na, false);
  if (id == classic_ies_relay_route_na)
    return set_route(relay.route_populate_na, true);
  if (id == md_ies_relay_route_pd_context || id == classic_ies_relay_route_pd)
    return set_route(relay.route_populate_pd, true);
  if (id == md_delete_ies_relay_route_pd ||
      id == classic_ies_relay_no_route_pd) {
    if (!relay.route_populate_pd && !relay.route_populate_pd_exclude)
      return false;
    relay.route_populate_pd = false;
    relay.route_populate_pd_exclude = false;
    return true;
  }
  if (id == md_ies_relay_route_pd ||
      id == classic_ies_relay_route_pd_exclude) {
    const auto enabled = id == md_ies_relay_route_pd
                             ? boolean_value(command)
                             : std::optional<bool>{true};
    if (!enabled || relay.lease_population_limit == 0U)
      return false;
    const bool changed = !relay.route_populate_pd ||
                         relay.route_populate_pd_exclude != *enabled;
    relay.route_populate_pd = true;
    relay.route_populate_pd_exclude = *enabled;
    return changed;
  }
  if (id == md_ies_relay_route_ta) {
    const auto enabled = boolean_value(command);
    return enabled && set_route(relay.route_populate_ta, *enabled);
  }
  if (id == md_delete_ies_relay_route_ta ||
      id == classic_ies_relay_no_route_ta)
    return set_route(relay.route_populate_ta, false);
  if (id == classic_ies_relay_route_ta)
    return set_route(relay.route_populate_ta, true);
  return false;
}

bool relay_command(CommandId id) noexcept {
  using enum CommandId;
  return (id >= md_ies_relay_admin_enable && id <= md_delete_ies_relay) ||
         (id >= classic_ies_relay_shutdown &&
          id <= classic_ies_relay_no_route_ta);
}

bool edit_impl(Configuration &configuration,
               const cli_detail::ParsedCommand &command, CliEngine engine,
               const RouterHardwareInventory &inventory,
               std::string_view system_name, std::string &instance) {
  using enum CommandId;
  const auto id = command.spec->id;
  const auto customer_name = value(command, TokenKind::customer_name);
  const auto service_name = value(command, TokenKind::service_name);
  const auto interface_name = value(command, TokenKind::service_interface_name);

  if (id == md_service_customer_id ||
      id == md_service_customer_description ||
      id == md_delete_service_customer) {
    instance = "/service/customer/" + std::string{customer_name};
    auto *customer = customer_by_name(configuration, customer_name);
    if (id == md_delete_service_customer) {
      if (!customer || std::any_of(configuration.ies_services.begin(),
                                   configuration.ies_services.end(),
                                   [&](const auto &service) {
                                     return service.customer_id != 0U &&
                                            service.customer_id ==
                                                customer->customer_id;
                                   }))
        return false;
      configuration.customers.erase(
          configuration.customers.begin() + (customer - configuration.customers.data()));
      return true;
    }
    if (!customer) {
      if (customer_name.empty())
        return false;
      configuration.customers.push_back(
          {.name = std::string{customer_name}});
      customer = &configuration.customers.back();
    }
    if (id == md_service_customer_id) {
      const auto number = decimal<std::uint32_t>(value(command, TokenKind::customer_id));
      return number && *number >= service::minimum_identifier &&
             *number <= service::maximum_identifier &&
             !customer_by_id(configuration, *number) &&
             set_distinct(customer->customer_id, *number);
    }
    return set_distinct(customer->description,
                        std::string{value(command, TokenKind::description)});
  }

  if (id == classic_service_customer_create ||
      id == classic_service_customer_description ||
      id == classic_service_no_customer) {
    const auto number = decimal<std::uint32_t>(value(command, TokenKind::customer_id));
    if (!number || *number < service::minimum_identifier ||
        *number > service::maximum_identifier)
      return false;
    instance = "/service/customer/" + std::to_string(*number);
    auto *customer = customer_by_id(configuration, *number);
    if (id == classic_service_customer_create) {
      if (customer)
        return false;
      configuration.customers.push_back({.name = std::to_string(*number),
                                         .customer_id = *number});
      return true;
    }
    if (!customer)
      return false;
    if (id == classic_service_no_customer) {
      if (std::any_of(configuration.ies_services.begin(),
                      configuration.ies_services.end(), [&](const auto &item) {
                        return item.customer_id == *number;
                      }))
        return false;
      configuration.customers.erase(configuration.customers.begin() +
                                    (customer - configuration.customers.data()));
      return true;
    }
    return set_distinct(customer->description,
                        std::string{value(command, TokenKind::description)});
  }

  if (id == md_service_port_mode || id == md_service_port_encapsulation ||
      id == md_delete_service_port_mode ||
      id == md_delete_service_port_encapsulation ||
      id == classic_service_port_mode ||
      id == classic_service_port_encapsulation) {
    const auto port_text = value(command, TokenKind::port_id);
    instance = "/port/" + std::string{port_text} + "/ethernet";
    auto *port = service_port(configuration, inventory, port_text, true);
    if (!port)
      return false;
    if (id == md_service_port_mode || id == classic_service_port_mode) {
      const auto text = value(command, TokenKind::ethernet_mode);
      const auto mode = text == "access" ? EthernetPortMode::access
                        : text == "network" ? EthernetPortMode::network
                        : text == "hybrid" ? EthernetPortMode::hybrid
                                            : EthernetPortMode::network;
      if (text != "access" && text != "network" && text != "hybrid")
        return false;
      return set_distinct(port->mode, mode);
    }
    if (id == md_delete_service_port_mode)
      return set_distinct(port->mode, EthernetPortMode::network);
    if (id == md_delete_service_port_encapsulation) {
      const bool changed = port->encapsulation != EthernetEncapsulation::null ||
                           port->outer_tpid != 0U;
      port->encapsulation = EthernetEncapsulation::null;
      port->outer_tpid = 0U;
      return changed;
    }
    const auto text = value(command, TokenKind::ethernet_encapsulation);
    const auto encapsulation = text == "null" ? EthernetEncapsulation::null
                               : text == "dot1q" ? EthernetEncapsulation::dot1q
                               : text == "qinq" ? EthernetEncapsulation::qinq
                                                : EthernetEncapsulation::null;
    if (text != "null" && text != "dot1q" && text != "qinq")
      return false;
    const std::uint16_t tpid = encapsulation == EthernetEncapsulation::null
                                   ? 0U
                                   : 0x8100U;
    const bool changed = port->encapsulation != encapsulation ||
                         port->outer_tpid != tpid;
    port->encapsulation = encapsulation;
    port->outer_tpid = tpid;
    return changed;
  }

  IesConfiguration *ies{};
  if (engine == CliEngine::md) {
    ies = id == md_delete_ies ? service_by_name(configuration, service_name)
                              : md_service(configuration, service_name);
  } else {
    const auto service_id = decimal<std::uint32_t>(value(command, TokenKind::service_id));
    if (!service_id)
      return false;
    ies = service_by_id(configuration, *service_id);
    if (id == classic_ies_create) {
      const auto customer_id = decimal<std::uint32_t>(value(command, TokenKind::customer_id));
      if (ies || !customer_id || !customer_by_id(configuration, *customer_id))
        return false;
      configuration.ies_services.push_back({.service_id = *service_id,
                                            .customer_id = *customer_id,
                                            .name = std::to_string(*service_id),
                                            .admin_enabled = false});
      instance = instance_path(configuration.ies_services.back().name);
      return true;
    }
  }
  if (!ies)
    return false;
  instance = instance_path(ies->name, interface_name);

  if (id == md_delete_ies || id == classic_ies_no_service) {
    if (ies->admin_enabled || !ies->interfaces.empty())
      return false;
    configuration.ies_services.erase(configuration.ies_services.begin() +
                                     (ies - configuration.ies_services.data()));
    return true;
  }
  if (id == md_ies_service_id) {
    const auto number = decimal<std::uint32_t>(value(command, TokenKind::service_id));
    return number && *number >= service::minimum_identifier &&
           *number <= service::maximum_identifier &&
           !service_by_id(configuration, *number) &&
           set_distinct(ies->service_id, *number);
  }
  if (id == md_ies_customer) {
    const auto *customer = customer_by_name(configuration, customer_name);
    return customer && customer->customer_id != 0U &&
           set_distinct(ies->customer_id, customer->customer_id);
  }
  if (id == md_ies_description || id == classic_ies_description)
    return set_distinct(ies->description,
                        std::string{value(command, TokenKind::description)});
  if (id == md_ies_admin_enable || id == classic_ies_no_shutdown)
    return set_distinct(ies->admin_enabled, true);
  if (id == md_ies_admin_disable || id == classic_ies_shutdown)
    return set_distinct(ies->admin_enabled, false);

  IesInterfaceConfiguration *interface{};
  if (engine == CliEngine::md) {
    interface = id == md_delete_ies_interface
                    ? interface_by_name(*ies, interface_name)
                    : md_interface(configuration, *ies, interface_name);
  } else {
    interface = interface_by_name(*ies, interface_name);
    if (id == classic_ies_interface_create) {
      if (interface)
        return false;
      const auto logical_id = next_logical_id(configuration);
      if (!logical_id || interface_name.empty())
        return false;
      ies->interfaces.push_back({.logical_id = *logical_id,
                                 .name = std::string{interface_name},
                                 .ip_mtu = 1500U,
                                 .admin_enabled = false});
      return true;
    }
  }
  if (!interface)
    return false;
  if (id == md_delete_ies_interface || id == classic_ies_no_interface) {
    if (interface->admin_enabled || interface->sap != SapKey{})
      return false;
    ies->interfaces.erase(ies->interfaces.begin() +
                          (interface - ies->interfaces.data()));
    return true;
  }
  if (id == md_ies_interface_admin_enable ||
      id == classic_ies_interface_no_shutdown)
    return set_distinct(interface->admin_enabled, true);
  if (id == md_ies_interface_admin_disable ||
      id == classic_ies_interface_shutdown)
    return set_distinct(interface->admin_enabled, false);
  if (id == md_ies_interface_description ||
      id == classic_ies_interface_description)
    return set_distinct(interface->description,
                        std::string{value(command, TokenKind::description)});
  if (id == md_ies_interface_mtu || id == classic_ies_interface_mtu) {
    const auto mtu = decimal<std::uint16_t>(value(command, TokenKind::mtu));
    return mtu && *mtu >= 1280U && set_distinct(interface->ip_mtu, *mtu);
  }
  if (id == md_ies_interface_ipv6_address) {
    const auto address = ip::parse_ipv6(value(command, TokenKind::ipv6));
    const auto prefix = decimal<std::uint8_t>(value(command, TokenKind::ipv6_prefix_length));
    return address && prefix && set_address(*interface, *address, *prefix);
  }
  if (id == classic_ies_interface_ipv6_address) {
    const auto prefix = parse_interface_address(
        value(command, TokenKind::ipv6_address_prefix));
    return prefix && set_address(*interface, prefix->address,
                                 prefix->prefix_length);
  }
  if (id == md_delete_ies_interface_ipv6_address ||
      id == classic_ies_interface_no_ipv6_address) {
    if (id == classic_ies_interface_no_ipv6_address) {
      const auto expected = parse_interface_address(
          value(command, TokenKind::ipv6_address_prefix));
      if (!expected || !interface->address_configured ||
          interface->address != expected->address ||
          interface->prefix_length != expected->prefix_length)
        return false;
    }
    return clear_address(*interface);
  }

  if (id == md_ies_interface_sap || id == classic_ies_interface_sap_create) {
    const auto sap_text = value(command, TokenKind::sap_id);
    const auto sap = parse_sap(configuration, inventory, sap_text);
    const auto mac = sap ? inventory.physical_mac(
                               sap_text.substr(0U, sap_text.find(':')))
                         : std::optional<packet::Mac>{};
    if (!sap || !mac || interface->sap != SapKey{})
      return false;
    interface->sap = *sap;
    interface->mac = *mac;
    if (interface->address_configured)
      interface->link_local = ip::link_local_from_mac(*mac);
    return true;
  }
  if (id == md_delete_ies_interface_sap ||
      id == classic_ies_interface_no_sap) {
    const auto expected = parse_sap(configuration, inventory,
                                    value(command, TokenKind::sap_id));
    if (interface->admin_enabled || !expected || interface->sap != *expected)
      return false;
    interface->sap = {};
    interface->mac = {};
    interface->link_local = {};
    return true;
  }

  if (relay_command(id)) {
    // ASCII tuple requires the access-node identifier. Until a dedicated
    // release leaf is exposed, use the configured system name as the explicit
    // canonical identifier only when the operator selects this encoding.
    if ((id == md_ies_relay_interface_id_ascii ||
         id == classic_ies_relay_interface_id_ascii) &&
        configuration.access_node_identifier.empty())
      configuration.access_node_identifier.assign(system_name);
    return edit_relay(configuration, interface->dhcpv6_relay, *interface, id,
                      command);
  }
  return false;
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= md_service_customer_id && id <= md_delete_ies_relay;
}

bool is_classic_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= classic_service_customer_create &&
         id <= classic_ies_relay_no_route_ta;
}

EditResult edit(Configuration &configuration,
                const cli_detail::ParsedCommand &command, CliEngine engine,
                const RouterHardwareInventory &inventory,
                std::string_view system_name) {
  const bool recognized = command.spec &&
                          (engine == CliEngine::md
                               ? is_md_command(command.spec->id)
                               : is_classic_command(command.spec->id));
  if (!recognized)
    return {};
  const auto before = configuration;
  std::string instance;
  const bool edited = edit_impl(configuration, command, engine, inventory,
                                system_name, instance);
  // Classic changes become running immediately and therefore require the full
  // relationship validator. MD may omit mandatory leaves until commit, but it
  // must still preserve every relationship that can already be checked. Using
  // the candidate validator here prevents a single MD edit from introducing a
  // duplicate key, malformed SAP or impossible relay dependency that would
  // otherwise survive until a later commit attempt.
  const bool structurally_changed = edited && configuration != before;
  const auto validation = engine == CliEngine::md
                              ? service::validate_candidate(configuration)
                              : service::validate(configuration);
  const bool valid = validation == service::ValidationError::none;
  if (!structurally_changed || !valid) {
    configuration = before;
    return {.recognized = true, .changed = false, .instance = std::move(instance)};
  }
  return {.recognized = true, .changed = true, .instance = std::move(instance)};
}

} // namespace router::lab::ies_cli
