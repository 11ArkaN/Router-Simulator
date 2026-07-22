// Pure IES configuration validation and DHCPv6 Interface-Id construction.
// This translation unit owns no running state. Keeping relationship checks
// here lets CLI, checkpoint restore and future northbound APIs use the same
// all-or-nothing rules before the service owner publishes a generation.

#include "router/ies_service.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <new>

namespace router::service {
namespace {

[[nodiscard]] bool printable_ascii(std::string_view text) noexcept {
  return std::all_of(text.begin(), text.end(), [](char value) {
    const auto octet = static_cast<unsigned char>(value);
    return octet >= 0x20U && octet <= 0x7eU;
  });
}

[[nodiscard]] bool usable_name(std::string_view text,
                               std::size_t maximum) noexcept {
  // SR OS permits spaces and punctuation in quoted names. Reject only empty,
  // oversized, non-printable, and all-space values here. Quoting belongs to
  // the terminal parser and must not leak into the canonical datastore.
  return !text.empty() && text.size() <= maximum && printable_ascii(text) &&
         std::any_of(text.begin(), text.end(),
                     [](char value) { return value != ' '; });
}

[[nodiscard]] bool valid_coordinate(
    const PhysicalPortCoordinate &coordinate) noexcept {
  // Ordinal zero is a valid array key. User-visible SR OS coordinates are
  // one-based, so only the three physical fields must be nonzero.
  return coordinate.card != 0U && coordinate.mda != 0U &&
         coordinate.port != 0U;
}

[[nodiscard]] bool same_physical_port(
    const PhysicalPortCoordinate &left,
    const PhysicalPortCoordinate &right) noexcept {
  // Both identities must agree. Accepting a matching coordinate with a
  // different ordinal would route configuration to the wrong packet owner.
  return left == right;
}

[[nodiscard]] bool valid_vlan(
    const std::optional<std::uint16_t> &vlan) noexcept {
  // VID 0 is a legal priority-tag value and remains a valid exact classifier.
  // VID 4095 is reserved by IEEE 802.1Q and is never a service identifier.
  return vlan && *vlan <= maximum_vlan_identifier;
}

[[nodiscard]] bool valid_unicast_mac(const packet::Mac &mac) noexcept {
  // The canonical service interface currently carries an explicit MAC. A
  // multicast or all-zero value cannot source Ethernet ND packets. A future
  // documented chassis-derived default must be represented as explicit
  // provenance, not by treating zero as a functioning address.
  return (mac[0U] & 1U) == 0U &&
         std::any_of(mac.begin(), mac.end(),
                     [](std::uint8_t octet) { return octet != 0U; });
}

[[nodiscard]] bool unspecified_mac(const packet::Mac &mac) noexcept {
  return std::all_of(mac.begin(), mac.end(),
                     [](std::uint8_t octet) { return octet == 0U; });
}

[[nodiscard]] bool valid_sap_shape(const SapKey &sap) noexcept {
  if (!valid_coordinate(sap.port))
    return false;
  switch (sap.encapsulation) {
  case EthernetEncapsulation::null:
    return !sap.outer_vlan && !sap.inner_vlan;
  case EthernetEncapsulation::dot1q:
    return valid_vlan(sap.outer_vlan) && !sap.inner_vlan;
  case EthernetEncapsulation::qinq:
    return valid_vlan(sap.outer_vlan) && valid_vlan(sap.inner_vlan);
  }
  return false;
}

[[nodiscard]] const EthernetPortConfiguration *find_port(
    const Configuration &configuration,
    const PhysicalPortCoordinate &coordinate) noexcept {
  const auto found = std::find_if(
      configuration.ports.begin(), configuration.ports.end(),
      [&](const EthernetPortConfiguration &port) {
        return same_physical_port(port.coordinate, coordinate);
      });
  return found == configuration.ports.end() ? nullptr : &*found;
}

[[nodiscard]] bool valid_relay_server(
    const dhcpv6::RelayDestination &server) noexcept {
  if (ip::is_unspecified(server.address) || ip::is_multicast(server.address))
    return false;
  // RFC 4007 zone identity is mandatory for link-local destinations and must
  // not be attached to global destinations. The value selects a logical local
  // interface, not another device or a direct delivery path.
  return ip::is_link_local(server.address)
             ? server.scope_interface_id != 0U
             : server.scope_interface_id == 0U;
}

[[nodiscard]] bool valid_relay(const Configuration &configuration,
                               const IesConfiguration &service,
                               const IesInterfaceConfiguration &interface)
    noexcept {
  const auto &relay = interface.dhcpv6_relay;
  if (!relay.configured) {
    // Children cannot survive deletion of their parent context. Rejecting a
    // populated disabled object prevents hidden configuration from reappearing
    // when the context is recreated later.
    return !relay.admin_enabled && !relay.neighbor_resolution &&
           !relay.link_address && !relay.source_address &&
           relay.servers.empty() &&
           relay.interface_id_kind == RelayInterfaceIdKind::absent &&
           relay.interface_id_string.empty() &&
           relay.lease_population_limit == 0U && !relay.route_populate_na &&
           !relay.route_populate_pd && !relay.route_populate_ta &&
           !relay.route_populate_pd_exclude;
  }
  if (!valid_coordinate(interface.sap.port) ||
      !interface.address_configured ||
      relay.servers.size() >
          device_catalog::dhcpv6_relay_servers_per_interface)
    return false;
  if (!std::all_of(relay.servers.begin(), relay.servers.end(),
                   valid_relay_server))
    return false;
  for (std::size_t left = 0; left < relay.servers.size(); ++left) {
    if (std::find(relay.servers.begin() + static_cast<std::ptrdiff_t>(left + 1U),
                  relay.servers.end(), relay.servers[left]) !=
        relay.servers.end())
      return false;
  }
  if (relay.source_address &&
      (ip::is_unspecified(*relay.source_address) ||
       ip::is_multicast(*relay.source_address)))
    return false;
  // SR OS documents link-address as the global allocation-scope selector,
  // not as an on-link or multicast destination.
  if (relay.link_address &&
      (ip::is_unspecified(*relay.link_address) ||
       ip::is_multicast(*relay.link_address) ||
       ip::is_link_local(*relay.link_address)))
    return false;
  if (relay.interface_id_kind == RelayInterfaceIdKind::string &&
      (relay.interface_id_string.empty() ||
       relay.interface_id_string.size() > maximum_relay_interface_id_octets ||
       !printable_ascii(relay.interface_id_string)))
    return false;
  if (relay.interface_id_kind != RelayInterfaceIdKind::string &&
      !relay.interface_id_string.empty())
    return false;
  if (relay.interface_id_kind == RelayInterfaceIdKind::ascii_tuple &&
      (!usable_name(configuration.access_node_identifier,
                    maximum_service_name_octets) ||
       configuration.access_node_identifier.size() + service.name.size() +
               interface.name.size() + 2U >
           std::numeric_limits<std::uint16_t>::max()))
    return false;
  if (relay.lease_population_limit > maximum_relay_leases)
    return false;
  const bool route_population = relay.route_populate_na ||
                                relay.route_populate_pd ||
                                relay.route_populate_ta ||
                                relay.route_populate_pd_exclude;
  if (route_population && relay.lease_population_limit == 0U)
    return false;
  if (relay.route_populate_pd_exclude && !relay.route_populate_pd)
    return false;
  return true;
}

[[nodiscard]] bool append_decimal(std::span<char> output, std::size_t &offset,
                                  std::uint16_t value) noexcept {
  if (offset >= output.size())
    return false;
  const auto converted = std::to_chars(output.data() + offset,
                                       output.data() + output.size(), value);
  if (converted.ec != std::errc{})
    return false;
  offset = static_cast<std::size_t>(converted.ptr - output.data());
  return true;
}

[[nodiscard]] bool append_character(std::span<char> output,
                                    std::size_t &offset,
                                    char value) noexcept {
  if (offset == output.size())
    return false;
  output[offset++] = value;
  return true;
}

} // namespace

ValidationError validate(const Configuration &configuration) {
  try {
    for (std::size_t index = 0; index < configuration.ports.size(); ++index) {
      const auto &port = configuration.ports[index];
      if (!valid_coordinate(port.coordinate))
        return ValidationError::invalid_port_coordinate;
      if (port.mode == EthernetPortMode::hybrid &&
          port.encapsulation == EthernetEncapsulation::null)
        return ValidationError::invalid_port_encapsulation;
      const bool tagged =
          port.encapsulation != EthernetEncapsulation::null;
      // IEEE 802.3 distinguishes an EtherType from an 802.3 length at 1536.
      // SR OS can profile a provider TPID other than 0x88a8, so accepting only
      // two familiar values would contradict the lossless SAP classifier and
      // reject valid hardware configuration such as 0x9100.
      const bool valid_tpid = port.outer_tpid >= 0x0600U;
      if ((tagged && !valid_tpid) || (!tagged && port.outer_tpid != 0U))
        return ValidationError::invalid_port_encapsulation;
      const auto duplicate = std::find_if(
          configuration.ports.begin() +
              static_cast<std::ptrdiff_t>(index + 1U),
          configuration.ports.end(), [&](const auto &candidate) {
            return candidate.coordinate.ordinal == port.coordinate.ordinal ||
                   (candidate.coordinate.card == port.coordinate.card &&
                    candidate.coordinate.mda == port.coordinate.mda &&
                    candidate.coordinate.port == port.coordinate.port);
          });
      if (duplicate != configuration.ports.end())
        return ValidationError::duplicate_port;
    }

    for (std::size_t index = 0; index < configuration.customers.size(); ++index) {
      const auto &customer = configuration.customers[index];
      if (!usable_name(customer.name, maximum_service_name_octets) ||
          customer.customer_id < minimum_identifier ||
          customer.customer_id > maximum_identifier ||
          customer.description.size() > maximum_description_octets ||
          !printable_ascii(customer.description))
        return ValidationError::invalid_customer;
      if (std::find_if(configuration.customers.begin() +
                           static_cast<std::ptrdiff_t>(index + 1U),
                       configuration.customers.end(), [&](const auto &other) {
                         return other.customer_id == customer.customer_id;
                       }) != configuration.customers.end())
        return ValidationError::duplicate_customer;
      if (std::find_if(configuration.customers.begin() +
                           static_cast<std::ptrdiff_t>(index + 1U),
                       configuration.customers.end(), [&](const auto &other) {
                         return other.name == customer.name;
                       }) != configuration.customers.end())
        return ValidationError::duplicate_customer;
    }

    std::vector<std::uint64_t> logical_ids{};
    std::vector<SapKey> sap_keys{};
    for (std::size_t service_index = 0;
         service_index < configuration.ies_services.size(); ++service_index) {
      const auto &service = configuration.ies_services[service_index];
      if (service.service_id < minimum_identifier ||
          service.service_id > maximum_identifier ||
          !usable_name(service.name, maximum_service_name_octets) ||
          service.description.size() > maximum_description_octets ||
          !printable_ascii(service.description))
        return ValidationError::invalid_service;
      const auto later = configuration.ies_services.begin() +
                         static_cast<std::ptrdiff_t>(service_index + 1U);
      if (std::find_if(later, configuration.ies_services.end(),
                       [&](const auto &other) {
                         return other.service_id == service.service_id;
                       }) != configuration.ies_services.end())
        return ValidationError::duplicate_service_id;
      if (std::find_if(later, configuration.ies_services.end(),
                       [&](const auto &other) {
                         return other.name == service.name;
                       }) != configuration.ies_services.end())
        return ValidationError::duplicate_service_name;
      if (std::none_of(configuration.customers.begin(),
                       configuration.customers.end(), [&](const auto &customer) {
                         return customer.customer_id == service.customer_id;
                       }))
        return ValidationError::missing_customer;

      for (std::size_t interface_index = 0;
           interface_index < service.interfaces.size(); ++interface_index) {
        const auto &interface = service.interfaces[interface_index];
        if (interface.logical_id == 0U ||
            !usable_name(interface.name, maximum_interface_name_octets) ||
            interface.description.size() > maximum_description_octets ||
            !printable_ascii(interface.description) || interface.ip_mtu < 1280U)
          return ValidationError::invalid_interface;
        if (std::find(logical_ids.begin(), logical_ids.end(),
                      interface.logical_id) != logical_ids.end())
          return ValidationError::duplicate_interface_id;
        logical_ids.push_back(interface.logical_id);
        if (std::find_if(service.interfaces.begin() +
                             static_cast<std::ptrdiff_t>(interface_index + 1U),
                         service.interfaces.end(), [&](const auto &other) {
                           return other.name == interface.name;
                         }) != service.interfaces.end())
          return ValidationError::duplicate_interface_name;

        const bool sap_configured = valid_coordinate(interface.sap.port);
        if (sap_configured) {
          if (!valid_unicast_mac(interface.mac) ||
              !valid_sap_shape(interface.sap))
            return ValidationError::invalid_sap;
          const auto *port = find_port(configuration, interface.sap.port);
          if (!port)
            return ValidationError::missing_port;
          if (port->mode == EthernetPortMode::network ||
              port->encapsulation != interface.sap.encapsulation ||
              (port->mode == EthernetPortMode::hybrid &&
               interface.sap.encapsulation == EthernetEncapsulation::null))
            return ValidationError::invalid_sap;
          if (std::find(sap_keys.begin(), sap_keys.end(), interface.sap) !=
              sap_keys.end())
            return ValidationError::duplicate_sap;
          sap_keys.push_back(interface.sap);
        } else if (interface.sap != SapKey{} ||
                   !unspecified_mac(interface.mac)) {
          // A classic interface can exist before its SAP is entered. Preserve
          // that real running state, but reject a partial coordinate or a MAC
          // that pretends an attachment already exists.
          return ValidationError::invalid_sap;
        }

        if (interface.address_configured &&
            (interface.prefix_length > 128U ||
             ip::is_unspecified(interface.address) ||
             ip::is_multicast(interface.address) ||
             (sap_configured && !ip::is_link_local(interface.link_local)) ||
             (!sap_configured &&
              !ip::is_unspecified(interface.link_local))))
          return ValidationError::invalid_ipv6_address;
        if (!interface.address_configured &&
            (!ip::is_unspecified(interface.address) ||
             !ip::is_unspecified(interface.link_local) ||
             interface.prefix_length != 0U))
          return ValidationError::invalid_ipv6_address;
        if (!valid_relay(configuration, service, interface))
          return ValidationError::invalid_relay;
        // Nokia documents selection of ifIndex but does not publish its exact
        // Interface-Id wire encoding. Until a release-matched capture supplies
        // that evidence, accepting this choice would manufacture wire bytes.
        if (interface.dhcpv6_relay.configured &&
            interface.dhcpv6_relay.interface_id_kind ==
                RelayInterfaceIdKind::ifindex)
          return ValidationError::unsupported_relay_interface_id;
      }
    }
    return ValidationError::none;
  } catch (const std::bad_alloc &) {
    // Candidate validation reports resource pressure without changing running
    // configuration. The caller can surface a deterministic management error.
    return ValidationError::resource_exhausted;
  }
}

ValidationError validate_candidate(const Configuration &configuration) {
  try {
    // Candidate port leaves already have effective defaults, so incomplete MD
    // semantics do not weaken their coordinate, TPID or uniqueness contract.
    for (std::size_t index = 0; index < configuration.ports.size(); ++index) {
      const auto &port = configuration.ports[index];
      const bool tagged = port.encapsulation != EthernetEncapsulation::null;
      if (!valid_coordinate(port.coordinate))
        return ValidationError::invalid_port_coordinate;
      if ((port.mode == EthernetPortMode::hybrid && !tagged) ||
          (tagged && port.outer_tpid < 0x0600U) ||
          (!tagged && port.outer_tpid != 0U))
        return ValidationError::invalid_port_encapsulation;
      if (std::find_if(configuration.ports.begin() +
                           static_cast<std::ptrdiff_t>(index + 1U),
                       configuration.ports.end(), [&](const auto &other) {
                         return other.coordinate.ordinal ==
                                    port.coordinate.ordinal ||
                                (other.coordinate.card == port.coordinate.card &&
                                 other.coordinate.mda == port.coordinate.mda &&
                                 other.coordinate.port == port.coordinate.port);
                       }) != configuration.ports.end())
        return ValidationError::duplicate_port;
    }

    for (std::size_t index = 0; index < configuration.customers.size(); ++index) {
      const auto &customer = configuration.customers[index];
      if (!usable_name(customer.name, maximum_service_name_octets) ||
          customer.customer_id > maximum_identifier ||
          customer.description.size() > maximum_description_octets ||
          !printable_ascii(customer.description))
        return ValidationError::invalid_customer;
      const auto later = configuration.customers.begin() +
                         static_cast<std::ptrdiff_t>(index + 1U);
      if (std::find_if(later, configuration.customers.end(),
                       [&](const auto &other) {
                         return other.name == customer.name ||
                                (customer.customer_id != 0U &&
                                 other.customer_id == customer.customer_id);
                       }) != configuration.customers.end())
        return ValidationError::duplicate_customer;
    }

    std::vector<std::uint64_t> logical_ids{};
    std::vector<SapKey> sap_keys{};
    for (std::size_t service_index = 0;
         service_index < configuration.ies_services.size(); ++service_index) {
      const auto &service = configuration.ies_services[service_index];
      if (!usable_name(service.name, maximum_service_name_octets) ||
          service.service_id > maximum_identifier ||
          service.customer_id > maximum_identifier ||
          service.description.size() > maximum_description_octets ||
          !printable_ascii(service.description))
        return ValidationError::invalid_service;
      const auto later = configuration.ies_services.begin() +
                         static_cast<std::ptrdiff_t>(service_index + 1U);
      if (std::find_if(later, configuration.ies_services.end(),
                       [&](const auto &other) {
                         return other.name == service.name;
                       }) != configuration.ies_services.end())
        return ValidationError::duplicate_service_name;
      if (service.service_id != 0U &&
          std::find_if(later, configuration.ies_services.end(),
                       [&](const auto &other) {
                         return other.service_id == service.service_id;
                       }) != configuration.ies_services.end())
        return ValidationError::duplicate_service_id;
      if (service.customer_id != 0U &&
          std::none_of(configuration.customers.begin(),
                       configuration.customers.end(), [&](const auto &customer) {
                         return customer.customer_id == service.customer_id;
                       }))
        return ValidationError::missing_customer;

      for (std::size_t interface_index = 0;
           interface_index < service.interfaces.size(); ++interface_index) {
        const auto &interface = service.interfaces[interface_index];
        if (interface.logical_id == 0U ||
            !usable_name(interface.name, maximum_interface_name_octets) ||
            interface.description.size() > maximum_description_octets ||
            !printable_ascii(interface.description) || interface.ip_mtu < 1280U)
          return ValidationError::invalid_interface;
        if (std::find(logical_ids.begin(), logical_ids.end(),
                      interface.logical_id) != logical_ids.end())
          return ValidationError::duplicate_interface_id;
        logical_ids.push_back(interface.logical_id);
        if (std::find_if(service.interfaces.begin() +
                             static_cast<std::ptrdiff_t>(interface_index + 1U),
                         service.interfaces.end(), [&](const auto &other) {
                           return other.name == interface.name;
                         }) != service.interfaces.end())
          return ValidationError::duplicate_interface_name;

        const bool sap_configured = valid_coordinate(interface.sap.port);
        if (sap_configured) {
          const auto *port = find_port(configuration, interface.sap.port);
          if (!valid_unicast_mac(interface.mac) ||
              !valid_sap_shape(interface.sap) || !port)
            return port ? ValidationError::invalid_sap
                        : ValidationError::missing_port;
          if (port->mode == EthernetPortMode::network ||
              port->encapsulation != interface.sap.encapsulation ||
              std::find(sap_keys.begin(), sap_keys.end(), interface.sap) !=
                  sap_keys.end())
            return ValidationError::invalid_sap;
          sap_keys.push_back(interface.sap);
        } else if (interface.sap != SapKey{} ||
                   !unspecified_mac(interface.mac)) {
          return ValidationError::invalid_sap;
        }

        if (interface.address_configured &&
            (interface.prefix_length > 128U ||
             ip::is_unspecified(interface.address) ||
             ip::is_multicast(interface.address) ||
             (sap_configured && !ip::is_link_local(interface.link_local)) ||
             (!sap_configured && !ip::is_unspecified(interface.link_local))))
          return ValidationError::invalid_ipv6_address;
        if (!interface.address_configured &&
            (!ip::is_unspecified(interface.address) ||
             !ip::is_unspecified(interface.link_local) ||
             interface.prefix_length != 0U))
          return ValidationError::invalid_ipv6_address;

        const auto &relay = interface.dhcpv6_relay;
        if (!relay.configured) {
          if (!valid_relay(configuration, service, interface))
            return ValidationError::invalid_relay;
          continue;
        }
        // A relay child may precede the interface address and SAP only inside
        // candidate. Every configured wire value and dependency among relay
        // leaves remains enforced before the checkpoint can be restored.
        if (relay.servers.size() >
                device_catalog::dhcpv6_relay_servers_per_interface ||
            !std::all_of(relay.servers.begin(), relay.servers.end(),
                         valid_relay_server) ||
            (relay.source_address &&
             (ip::is_unspecified(*relay.source_address) ||
              ip::is_multicast(*relay.source_address))) ||
            (relay.link_address &&
             (ip::is_unspecified(*relay.link_address) ||
              ip::is_multicast(*relay.link_address) ||
              ip::is_link_local(*relay.link_address))) ||
            relay.lease_population_limit > maximum_relay_leases ||
            ((relay.route_populate_na || relay.route_populate_pd ||
              relay.route_populate_ta || relay.route_populate_pd_exclude) &&
             relay.lease_population_limit == 0U) ||
            (relay.route_populate_pd_exclude && !relay.route_populate_pd))
          return ValidationError::invalid_relay;
        for (std::size_t left = 0; left < relay.servers.size(); ++left)
          if (std::find(relay.servers.begin() +
                           static_cast<std::ptrdiff_t>(left + 1U),
                       relay.servers.end(), relay.servers[left]) !=
              relay.servers.end())
            return ValidationError::invalid_relay;
        if (relay.interface_id_kind == RelayInterfaceIdKind::ifindex)
          return ValidationError::unsupported_relay_interface_id;
        if ((relay.interface_id_kind == RelayInterfaceIdKind::string &&
             (relay.interface_id_string.empty() ||
              relay.interface_id_string.size() >
                  maximum_relay_interface_id_octets ||
              !printable_ascii(relay.interface_id_string))) ||
            (relay.interface_id_kind != RelayInterfaceIdKind::string &&
             !relay.interface_id_string.empty()))
          return ValidationError::invalid_relay;
      }
    }
    return ValidationError::none;
  } catch (const std::bad_alloc &) {
    return ValidationError::resource_exhausted;
  }
}

bool format_sap_id(const SapKey &sap, std::span<char> output,
                   std::string_view &written) noexcept {
  if (!valid_sap_shape(sap))
    return false;
  std::array<char, 45U> temporary{};
  std::size_t offset{};
  if (!append_decimal(temporary, offset, sap.port.card) ||
      !append_character(temporary, offset, '/') ||
      !append_decimal(temporary, offset, sap.port.mda) ||
      !append_character(temporary, offset, '/') ||
      !append_decimal(temporary, offset, sap.port.port))
    return false;
  if (sap.encapsulation != EthernetEncapsulation::null &&
      (!append_character(temporary, offset, ':') ||
       !append_decimal(temporary, offset, *sap.outer_vlan)))
    return false;
  if (sap.encapsulation == EthernetEncapsulation::qinq &&
      (!append_character(temporary, offset, '.') ||
       !append_decimal(temporary, offset, *sap.inner_vlan)))
    return false;
  if (output.size() < offset)
    return false;
  std::copy_n(temporary.begin(), offset, output.begin());
  written = std::string_view{output.data(), offset};
  return true;
}

std::optional<std::vector<std::uint8_t>> relay_interface_id(
    const Configuration &configuration, const IesConfiguration &service,
    const IesInterfaceConfiguration &interface) {
  const auto &relay = interface.dhcpv6_relay;
  std::string text{};
  switch (relay.interface_id_kind) {
  case RelayInterfaceIdKind::absent:
    return std::vector<std::uint8_t>{};
  case RelayInterfaceIdKind::ascii_tuple:
    text.reserve(configuration.access_node_identifier.size() +
                 service.name.size() + interface.name.size() + 2U);
    text.append(configuration.access_node_identifier);
    text.push_back('|');
    text.append(std::to_string(service.service_id));
    text.push_back('|');
    text.append(interface.name);
    break;
  case RelayInterfaceIdKind::sap_id: {
    std::array<char, 45U> storage{};
    std::string_view sap_text{};
    if (!format_sap_id(interface.sap, storage, sap_text))
      return std::nullopt;
    text.assign(sap_text);
    break;
  }
  case RelayInterfaceIdKind::string:
    text = relay.interface_id_string;
    break;
  case RelayInterfaceIdKind::ifindex:
    return std::nullopt;
  }
  if (text.size() > std::numeric_limits<std::uint16_t>::max())
    return std::nullopt;
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

} // namespace router::service
