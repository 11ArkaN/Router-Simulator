// IES configuration tests cover service graph identity, physical attachment,
// exact SAP rendering, DHCPv6 relay option construction and rejection of
// relationships that cannot exist on SR OS 26.7.R1.

#include "router/ies_service.hpp"

#include "router/ip_address.hpp"

#include <array>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

router::service::Configuration valid_configuration() {
  using namespace router;
  using namespace router::service;

  const auto address = ip::parse_ipv6("2001:db8:100::1");
  const auto link_local = ip::parse_ipv6("fe80::1");
  const auto server = ip::parse_ipv6("2001:db8:ffff::53");
  if (!address || !link_local || !server)
    throw std::runtime_error("IES fixture IPv6 address is invalid");

  Configuration result{};
  result.access_node_identifier = "edge-a";
  result.ports.push_back(
      {.coordinate = PhysicalPortCoordinate{0U, 1U, 1U, 1U},
       .mode = EthernetPortMode::hybrid,
       .encapsulation = EthernetEncapsulation::qinq,
       .outer_tpid = packet::ethernet_type_service_vlan});
  result.customers.push_back({"10", 10U, "Customer 10"});

  IesInterfaceConfiguration interface{};
  interface.logical_id = 0x100000001ULL;
  interface.name = "subscriber-v6";
  interface.description = "Dual-stack subscriber attachment";
  interface.sap = {PhysicalPortCoordinate{0U, 1U, 1U, 1U},
                   EthernetEncapsulation::qinq, std::uint16_t{200U},
                   std::uint16_t{300U}};
  interface.mac = packet::Mac{0x02U, 0x00U, 0x00U, 0x00U, 0x10U, 0x01U};
  interface.address = *address;
  interface.link_local = *link_local;
  interface.prefix_length = 64U;
  interface.ip_mtu = 1500U;
  interface.address_configured = true;
  interface.admin_enabled = true;
  interface.dhcpv6_relay.configured = true;
  interface.dhcpv6_relay.admin_enabled = true;
  interface.dhcpv6_relay.neighbor_resolution = true;
  interface.dhcpv6_relay.servers.push_back({*server, 0U});
  interface.dhcpv6_relay.interface_id_kind =
      RelayInterfaceIdKind::ascii_tuple;
  interface.dhcpv6_relay.lease_population_limit = 512U;
  interface.dhcpv6_relay.route_populate_na = true;
  interface.dhcpv6_relay.route_populate_pd = true;
  interface.dhcpv6_relay.route_populate_pd_exclude = true;

  IesConfiguration service{};
  service.service_id = 100U;
  service.customer_id = 10U;
  service.name = "internet-access";
  service.description = "Internet Enhanced Service";
  service.admin_enabled = true;
  service.interfaces.push_back(std::move(interface));
  result.ies_services.push_back(std::move(service));
  return result;
}

void require_error(const router::service::Configuration &configuration,
                   router::service::ValidationError expected,
                   const char *message) {
  if (router::service::validate(configuration) != expected)
    throw std::runtime_error(message);
}

} // namespace

void ies_service_tests() {
  using namespace router::service;

  auto configuration = valid_configuration();
  require_error(configuration, ValidationError::none,
                "valid QinQ IES graph was rejected");
  configuration.ports.front().outer_tpid = 0x9100U;
  require_error(configuration, ValidationError::none,
                "profiled provider EtherType was treated as a fixed TPID list");
  configuration = valid_configuration();

  std::array<char, 45U> sap_storage{};
  std::string_view sap_text{};
  if (!format_sap_id(configuration.ies_services[0].interfaces[0].sap,
                     sap_storage, sap_text) || sap_text != "1/1/1:200.300")
    throw std::runtime_error("QinQ SAP text did not preserve physical identity");

  const auto interface_id = relay_interface_id(
      configuration, configuration.ies_services[0],
      configuration.ies_services[0].interfaces[0]);
  const std::string expected_tuple = "edge-a|100|subscriber-v6";
  if (!interface_id ||
      std::string(interface_id->begin(), interface_id->end()) != expected_tuple)
    throw std::runtime_error("DHCPv6 ASCII tuple bytes were not exact");

  auto duplicate_logical = configuration;
  duplicate_logical.ies_services[0].interfaces.push_back(
      duplicate_logical.ies_services[0].interfaces[0]);
  duplicate_logical.ies_services[0].interfaces.back().name = "second";
  duplicate_logical.ies_services[0].interfaces.back().sap.outer_vlan =
      std::uint16_t{201U};
  require_error(duplicate_logical, ValidationError::duplicate_interface_id,
                "duplicate logical interface identity was accepted");

  auto network_sap = configuration;
  network_sap.ports[0].mode = EthernetPortMode::network;
  require_error(network_sap, ValidationError::invalid_sap,
                "network-only port accepted a service SAP");

  auto malformed_qinq = configuration;
  malformed_qinq.ies_services[0].interfaces[0].sap.inner_vlan.reset();
  require_error(malformed_qinq, ValidationError::invalid_sap,
                "QinQ SAP without inner VID was accepted");

  auto reserved_vlan = configuration;
  reserved_vlan.ies_services[0].interfaces[0].sap.outer_vlan =
      std::uint16_t{4095U};
  require_error(reserved_vlan, ValidationError::invalid_sap,
                "reserved VLAN identifier 4095 was accepted");

  auto route_without_leases = configuration;
  route_without_leases.ies_services[0]
      .interfaces[0]
      .dhcpv6_relay.lease_population_limit = 0U;
  require_error(route_without_leases, ValidationError::invalid_relay,
                "route population without a lease table was accepted");

  auto unsupported_ifindex = configuration;
  unsupported_ifindex.ies_services[0]
      .interfaces[0]
      .dhcpv6_relay.interface_id_kind = RelayInterfaceIdKind::ifindex;
  require_error(unsupported_ifindex,
                ValidationError::unsupported_relay_interface_id,
                "unverified ifIndex wire encoding was accepted");

  // Different tags on one access or hybrid port are distinct SAPs. This
  // guards against reintroducing the artificial one-interface-per-port model.
  auto shared_port = configuration;
  auto second = shared_port.ies_services[0].interfaces[0];
  second.logical_id = 0x100000002ULL;
  second.name = "subscriber-v6-b";
  second.sap.inner_vlan = std::uint16_t{301U};
  shared_port.ies_services[0].interfaces.push_back(std::move(second));
  require_error(shared_port, ValidationError::none,
                "distinct tagged SAPs on one hybrid port were rejected");

  auto duplicate_customer_name = configuration;
  duplicate_customer_name.customers.push_back(
      {.name = "10", .customer_id = 11U});
  require_error(duplicate_customer_name, ValidationError::duplicate_customer,
                "duplicate MD customer key was accepted");

  auto unattached = configuration;
  auto &unattached_interface = unattached.ies_services[0].interfaces[0];
  unattached_interface.sap = {};
  unattached_interface.mac = {};
  unattached_interface.link_local = {};
  unattached_interface.dhcpv6_relay = {};
  require_error(unattached, ValidationError::none,
                "classic interface without a SAP was rejected");

  auto partial_candidate = Configuration{};
  partial_candidate.customers.push_back(
      {.name = "tenant-a", .customer_id = 0U});
  partial_candidate.ies_services.push_back(
      {.service_id = 0U, .customer_id = 0U, .name = "internet"});
  partial_candidate.ies_services[0].interfaces.push_back(
      {.logical_id = 1U,
       .name = "subscriber",
       .ip_mtu = 1500U,
       .dhcpv6_relay = {.configured = true}});
  if (validate_candidate(partial_candidate) != ValidationError::none)
    throw std::runtime_error("structurally valid partial MD candidate rejected");
  require_error(partial_candidate, ValidationError::invalid_customer,
                "partial MD candidate was accepted as running state");

  auto invalid_candidate = partial_candidate;
  invalid_candidate.ies_services[0]
      .interfaces[0]
      .dhcpv6_relay.route_populate_na = true;
  if (validate_candidate(invalid_candidate) != ValidationError::invalid_relay)
    throw std::runtime_error(
        "partial MD candidate bypassed relay leaf dependency validation");
}
