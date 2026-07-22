// Control-owned configuration graph for Internet Enhanced Service instances.
// The service owner validates customer, port, SAP, routed-interface and DHCPv6
// relay relationships before any immutable generation reaches forwarding. It
// depends only on packet and protocol value types and never calls hardware,
// forwarding, CLI, persistence or UI owners.

#pragma once

#include "router/dhcpv6_relay.hpp"
#include "router/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::service {

inline constexpr std::uint32_t minimum_identifier = 1U;
inline constexpr std::uint32_t maximum_identifier = 2'147'483'647U;
inline constexpr std::size_t maximum_service_name_octets = 64U;
inline constexpr std::size_t maximum_interface_name_octets = 32U;
inline constexpr std::size_t maximum_description_octets = 80U;
inline constexpr std::size_t maximum_relay_interface_id_octets = 80U;
inline constexpr std::uint16_t maximum_vlan_identifier = 4094U;
inline constexpr std::uint16_t maximum_relay_leases = 8000U;

enum class EthernetPortMode : std::uint8_t { network, access, hybrid };
enum class EthernetEncapsulation : std::uint8_t { null, dot1q, qinq };

// A physical coordinate is stored beside the inventory ordinal because they
// serve different contracts. The ordinal is an efficient local array key. The
// three visible numbers are the stable SR OS port identifier used in SAP text,
// checkpoints and Interface-Id. Rebuilding inventory cannot turn an ordinal
// into user-visible or wire-visible syntax accidentally.
struct PhysicalPortCoordinate {
  std::uint16_t ordinal{};
  std::uint16_t card{};
  std::uint16_t mda{};
  std::uint16_t port{};

  [[nodiscard]] friend constexpr bool
  operator==(const PhysicalPortCoordinate &,
             const PhysicalPortCoordinate &) noexcept = default;
};

struct EthernetPortConfiguration {
  PhysicalPortCoordinate coordinate{};
  EthernetPortMode mode{EthernetPortMode::network};
  EthernetEncapsulation encapsulation{EthernetEncapsulation::null};
  // Zero belongs only to null encapsulation. Tagged ports retain their actual
  // configured outer TPID, so QinQ is not silently equated with one EtherType.
  std::uint16_t outer_tpid{};

  // Candidate comparison is structural: changing only port classification
  // must still trigger service validation and a new forwarding generation.
  [[nodiscard]] friend constexpr bool
  operator==(const EthernetPortConfiguration &,
             const EthernetPortConfiguration &) noexcept = default;
};

// The tag stack is an exact classifier, not a display shortcut. Null SAPs have
// no VLAN identifiers, dot1q SAPs have only outer_vlan, and QinQ SAPs have both
// identifiers. Priority bits are deliberately absent because SAP identity is
// based on VID while the frame codec preserves PCP and DEI on the wire.
struct SapKey {
  PhysicalPortCoordinate port{};
  EthernetEncapsulation encapsulation{EthernetEncapsulation::null};
  std::optional<std::uint16_t> outer_vlan{};
  std::optional<std::uint16_t> inner_vlan{};

  [[nodiscard]] friend constexpr bool operator==(const SapKey &,
                                                 const SapKey &) noexcept =
      default;
};

enum class RelayInterfaceIdKind : std::uint8_t {
  absent,
  ascii_tuple,
  ifindex,
  sap_id,
  string
};

struct Dhcpv6RelayConfiguration {
  bool configured{};
  bool admin_enabled{};
  bool neighbor_resolution{};
  // The Relay-Forward link address selects the DHCPv6 server allocation
  // scope. It is a different wire field from the outer IPv6 source address.
  std::optional<packet::Ipv6> link_address{};
  std::optional<packet::Ipv6> source_address{};
  std::vector<dhcpv6::RelayDestination> servers{};
  RelayInterfaceIdKind interface_id_kind{RelayInterfaceIdKind::absent};
  std::string interface_id_string{};
  std::uint16_t lease_population_limit{};
  bool route_populate_na{};
  bool route_populate_pd{};
  bool route_populate_ta{};
  bool route_populate_pd_exclude{};

  // The management datastore compares the complete relay policy. Omitting a
  // leaf here could make commit report no change while the candidate differs.
  [[nodiscard]] friend bool
  operator==(const Dhcpv6RelayConfiguration &,
             const Dhcpv6RelayConfiguration &) noexcept = default;
};

struct IesInterfaceConfiguration {
  // logical_id is allocated by the service owner and never derived from vector
  // position or port ordinal. All FIB, ND, relay and checkpoint references use
  // it so a single port may own many tagged interfaces without aliasing state.
  std::uint64_t logical_id{};
  std::string name{};
  std::string description{};
  SapKey sap{};
  packet::Mac mac{};
  packet::Ipv6 address{};
  packet::Ipv6 link_local{};
  std::uint8_t prefix_length{};
  std::uint16_t ip_mtu{1500U};
  bool address_configured{};
  bool admin_enabled{};
  Dhcpv6RelayConfiguration dhcpv6_relay{};

  [[nodiscard]] friend bool
  operator==(const IesInterfaceConfiguration &,
             const IesInterfaceConfiguration &) noexcept = default;
};

struct CustomerConfiguration {
  // MD-CLI keys customers by a printable name and stores customer-id as a
  // distinct mandatory leaf. Classic CLI uses the decimal ID as its natural
  // default name, so both engines share one lossless canonical record.
  std::string name{};
  std::uint32_t customer_id{};
  std::string description{};

  [[nodiscard]] friend bool
  operator==(const CustomerConfiguration &,
             const CustomerConfiguration &) noexcept = default;
};

struct IesConfiguration {
  std::uint32_t service_id{};
  std::uint32_t customer_id{};
  std::string name{};
  std::string description{};
  bool admin_enabled{};
  std::vector<IesInterfaceConfiguration> interfaces{};

  [[nodiscard]] friend bool
  operator==(const IesConfiguration &, const IesConfiguration &) noexcept =
      default;
};

struct Configuration {
  std::string access_node_identifier{};
  std::vector<EthernetPortConfiguration> ports{};
  std::vector<CustomerConfiguration> customers{};
  std::vector<IesConfiguration> ies_services{};

  // ConfigurationIntent uses value equality to implement MD candidate
  // comparison and to avoid republishing an unchanged immutable generation.
  [[nodiscard]] friend bool operator==(const Configuration &,
                                       const Configuration &) noexcept =
      default;
};

enum class ValidationError : std::uint8_t {
  none,
  resource_exhausted,
  invalid_access_node_identifier,
  invalid_port_coordinate,
  duplicate_port,
  invalid_port_encapsulation,
  invalid_customer,
  duplicate_customer,
  invalid_service,
  duplicate_service_id,
  duplicate_service_name,
  missing_customer,
  invalid_interface,
  duplicate_interface_id,
  duplicate_interface_name,
  missing_port,
  invalid_sap,
  duplicate_sap,
  invalid_ipv6_address,
  invalid_relay,
  unsupported_relay_interface_id
};

// Validation is allocation-free except for bounded uniqueness bookkeeping in
// the control plane. It reports the first deterministic error and never mutates
// configuration, so a candidate failure cannot partially change running state.
[[nodiscard]] ValidationError validate(const Configuration &configuration);

// MD candidate may contain a named list entry before all mandatory leaves are
// supplied. This validator preserves every structural, range, uniqueness and
// wire-value constraint while allowing only those missing relationships that
// commit will later reject through validate(). It exists for candidate
// checkpoint restore and must never authorize running publication.
[[nodiscard]] ValidationError
validate_candidate(const Configuration &configuration);

// Callers own output storage. Returning false leaves the output unchanged and
// means either the SAP is invalid or the supplied span cannot hold its exact SR
// OS text. The written view excludes a NUL terminator.
[[nodiscard]] bool format_sap_id(const SapKey &sap, std::span<char> output,
                                 std::string_view &written) noexcept;

// The generated bytes are exactly the opaque RFC 9915 Interface-Id value.
// nullopt means that the selected representation is unsupported or invalid,
// never that the option should be silently omitted.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> relay_interface_id(
    const Configuration &configuration, const IesConfiguration &service,
    const IesInterfaceConfiguration &interface);

} // namespace router::service
