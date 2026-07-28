// Canonical Base-router DHCPv4 server configuration shared by management,
// persistence and the protocol compiler. The control-plane shard owns this
// intent. Forwarding and packet modules may consume a validated compiled copy,
// but they may not mutate or reinterpret operator-visible names and defaults.

#pragma once

#include "router/dhcpv4_packet.hpp"
#include "router/generated_device_catalog.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace router::dhcpv4::configuration {

enum class FailoverControlType : std::uint8_t {
  local,
  remote,
};

enum class OptionValueKind : std::uint8_t {
  ascii_string,
  hexadecimal,
  duration,
  empty,
  ipv4_address,
  netbios_node_type,
};

struct Option {
  // The numeric code remains authoritative even for SR OS keyword aliases.
  // Raw bytes preserve options not interpreted by the current endpoint while
  // kind retains enough intent for exact info rendering and validation.
  std::uint8_t code{};
  OptionValueKind kind{OptionValueKind::hexadecimal};
  std::vector<std::uint8_t> value{};
  bool operator==(const Option &) const = default;
};

struct AddressRange {
  packet::Ipv4 first{};
  packet::Ipv4 last{};
  FailoverControlType failover_control{FailoverControlType::local};
  bool operator==(const AddressRange &) const = default;
};

struct ExcludedRange {
  packet::Ipv4 first{};
  packet::Ipv4 last{};
  bool operator==(const ExcludedRange &) const = default;
};

struct Subnet {
  // This persistent key scopes relay-only bindings when no physical Base
  // interface owns the subnet. Directly attached subnets compile to their
  // physical interface identity, while this key survives list reordering.
  std::uint64_t allocation_scope_id{};
  packet::Ipv4 network{};
  std::uint8_t prefix_length{};
  std::uint32_t maximum_declined{
      device_catalog::dhcpv4_maximum_declined_default};
  bool drain{};
  std::vector<AddressRange> address_ranges{};
  std::vector<ExcludedRange> excluded_ranges{};
  std::vector<Option> options{};
  bool operator==(const Subnet &) const = default;
};

struct Pool {
  std::string name{};
  std::string description{};
  std::uint32_t minimum_lease_seconds{
      device_catalog::dhcpv4_minimum_lease_time_seconds};
  std::uint32_t maximum_lease_seconds{
      device_catalog::dhcpv4_maximum_lease_time_seconds};
  std::uint32_t offer_seconds{device_catalog::dhcpv4_offer_time_seconds};
  bool nak_non_matching_subnet{};
  std::vector<Option> options{};
  std::vector<Subnet> subnets{};
  bool operator==(const Pool &) const = default;
};

struct Server {
  // Runtime lease scope uses this persistent identity, not vector position.
  // Deleting or reordering another named server therefore cannot reassign
  // existing bindings to a different protocol instance after checkpoint.
  std::uint32_t instance_id{};
  std::string name{};
  std::string description{};
  bool force_renews{};
  bool admin_enabled{};
  std::vector<Pool> pools{};
  bool operator==(const Server &) const = default;
};

struct RouterConfiguration {
  std::vector<Server> servers{};
  bool operator==(const RouterConfiguration &) const = default;
};

enum class Status : std::uint8_t {
  valid,
  resource_exhausted,
  duplicate_server,
  duplicate_pool,
  invalid_name,
  invalid_description,
  invalid_lease_time,
  invalid_offer_time,
  invalid_subnet,
  invalid_address_range,
  overlapping_address_range,
  invalid_excluded_range,
  overlapping_excluded_range,
  exclusion_outside_range,
  invalid_option,
};

// Validation is all-or-nothing and allocation free after the configuration
// vectors have been built. allow_incomplete is reserved for an interactive MD
// candidate whose list keys exist before mandatory child leaves are entered.
[[nodiscard]] Status validate(const RouterConfiguration &configuration,
                              bool allow_incomplete = false) noexcept;

} // namespace router::dhcpv4::configuration
