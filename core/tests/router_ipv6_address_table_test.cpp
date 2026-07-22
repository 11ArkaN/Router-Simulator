// Native router address-table tests cover atomic replacement, documented
// interface scale and deterministic primary selection independently from CLI.

#include "router/router_ipv6_address_table.hpp"

#include "router/interface_identity.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::packet::Ipv6 address(const char *text) {
  const auto value = router::ip::parse_ipv6(text);
  if (!value)
    throw std::runtime_error("invalid IPv6 address fixture");
  return *value;
}

router::lab::RouterIpv6Address record(const char *text,
                                      std::uint16_t port,
                                      std::uint32_t preference) {
  const auto value = address(text);
  return {.address = value,
          .network = router::ip::mask(value, 64U),
          .interface_id = router::lab::physical_interface_id(port),
          .primary_preference = preference,
          .port_ordinal = port,
          .prefix_length = 64U};
}

} // namespace

void router_ipv6_address_table_tests() {
  using namespace router::lab;
  RouterIpv6AddressTable table;
  const std::array initial{record("2001:db8:1::2", 1U, 20U),
                           record("2001:db8:1::1", 1U, 10U),
                           record("2001:db8:2::1", 2U, 1U)};
  require(table.program(initial) ==
              RouterIpv6AddressProgramStatus::accepted,
          "valid multiple IPv6 addresses were rejected");
  require(table.records().size() == 3U &&
              table.interface_count(physical_interface_id(1U)) == 2U,
          "address generation lost an interface member");
  const auto *primary = table.primary(physical_interface_id(1U));
  require(primary && primary->address == address("2001:db8:1::1"),
          "lowest primary preference was not selected");
  require(table.owner(address("2001:db8:2::1")) &&
              table.find(physical_interface_id(2U),
                         address("2001:db8:2::1")),
          "address ownership lookup lost the physical interface");

  const std::array duplicate{record("2001:db8:3::1", 3U, 1U),
                             record("2001:db8:3::1", 4U, 1U)};
  require(table.program(duplicate) ==
              RouterIpv6AddressProgramStatus::duplicate_address &&
              table.records().size() == initial.size(),
          "rejected duplicate partially replaced the live generation");

  std::array<RouterIpv6Address,
             router::device_catalog::network_interface_ip_addresses + 1U>
      over_limit{};
  for (std::size_t index = 0; index < over_limit.size(); ++index) {
    auto value = address("2001:db8:4::1");
    value[15] = static_cast<std::uint8_t>(index + 1U);
    over_limit[index] = {.address = value,
                         .network = router::ip::mask(value, 64U),
                         .interface_id = physical_interface_id(4U),
                         .primary_preference =
                             static_cast<std::uint32_t>(index),
                         .port_ordinal = 4U,
                         .prefix_length = 64U};
  }
  require(table.program(over_limit) ==
              RouterIpv6AddressProgramStatus::interface_limit_exceeded &&
              table.records().size() == initial.size(),
          "documented per-interface address limit was not atomic");
}
