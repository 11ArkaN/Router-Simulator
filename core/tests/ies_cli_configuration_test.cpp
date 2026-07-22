// IES CLI editor tests verify that generated MD and classic commands produce
// one canonical, strictly valid service graph. The inventory fixture is the
// only source of physical coordinates and MAC addresses, so these tests also
// guard against reintroducing fixed two-port or vector-index behavior.

#include "../src/ies_cli_configuration.hpp"
#include "router/interface_identity.hpp"

#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using router::CliEngine;
using router::MdCliWorkflow;
using router::cli_detail::ParsedCommand;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

ParsedCommand parse(CliEngine engine, std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(
      engine, engine == CliEngine::md ? MdCliWorkflow::explicit_private
                                      : MdCliWorkflow::operational,
      text);
  if (!parsed)
    throw std::runtime_error("generated IES command did not parse: " +
                             std::string{text});
  return *parsed;
}

void edit(router::service::Configuration &configuration, CliEngine engine,
          const router::lab::RouterHardwareInventory &inventory,
          std::string_view text) {
  const auto parsed = parse(engine, text);
  const auto result = router::lab::ies_cli::edit(
      configuration, parsed, engine, inventory, "edge-a");
  if (!result.recognized || !result.changed)
    throw std::runtime_error("IES command did not change configuration: " +
                             std::string{text});
}

router::lab::RouterHardwareInventory inventory() {
  const auto *profile = router::device_catalog::find_profile("7750-sr-1");
  require(profile != nullptr, "fixed hardware profile is missing");
  return router::lab::RouterHardwareInventory{{0U, 1U}, *profile};
}

} // namespace

void ies_cli_configuration_tests() {
  using router::CliEngine;
  using router::service::ValidationError;

  const auto hardware = inventory();

  // Classic CLI creates each object explicitly and every successful command
  // is valid running configuration immediately. The sequence intentionally
  // configures the address before SAP to exercise the real intermediate state.
  router::service::Configuration classic{};
  edit(classic, CliEngine::classic, hardware,
       "configure service customer 10 create");
  edit(classic, CliEngine::classic, hardware,
       "configure port 1/1/1 ethernet mode access");
  edit(classic, CliEngine::classic, hardware,
       "configure port 1/1/1 ethernet encap-type dot1q");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 customer 10 create");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber create");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 address "
       "2001:db8:100::1/64");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber sap 1/1/1:100 "
       "create");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
       "server 2001:db8:ffff::1");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
       "lease-populate");
  require(classic.ies_services[0]
                  .interfaces[0]
                  .dhcpv6_relay.lease_population_limit == 1U,
          "classic DHCPv6 lease-populate omitted-count default was not one");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
       "lease-populate 512");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
       "lease-populate route-populate na");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
       "no shutdown");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber no shutdown");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 no shutdown");
  require(router::service::validate(classic) == ValidationError::none,
          "classic IES command sequence did not produce valid running state");
  require(classic.ies_services[0].interfaces[0].sap.port.card == 1U &&
              classic.ies_services[0].interfaces[0].sap.port.mda == 1U &&
              classic.ies_services[0].interfaces[0].sap.port.port == 1U,
          "classic SAP did not retain the inventory coordinate");

  // A failed command restores the complete value, including a relay parent
  // that the attempted child edit would otherwise have materialized.
  const auto before_invalid = classic;
  const auto invalid = parse(
      CliEngine::classic,
      "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
      "link-address fe80::1");
  const auto invalid_result = router::lab::ies_cli::edit(
      classic, invalid, CliEngine::classic, hardware, "edge-a");
  require(invalid_result.recognized && !invalid_result.changed &&
              classic == before_invalid,
          "invalid relay edit partially changed classic running state");

  // MD list entries can be assembled in any candidate order. Mandatory IDs
  // are absent only transiently; the completed value must pass the same strict
  // running validator before LabRuntime can commit it.
  router::service::Configuration md{};
  edit(md, CliEngine::md, hardware,
       "configure service customer tenant-a customer-id 20");
  edit(md, CliEngine::md, hardware,
       "configure port 1/1/2 ethernet mode access");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet service-id 200");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet customer tenant-a");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet interface uplink ipv6 address "
       "2001:db8:200::1 prefix-length 64");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet interface uplink sap 1/1/2");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet interface uplink admin-state enable");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet admin-state enable");
  require(router::service::validate(md) == ValidationError::none,
          "complete MD candidate did not satisfy running IES validation");
  require(md.ies_services[0].interfaces[0].logical_id != 0U &&
              md.ies_services[0].interfaces[0].logical_id <
                  router::lab::physical_interface_namespace,
          "MD service interface did not receive a stable logical identity");

  const auto repeated = parse(
      CliEngine::md,
      "configure service ies internet interface uplink admin-state enable");
  const auto before_repeat = md;
  const auto repeated_result = router::lab::ies_cli::edit(
      md, repeated, CliEngine::md, hardware, "edge-a");
  require(repeated_result.recognized && !repeated_result.changed &&
              md == before_repeat,
          "repeated MD leaf was accepted as a successful no-op");
}
