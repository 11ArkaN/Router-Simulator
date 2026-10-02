// IES CLI editor tests verify that generated MD and classic commands produce
// one canonical, strictly valid service graph. The inventory fixture is the
// only source of physical coordinates and MAC addresses, so these tests also
// guard against reintroducing fixed two-port or vector-index behavior.

#include "cli/ies_cli_configuration.hpp"
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
       "configure port 1/1/1 ethernet encap-type dot1q");
  edit(classic, CliEngine::classic, hardware,
       "configure port 1/1/1 ethernet mode hybrid");
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
  // Classic nbr-of-leases spans 1 through 8000. Zero and values above the
  // classic bound are rejected without touching running state.
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
       "lease-populate 8000");
  require(classic.ies_services[0]
                  .interfaces[0]
                  .dhcpv6_relay.lease_population_limit == 8000U,
          "classic relay lease limit did not accept 8000");
  for (const auto text :
       {"configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "lease-populate 8001",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "lease-populate 0"}) {
    const auto before_limit = classic;
    const auto rejected = router::lab::ies_cli::edit(
        classic, parse(CliEngine::classic, text), CliEngine::classic,
        hardware, "edge-a");
    require(rejected.recognized && !rejected.changed &&
                classic == before_limit,
            "out-of-range classic relay lease limit changed running state");
  }
  // The classic reference documents only `no lease-populate`: per-address
  // family `no` forms do not exist.
  for (const auto text :
       {"configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "lease-populate route-populate no na",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "lease-populate route-populate no pd",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "lease-populate route-populate no ta"})
    require(!router::cli_detail::parse_command(CliEngine::classic,
                                               MdCliWorkflow::operational,
                                               text)
                 .has_value(),
            "classic relay accepted an undocumented route-populate no form");
  // Classic no forms keep the rejected result for absent elements.
  const auto classic_no_absent = parse(
      CliEngine::classic,
      "configure service ies 100 interface subscriber ipv6 dhcp6-relay no "
      "server 2001:db8:ffff::9");
  require(!router::lab::ies_cli::edit(classic, classic_no_absent,
                                      CliEngine::classic, hardware, "edge-a")
               .valid,
          "classic no of an absent relay server was not rejected");
  edit(classic, CliEngine::classic, hardware,
       "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
       "no shutdown");
  // YANG defaults the interface admin-state leaf to enable, so no shutdown
  // on a fresh interface is a valid idempotent no-op.
  const auto already_up = router::lab::ies_cli::edit(
      classic,
      parse(CliEngine::classic,
            "configure service ies 100 interface subscriber no shutdown"),
      CliEngine::classic, hardware, "edge-a");
  require(already_up.recognized && already_up.valid && !already_up.changed,
          "classic no shutdown of an enabled interface was not a no-op");
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

  // Classic port ethernet mode accepts only network and hybrid: access is an
  // MD-CLI value. The fresh port starts in network mode.
  const auto parse_rejected = [&](CliEngine engine, std::string_view text) {
    require(!router::cli_detail::parse_command(
                 engine,
                 engine == CliEngine::md ? MdCliWorkflow::explicit_private
                                         : MdCliWorkflow::operational,
                 text)
                 .has_value(),
            "undocumented port mode parsed");
  };
  parse_rejected(CliEngine::classic,
                 "configure port 1/1/2 ethernet mode access");
  // Hybrid requires a tagging encapsulation first.
  edit(classic, CliEngine::classic, hardware,
       "configure port 1/1/2 ethernet encap-type dot1q");
  edit(classic, CliEngine::classic, hardware,
       "configure port 1/1/2 ethernet mode hybrid");
  edit(classic, CliEngine::classic, hardware,
       "configure port 1/1/2 ethernet mode network");

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
  // YANG defaults the interface admin-state leaf to enable, so enabling a
  // fresh interface is a valid idempotent no-op.
  const auto md_already_up = router::lab::ies_cli::edit(
      md,
      parse(CliEngine::md,
            "configure service ies internet interface uplink admin-state "
            "enable"),
      CliEngine::md, hardware, "edge-a");
  require(md_already_up.recognized && md_already_up.valid &&
              !md_already_up.changed,
          "MD admin-state enable of an enabled interface was not a no-op");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet admin-state enable");
  require(router::service::validate(md) == ValidationError::none,
          "complete MD candidate did not satisfy running IES validation");
  require(md.ies_services[0].interfaces[0].logical_id != 0U &&
              md.ies_services[0].interfaces[0].logical_id <
                  router::lab::physical_interface_namespace,
          "MD service interface did not receive a stable logical identity");

  // MD-CLI max-nbr-of-leases spans 0 through 32767 with 0 as the default
  // leaf value, so an explicit zero is configuration rather than a rejection.
  edit(md, CliEngine::md, hardware,
       "configure service ies internet interface uplink ipv6 dhcp6 relay "
       "lease-populate max-nbr-of-leases 100");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet interface uplink ipv6 dhcp6 relay "
       "lease-populate max-nbr-of-leases 0");
  require(md.ies_services[0]
                  .interfaces[0]
                  .dhcpv6_relay.lease_population_limit == 0U,
          "MD relay lease limit did not accept the default zero");
  edit(md, CliEngine::md, hardware,
       "configure service ies internet interface uplink ipv6 dhcp6 relay "
       "lease-populate max-nbr-of-leases 32767");
  const auto before_limit = md;
  const auto rejected = router::lab::ies_cli::edit(
      md,
      parse(CliEngine::md,
            "configure service ies internet interface uplink ipv6 dhcp6 relay "
            "lease-populate max-nbr-of-leases 32768"),
      CliEngine::md, hardware, "edge-a");
  require(rejected.recognized && !rejected.changed && md == before_limit,
          "out-of-range MD relay lease limit changed the candidate");
  // Documented MD-CLI delete stays silent on absent elements without
  // materializing interfaces or relay state.
  const auto delete_populate = parse(
      CliEngine::md,
      "delete service ies internet interface uplink ipv6 dhcp6 relay "
      "lease-populate");
  require(router::lab::ies_cli::edit(md, delete_populate, CliEngine::md,
                                     hardware, "edge-a")
              .changed,
          "MD relay lease-populate delete did not remove the limit");
  for (const auto text :
       {"delete service ies internet interface uplink ipv6 dhcp6 relay server "
        "2001:db8:ffff::9",
        "delete service ies internet interface uplink ipv6 dhcp6 relay "
        "lease-populate",
        "delete service ies internet interface uplink ipv6 dhcp6 relay "
        "lease-populate route-populate na",
        "delete service ies internet interface missing ipv6 dhcp6 relay"}) {
    const auto before_relay = md;
    const auto result = router::lab::ies_cli::edit(
        md, parse(CliEngine::md, text), CliEngine::md, hardware, "edge-a");
    require(result.recognized && result.valid && !result.changed &&
                md == before_relay,
            "MD relay delete of an absent element was not silent");
  }

  const auto repeated = parse(
      CliEngine::md,
      "configure service ies internet interface uplink admin-state enable");
  const auto before_repeat = md;
  const auto repeated_result = router::lab::ies_cli::edit(
      md, repeated, CliEngine::md, hardware, "edge-a");
  require(repeated_result.recognized && !repeated_result.changed &&
              md == before_repeat,
          "repeated MD leaf was accepted as a successful no-op");

  // The ipv6 address list is keyed by address: only the addressed entry is
  // removed, an absent key is the silent no-op, and the bare form does not
  // exist. The uplink address comes from the fixture above.
  const auto remove_address = parse(
      CliEngine::md,
      "delete service ies internet interface uplink ipv6 address "
      "2001:db8:200::1");
  require(router::lab::ies_cli::edit(md, remove_address, CliEngine::md,
                                     hardware, "edge-a")
                  .changed &&
              !md.ies_services[0]
                   .interfaces[0]
                   .address_configured,
          "keyed MD address delete did not remove the entry");
  const auto repeat_remove = router::lab::ies_cli::edit(
      md, remove_address, CliEngine::md, hardware, "edge-a");
  require(repeat_remove.recognized && repeat_remove.valid &&
              !repeat_remove.changed,
          "MD delete of an absent address key was not silent");
  const auto before_wrong_key = md;
  const auto wrong_key = parse(
      CliEngine::md,
      "delete service ies internet interface uplink ipv6 address "
      "2001:db8:200::2");
  const auto wrong_result = router::lab::ies_cli::edit(
      md, wrong_key, CliEngine::md, hardware, "edge-a");
  require(wrong_result.recognized && wrong_result.valid &&
              !wrong_result.changed && md == before_wrong_key,
          "MD delete of a foreign address key changed state");
  parse_rejected(CliEngine::md,
                 "delete service ies internet interface uplink ipv6 address");

  const auto existing_ies = parse(
      CliEngine::classic, "configure service ies 100 customer 10 create");
  const auto selected_ies = router::lab::ies_cli::edit(
      classic, existing_ies, CliEngine::classic, hardware, "edge-a");
  require(selected_ies.recognized && selected_ies.valid &&
              !selected_ies.changed,
          "classic IES create of an existing service was not a select");

  router::service::Configuration md_delete = md;
  const auto delete_enabled = parse(
      CliEngine::md, "delete service ies internet");
  const auto deleted = router::lab::ies_cli::edit(
      md_delete, delete_enabled, CliEngine::md, hardware, "edge-a");
  require(deleted.recognized && deleted.valid && deleted.changed &&
              md_delete.ies_services.empty(),
          "MD delete ies retained an enabled service with interfaces");

  // MD delete of an absent customer is the silent no-op, deleting a present
  // one removes it, and a customer referenced by an IES service stays
  // rejected. Classic no on an absent customer keeps the rejected result.
  router::service::Configuration customers{};
  edit(customers, CliEngine::md, hardware,
       "configure service customer tenant-a customer-id 20");
  const auto before_ghost = customers;
  const auto ghost = router::lab::ies_cli::edit(
      customers, parse(CliEngine::md, "delete service customer ghost"),
      CliEngine::md, hardware, "edge-a");
  require(ghost.recognized && ghost.valid && !ghost.changed &&
              customers == before_ghost,
          "MD delete of an absent customer was not silent");
  const auto remove_present = router::lab::ies_cli::edit(
      customers, parse(CliEngine::md, "delete service customer tenant-a"),
      CliEngine::md, hardware, "edge-a");
  require(remove_present.recognized && remove_present.valid &&
              remove_present.changed && customers.customers.empty(),
          "MD delete did not remove a present customer");
  const auto repeat_remove_customer = router::lab::ies_cli::edit(
      customers, parse(CliEngine::md, "delete service customer tenant-a"),
      CliEngine::md, hardware, "edge-a");
  require(repeat_remove_customer.recognized &&
              repeat_remove_customer.valid &&
              !repeat_remove_customer.changed,
          "repeated MD customer delete was not silent");
  edit(customers, CliEngine::md, hardware,
       "configure service customer tenant-a customer-id 20");
  edit(customers, CliEngine::md, hardware,
       "configure port 1/1/2 ethernet mode access");
  edit(customers, CliEngine::md, hardware,
       "configure service ies internet service-id 200");
  edit(customers, CliEngine::md, hardware,
       "configure service ies internet customer tenant-a");
  const auto referenced = router::lab::ies_cli::edit(
      customers, parse(CliEngine::md, "delete service customer tenant-a"),
      CliEngine::md, hardware, "edge-a");
  require(referenced.recognized && !referenced.valid,
          "MD delete removed a customer referenced by an IES service");
  const auto absent_no = router::lab::ies_cli::edit(
      customers, parse(CliEngine::classic, "configure service no customer 999"),
      CliEngine::classic, hardware, "edge-a");
  require(absent_no.recognized && !absent_no.valid,
          "classic no customer accepted an absent customer");

  // MD delete stays silent on an absent service, its interfaces and already
  // default port leaves without materializing configuration.
  router::service::Configuration absent{};
  for (const auto text :
       {"delete service ies ghost",
        "delete service ies ghost interface uplink",
        "delete port 1/1/2 ethernet mode",
        "delete port 1/1/2 ethernet encap-type"}) {
    const auto before_absent = absent;
    const auto silent = router::lab::ies_cli::edit(
        absent, parse(CliEngine::md, text), CliEngine::md, hardware, "edge-a");
    require(silent.recognized && silent.valid && !silent.changed &&
                absent == before_absent,
            "MD delete of an absent IES element was not silent");
  }
  edit(absent, CliEngine::md, hardware,
       "configure port 1/1/2 ethernet mode access");
  const auto remove_mode = router::lab::ies_cli::edit(
      absent, parse(CliEngine::md, "delete port 1/1/2 ethernet mode"),
      CliEngine::md, hardware, "edge-a");
  require(remove_mode.recognized && remove_mode.valid &&
              remove_mode.changed,
          "MD port mode delete did not restore the default");
  const auto repeat_mode = router::lab::ies_cli::edit(
      absent, parse(CliEngine::md, "delete port 1/1/2 ethernet mode"),
      CliEngine::md, hardware, "edge-a");
  require(repeat_mode.recognized && repeat_mode.valid &&
              !repeat_mode.changed,
          "repeated MD port mode delete was not silent");

  // Deleting an absent SAP key is the MD silent no-op while an enabled
  // interface keeps the rejected result.
  edit(customers, CliEngine::md, hardware,
       "configure service ies internet interface uplink description tag");
  edit(customers, CliEngine::md, hardware,
       "configure service ies internet interface uplink admin-state disable");
  const auto before_sap = customers;
  const auto absent_sap = router::lab::ies_cli::edit(
      customers,
      parse(CliEngine::md,
            "delete service ies internet interface uplink sap 1/1/2"),
      CliEngine::md, hardware, "edge-a");
  require(absent_sap.recognized && absent_sap.valid &&
              !absent_sap.changed && customers == before_sap,
          "MD delete of an absent SAP key was not silent");
}
