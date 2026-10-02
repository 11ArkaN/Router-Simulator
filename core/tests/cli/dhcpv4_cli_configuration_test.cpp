// DHCPv4 CLI editor tests verify that generated MD-CLI and classic syntax
// produce the same canonical hierarchy, preserve list identities and reject
// invalid cross-field edits without partially mutating the configuration.

#include "cli/dhcpv4_cli_configuration.hpp"

#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using router::CliEngine;
using router::MdCliWorkflow;
using router::dhcpv4::configuration::RouterConfiguration;

router::cli_detail::ParsedCommand parse(CliEngine engine,
                                        std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(
      engine, engine == CliEngine::md ? MdCliWorkflow::explicit_private
                                      : MdCliWorkflow::operational,
      text);
  if (!parsed)
    throw std::runtime_error("generated DHCPv4 command did not parse: " +
                             std::string{text});
  return *parsed;
}

void edit(RouterConfiguration &configuration, CliEngine engine,
          std::string_view text) {
  const auto command = parse(engine, text);
  const auto result =
      router::lab::dhcpv4_cli::edit(configuration, command, engine);
  if (!result.recognized || !result.valid || !result.changed)
    throw std::runtime_error("DHCPv4 command did not change configuration: " +
                             std::string{text});
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void dhcpv4_cli_configuration_tests() {
  RouterConfiguration md;
  edit(md, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access "
       "description \"Base access server\"");
  edit(md, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access pool users "
       "min-lease-time 600");
  edit(md, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access pool users "
       "max-lease-time 800000");
  edit(md, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access pool users "
       "offer-time 500");
  edit(md, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access pool users "
       "subnet 192.0.2.0/24 address-range 192.0.2.10 end 192.0.2.200 "
       "failover-control-type local");
  edit(md, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access pool users "
       "subnet 192.0.2.0/24 exclude-addresses 192.0.2.100 end "
       "192.0.2.110");
  edit(md, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access admin-state "
       "enable");

  require(md.servers.size() == 1U &&
              md.servers.front().instance_id != 0U &&
              md.servers.front().pools.front().subnets.front()
                      .allocation_scope_id != 0U,
          "MD DHCPv4 list objects did not receive persistent identities");

  const auto before = md;
  const auto invalid = parse(
      CliEngine::md,
      "configure router \"Base\" dhcp-server dhcpv4 access pool users "
      "subnet 192.0.2.0/24 exclude-addresses 192.0.2.201 end "
      "192.0.2.210");
  const auto rejected =
      router::lab::dhcpv4_cli::edit(md, invalid, CliEngine::md);
  require(rejected.recognized && !rejected.valid && md == before,
          "invalid DHCPv4 exclusion partially changed the candidate");

  // Documented MD-CLI delete never creates configuration: absent elements
  // resolve without materializing their ancestors and stay a silent no-op.
  RouterConfiguration empty;
  for (const auto text :
       {"delete router \"Base\" dhcp-server dhcpv4 missing",
        "delete router \"Base\" dhcp-server dhcpv4 missing description",
        "delete router \"Base\" dhcp-server dhcpv4 missing pool users",
        "delete router \"Base\" dhcp-server dhcpv4 missing pool users "
        "min-lease-time",
        "delete router \"Base\" dhcp-server dhcpv4 missing pool users subnet "
        "192.0.2.0/24",
        "delete router \"Base\" dhcp-server dhcpv4 missing pool users subnet "
        "192.0.2.0/24 drain"}) {
    const auto before_delete = empty;
    const auto result = router::lab::dhcpv4_cli::edit(
        empty, parse(CliEngine::md, text), CliEngine::md);
    require(result.recognized && result.valid && !result.changed &&
                empty == before_delete,
            "MD delete of an absent element was not silent");
  }
  // An absent range on a present subnet is the same silent no-op, while a
  // classic no on an absent element stays rejected.
  auto md_probe = md;
  const auto absent_range = parse(
      CliEngine::md,
      "delete router \"Base\" dhcp-server dhcpv4 access pool users subnet "
      "192.0.2.0/24 address-range 192.0.2.50 end 192.0.2.60");
  const auto absent_result =
      router::lab::dhcpv4_cli::edit(md_probe, absent_range, CliEngine::md);
  require(absent_result.recognized && absent_result.valid &&
              !absent_result.changed && md_probe == md,
          "MD delete of an absent range was not silent");
  const auto classic_absent = parse(
      CliEngine::classic,
      "configure router dhcp local-dhcp-server access pool users subnet "
      "192.0.2.0/24 no address-range 192.0.2.50 192.0.2.60");
  RouterConfiguration classic_probe;
  require(!router::lab::dhcpv4_cli::edit(classic_probe, classic_absent,
                                         CliEngine::classic)
               .valid,
          "classic no of an absent range was not rejected");

  RouterConfiguration classic;
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access description "
       "\"Base access server\"");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users "
       "min-lease-time min 10");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users "
       "max-lease-time days 9 hrs 6 min 13 sec 20");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users "
       "offer-time min 8 sec 20");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users subnet "
       "192.0.2.0/24 address-range 192.0.2.10 192.0.2.200 failover local");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users subnet "
       "192.0.2.0/24 exclude-addresses 192.0.2.100 192.0.2.110");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access no shutdown");

  require(classic == md,
          "MD-CLI and classic DHCPv4 edits diverged in canonical state");

  // Classic CLI timers are keyword based. A bare seconds operand and a
  // seconds operand after a keyword group are not documented forms.
  require(!router::cli_detail::parse_command(
              CliEngine::classic, MdCliWorkflow::operational,
              "configure router dhcp local-dhcp-server access pool users "
              "min-lease-time 600"),
          "classic bare-seconds min-lease-time still parses");
  require(!router::cli_detail::parse_command(
              CliEngine::classic, MdCliWorkflow::operational,
              "configure router dhcp local-dhcp-server access pool users "
              "min-lease-time min 10 20"),
          "classic min-lease-time accepted a second bare operand");

  // YANG marks failover-control-type immutable: reconfiguring an existing
  // range with a different control is rejected, while access-driven is a
  // documented third value in both engines.
  auto md_immutable = md;
  const auto mutate_control = parse(
      CliEngine::md,
      "configure router \"Base\" dhcp-server dhcpv4 access pool users "
      "subnet 192.0.2.0/24 address-range 192.0.2.10 end 192.0.2.200 "
      "failover-control-type remote");
  require(!router::lab::dhcpv4_cli::edit(md_immutable, mutate_control,
                                         CliEngine::md)
               .valid &&
              md_immutable == md,
          "immutable failover-control-type was mutated after create");
  edit(md_immutable, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv4 access pool users "
       "subnet 192.0.2.0/24 address-range 192.0.2.210 end 192.0.2.220 "
       "failover-control-type access-driven");
  require(md_immutable.servers.front()
                  .pools.front()
                  .subnets.front()
                  .address_ranges.back()
                  .failover_control ==
              router::dhcpv4::configuration::FailoverControlType::
                  access_driven,
          "access-driven range was not stored");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users subnet "
       "192.0.2.0/24 address-range 192.0.2.210 192.0.2.220 failover "
       "access-driven");
}
