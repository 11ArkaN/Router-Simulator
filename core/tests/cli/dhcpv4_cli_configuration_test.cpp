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

  RouterConfiguration classic;
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access description "
       "\"Base access server\"");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users "
       "min-lease-time 600");
  edit(classic, CliEngine::classic,
       "configure router dhcp local-dhcp-server access pool users "
       "max-lease-time 800000");
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
}
