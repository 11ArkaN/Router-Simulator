// DHCPv6 CLI editor tests exercise the externally meaningful contract:
// both terminal engines produce identical canonical configuration, persistent
// identities consume entropy only on list creation, and invalid inheritance
// edits cannot partially alter a candidate.

#include "cli/dhcpv6_cli_configuration.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using router::CliEngine;
using router::MdCliWorkflow;
using router::dhcpv6::configuration::RouterConfiguration;

class CountingEntropy final : public router::lab::dhcpv6_cli::EntropySource {
public:
  bool fill(std::span<std::uint8_t> output) noexcept override {
    ++calls;
    for (auto &byte : output)
      byte = next++;
    return true;
  }

  std::size_t calls{};
  std::uint8_t next{1U};
};

router::cli_detail::ParsedCommand parse(CliEngine engine,
                                        std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(
      engine, engine == CliEngine::md ? MdCliWorkflow::explicit_private
                                      : MdCliWorkflow::operational,
      text);
  if (!parsed)
    throw std::runtime_error("generated DHCPv6 command did not parse: " +
                             std::string{text});
  return *parsed;
}

void edit(RouterConfiguration &configuration, CountingEntropy &entropy,
          CliEngine engine, std::string_view text) {
  const auto command = parse(engine, text);
  const auto result = router::lab::dhcpv6_cli::edit(
      configuration, command, engine, &entropy);
  if (!result.recognized || !result.valid || !result.changed)
    throw std::runtime_error("DHCPv6 command did not change configuration: " +
                             std::string{text});
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void dhcpv6_cli_configuration_tests() {
  RouterConfiguration md;
  CountingEntropy md_entropy;
  edit(md, md_entropy, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv6 access description "
       "\"IPv6 access server\"");
  edit(md, md_entropy, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv6 access defaults "
       "preferred-lifetime 7200");
  edit(md, md_entropy, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv6 access defaults "
       "valid-lifetime 172800");
  edit(md, md_entropy, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv6 access pool users "
       "prefix 2001:db8:100::/56 drain false");
  // MD-CLI records an explicitly configured false leaf while classic CLI
  // suppresses default-valued leaves in `info`. Deleting the MD leaf proves
  // that both command sequences converge on the same canonical presence
  // semantics, not merely the same effective boolean value.
  edit(md, md_entropy, CliEngine::md,
       "delete router \"Base\" dhcp-server dhcpv6 access pool users "
       "prefix 2001:db8:100::/56 drain");
  edit(md, md_entropy, CliEngine::md,
       "configure router \"Base\" dhcp-server dhcpv6 access admin-state "
       "enable");

  require(md.servers.size() == 1U &&
              md.servers.front().duid_octets == 18U &&
              md.servers.front().pools.front().prefixes.front()
                      .allocation_scope_id != 0U &&
              md_entropy.calls == 2U,
          "DHCPv6 list creation did not generate stable identities exactly once");
  require(router::dhcpv6::configuration::validate(md, false) ==
              router::dhcpv6::configuration::Status::valid,
          "complete DHCPv6 MD candidate failed running-state validation");

  const auto before = md;
  const auto invalid = parse(
      CliEngine::md,
      "configure router \"Base\" dhcp-server dhcpv6 access defaults "
      "renew-time 604800");
  const auto rejected = router::lab::dhcpv6_cli::edit(
      md, invalid, CliEngine::md, &md_entropy);
  require(rejected.recognized && !rejected.valid && md == before,
          "invalid DHCPv6 timer relationship partially changed candidate");

  RouterConfiguration classic;
  CountingEntropy classic_entropy;
  edit(classic, classic_entropy, CliEngine::classic,
       "configure router dhcp6 local-dhcp-server access description "
       "\"IPv6 access server\"");
  edit(classic, classic_entropy, CliEngine::classic,
       "configure router dhcp6 local-dhcp-server access defaults "
       "preferred-lifetime 7200");
  edit(classic, classic_entropy, CliEngine::classic,
       "configure router dhcp6 local-dhcp-server access defaults "
       "valid-lifetime 172800");
  edit(classic, classic_entropy, CliEngine::classic,
       "configure router dhcp6 local-dhcp-server access pool users prefix "
       "2001:db8:100::/56");
  edit(classic, classic_entropy, CliEngine::classic,
       "configure router dhcp6 local-dhcp-server access no shutdown");

  require(classic == md,
          "MD-CLI and classic DHCPv6 edits diverged in canonical state");
}
