// Atomic SR OS DHCPv4 local-server configuration editor shared by MD-CLI and
// classic CLI. LabRuntime owns candidate and running state. This module only
// translates a generated command into one validated canonical-model mutation.

#pragma once

#include "cli_parser.hpp"
#include "router/dhcpv4_configuration.hpp"

#include <string>

namespace router::lab::dhcpv4_cli {

struct EditResult {
  // recognized distinguishes DHCP commands from commands owned by another
  // module. valid reports semantic acceptance. changed is false for a valid,
  // idempotent command so the caller need not advance a datastore generation.
  bool recognized{};
  bool valid{};
  bool changed{};
  std::string instance{};
};

// Preconditions: command was accepted by the generated release grammar and
// the caller exclusively owns configuration for this control-plane turn.
// Postcondition: configuration is replaced atomically only after complete
// cross-field validation; an error leaves the original value unchanged.
[[nodiscard]] EditResult
edit(dhcpv4::configuration::RouterConfiguration &configuration,
     const cli_detail::ParsedCommand &command, CliEngine engine);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::dhcpv4_cli
