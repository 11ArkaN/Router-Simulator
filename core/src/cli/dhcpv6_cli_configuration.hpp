// Atomic SR OS DHCPv6 local-server configuration editor shared by MD-CLI and
// classic CLI. LabRuntime owns the candidate or running model. This module
// owns no mutable state and only publishes a completely validated replacement.

#pragma once

#include "cli_parser.hpp"
#include "router/dhcpv6_configuration.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace router::lab::dhcpv6_cli {

class EntropySource {
public:
  virtual ~EntropySource() = default;

  // Preconditions: output is writable for its complete extent.
  // Postcondition: success means every byte came from the platform CSPRNG.
  // Failure leaves the caller responsible for discarding the staged object.
  [[nodiscard]] virtual bool
  fill(std::span<std::uint8_t> output) noexcept = 0;
};

struct EditResult {
  bool recognized{};
  bool valid{};
  bool changed{};
  std::string instance{};
};

// The editor generates a persistent DUID-UUID when a server list entry is
// created and a persistent allocation secret when a prefix entry is created.
// It never substitutes deterministic bytes if the entropy provider fails.
[[nodiscard]] EditResult
edit(dhcpv6::configuration::RouterConfiguration &configuration,
     const cli_detail::ParsedCommand &command, CliEngine engine,
     EntropySource *entropy);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::dhcpv6_cli
