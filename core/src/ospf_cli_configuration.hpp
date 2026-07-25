// OSPF configuration editor shared by MD-CLI and classic CLI. LabRuntime owns
// candidate and running generations; this module performs one atomic edit on
// the canonical protocol intent and has no access to protocol runtime state.

#pragma once

#include "cli_parser.hpp"
#include "router/ospf_configuration.hpp"

#include <string>
#include <span>
#include <optional>

namespace router::lab::ospf_cli {

struct EditResult {
  // recognized separates an invalid OSPF edit from a command owned by another
  // configuration module. valid distinguishes an accepted idempotent write
  // from a rejected value. changed is true only when whole-model validation
  // produced a different generation.
  bool recognized{};
  bool valid{};
  bool changed{};
  std::string instance;
};

class SecretSink {
public:
  virtual ~SecretSink() = default;
  // The implementation must replace plaintext with a purpose-bound opaque
  // handle atomically. The editor never retains or returns the supplied view.
  [[nodiscard]] virtual std::optional<vault::SecretHandle>
  seal(std::span<const std::uint8_t> plaintext) noexcept = 0;
};

// Preconditions: command came from the generated 26.7.R1 grammar and the
// caller exclusively owns configuration for this control turn. On failure the
// supplied configuration is restored to its exact prior value.
[[nodiscard]] EditResult edit(ospf::RouterConfiguration &configuration,
                              const cli_detail::ParsedCommand &command,
                              CliEngine engine,
                              SecretSink *secrets = nullptr);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::ospf_cli
