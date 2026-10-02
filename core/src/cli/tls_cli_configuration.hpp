// TLS CLI configuration editor. LabRuntime owns candidate and running state;
// this module only applies one generated command to the supplied TLS value.
// It depends inward on the release schema and tls_profile model and never on
// forwarding, PKI private material, terminal rendering or browser APIs.

#pragma once

#include "cli_parser.hpp"
#include "router/tls_profile.hpp"

#include <string>

namespace router::lab::tls_cli {

struct EditResult {
  // recognized distinguishes a non-TLS command from an invalid TLS edit.
  // valid distinguishes an accepted idempotent write or classic create-or-select
  // from a rejected value. changed is true only when the canonical model moved.
  bool recognized{};
  bool valid{};
  bool changed{};
  std::string instance;
};

// Preconditions: command was produced by the generated 26.7.R1 parser and
// configuration belongs to the calling control shard. Postcondition on
// changed=true: configuration passes tls_profile::validate and differs from
// its input. On failure the input is restored exactly. No reference returned
// by this function outlives the call.
[[nodiscard]] EditResult
edit(tls_profile::Configuration &configuration,
     const cli_detail::ParsedCommand &command, CliEngine engine);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::tls_cli
