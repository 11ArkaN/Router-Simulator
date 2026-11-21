// Atomic IS-IS intent editor. The caller owns the datastore generation and
// Base-interface reference validation; this module cannot access live protocol state.
#pragma once
#include "cli_parser.hpp"
#include "router/isis_configuration.hpp"
namespace router::lab::isis_cli {
// Read-only generated ownership checks; no datastore or shard affinity.
[[nodiscard]] bool is_md_command(cli_schema::CommandId) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId) noexcept;
struct EditResult {
  bool recognized{}, valid{}, changed{};
  std::uint8_t instance{};
};
// Exclusive control-owner access is required. Invalid edits preserve the exact
// supplied generation. Returned values contain no borrowed command storage.
[[nodiscard]] EditResult edit(isis::RouterConfiguration &,
    const cli_detail::ParsedCommand &, CliEngine);
}
