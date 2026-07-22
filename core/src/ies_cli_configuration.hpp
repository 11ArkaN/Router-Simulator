// IES CLI configuration editor shared by the MD-CLI and classic terminal
// engines. LabRuntime remains the sole owner of candidate and running state;
// this module performs one bounded, atomic edit against the canonical service
// model. It may read immutable hardware inventory to resolve a physical SAP,
// but it never programs forwarding, sessions, checkpoints or UI state.

#pragma once

#include "cli_parser.hpp"
#include "router/ies_service.hpp"
#include "router/router_hardware_inventory.hpp"

#include <string>
#include <string_view>

namespace router::lab::ies_cli {

struct EditResult {
  // recognized distinguishes an invalid IES edit from a command owned by a
  // different configuration module. changed is true only when the canonical
  // value changed and passed the validation appropriate to the CLI engine.
  bool recognized{};
  bool changed{};
  std::string instance;
};

// Preconditions: command was resolved by the generated 26.7.R1 grammar,
// configuration is exclusively owned by the caller's control turn, and
// inventory belongs to the same router. A failed edit restores configuration
// byte-for-byte at the value level. MD edits may leave mandatory parent leaves
// absent in candidate; classic edits must always produce valid running state.
[[nodiscard]] EditResult
edit(service::Configuration &configuration,
     const cli_detail::ParsedCommand &command, CliEngine engine,
     const RouterHardwareInventory &inventory, std::string_view system_name);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::ies_cli
