// Release-schema parser boundary shared by execution and command completion.
// The generated catalog owns syntax. Handlers consume stable command IDs and
// typed parameter positions instead of comparing whole command strings.

#pragma once

#include "router/device.hpp"
#include "router/generated_cli_schema.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace router::cli_detail {

struct ParsedCommand {
  const cli_schema::CommandSpec *spec{};
  std::array<std::string_view, cli_schema::maximum_tokens> tokens{};
  std::uint8_t token_count{};
};

[[nodiscard]] std::optional<ParsedCommand>
parse_command(const DeviceState &state, CliEngine engine,
              std::string_view input);

[[nodiscard]] std::optional<std::string_view>
argument(const ParsedCommand &command, cli_schema::TokenKind kind) noexcept;

// Completion returns a display list when several context elements match. A
// unique keyword or concrete model value returns the completed input line.
[[nodiscard]] std::string complete_command(const DeviceState &state,
                                           CliEngine engine,
                                           std::string_view input);

// Returns contextual help only when every supplied token is an exact prefix of
// an executable schema row and at least one mandatory token is still missing.
[[nodiscard]] std::string incomplete_command_help(const DeviceState &state,
                                                  CliEngine engine,
                                                  std::string_view input);

} // namespace router::cli_detail
