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

  // Modifiers are release-schema metadata rather than suffix guesses. A
  // renderer can therefore share one semantic branch for `detail` while the
  // generated grammar remains the authority on which commands accept it.
  [[nodiscard]] bool
  has_modifier(cli_schema::OutputModifier modifier) const noexcept {
    return spec != nullptr &&
           (spec->output_modifier_mask &
            static_cast<std::uint8_t>(modifier)) != 0U;
  }
};

enum class CommandFailureKind : std::uint8_t {
  unknown_element,
  invalid_element_value,
};

struct CommandFailure {
  // The failing text is copied because canonical relative expansion is a
  // temporary string. Diagnostics are terminal cold-path work, so one bounded
  // token copy is preferable to a dangling view or a wrong raw-token guess.
  CommandFailureKind kind{CommandFailureKind::unknown_element};
  std::string token;
};

[[nodiscard]] std::optional<ParsedCommand>
parse_command(const DeviceState &state, const CliSession &session,
              std::string_view input);

// Multi-router execution supplies only session semantics to syntax parsing.
// Dynamic device values are resolved by the selected router facade after a
// schema row has been identified.
[[nodiscard]] std::optional<ParsedCommand>
parse_command(CliEngine engine, MdCliWorkflow workflow,
              std::string_view input);

// Classifies the first token that cannot continue any generated command row.
// Preconditions: input is canonical and parsing has failed. The call is
// read-only, allocates only the returned bounded token and may run on any CLI
// shard.
[[nodiscard]] std::optional<CommandFailure>
diagnose_command_failure(CliEngine engine, MdCliWorkflow workflow,
                         std::string_view input);

[[nodiscard]] std::optional<std::string_view>
argument(const ParsedCommand &command, cli_schema::TokenKind kind) noexcept;

// Completion returns a display list when several context elements match. A
// unique keyword or concrete model value returns the completed input line.
[[nodiscard]] std::string complete_command(const DeviceState &state,
                                           const CliSession &session,
                                           std::string_view input,
                                           CliCompletionTrigger trigger);

// Returns contextual help only when every supplied token is an exact prefix of
// an executable schema row and at least one mandatory token is still missing.
[[nodiscard]] std::string incomplete_command_help(const DeviceState &state,
                                                  const CliSession &session,
                                                  std::string_view input);

// A navigable prefix ends at a modeled container whose next schema token is a
// literal child. Parameter-only prefixes such as "ping" remain incomplete
// actions and must display syntax help instead of changing the working path.
[[nodiscard]] bool navigable_command_prefix(const CliSession &session,
                                            std::string_view input);

// Returns true when every supplied token matches the beginning of at least one
// longer generated command. Unlike navigable_command_prefix, the next token
// may be a parameter because this predicate also serves incomplete-command
// help and default-key expansion.
[[nodiscard]] bool command_prefix(const CliSession &session,
                                  std::string_view input);

// Expands abbreviated literals in a validated context prefix while preserving
// user-supplied list keys. Empty means the input is not one unambiguous path.
[[nodiscard]] std::string canonical_command_prefix(const CliSession &session,
                                                   std::string_view input);

// Returns the nearest shorter schema container, not merely the preceding
// token. List keys are part of one context and must be removed with their node.
[[nodiscard]] std::string parent_command_prefix(const CliSession &session,
                                                std::string_view input);

} // namespace router::cli_detail
