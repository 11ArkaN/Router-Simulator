// Token parser and context completion for the generated SR OS CLI schema.
// Source: nokia.sros.26_7.md_cli.command_completion

#include "cli_parser.hpp"

#include "router/generated_profile.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace router::cli_detail {
namespace {

struct TokenizedLine {
  // The schema generator publishes the largest legal command width. Keeping
  // token views in a fixed array makes parsing allocation-free and places an
  // explicit upper bound on work for malformed terminal input.
  std::array<std::string_view, cli_schema::maximum_tokens> tokens{};
  std::uint8_t count{};
  bool trailing_space{};
  bool valid{true};
};

struct Candidate {
  // Placeholders are useful in help output but cannot replace user input.
  // Keeping that distinction beside the text avoids guessing from angle
  // brackets in the presentation layer.
  std::string value;
  std::string description;
  bool completable{};
  bool keyword{};
  bool context{};
};

constexpr bool ascii_space(char value) noexcept {
  // SR OS command grammar is byte-oriented here. Locale-dependent whitespace
  // would make the native and WebAssembly builds tokenize differently.
  return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::string_view trim_view(std::string_view value) noexcept {
  // Views retain ownership in the terminal command for the whole synchronous
  // parse. No token is copied unless it becomes completion output.
  while (!value.empty() && ascii_space(value.front()))
    value.remove_prefix(1);
  while (!value.empty() && ascii_space(value.back()))
    value.remove_suffix(1);
  return value;
}

TokenizedLine tokenize(std::string_view input, bool completion) {
  // Completion deliberately accepts an open quote. Execution does not. This
  // permits contextual help while a description is being typed without ever
  // treating incomplete text as a valid configuration value.
  TokenizedLine result;
  result.trailing_space = !input.empty() && ascii_space(input.back());
  std::size_t cursor{};
  while (cursor < input.size()) {
    while (cursor < input.size() && ascii_space(input[cursor]))
      ++cursor;
    if (cursor == input.size())
      break;
    if (result.count == result.tokens.size()) {
      result.valid = false;
      return result;
    }

    const auto begin = cursor;
    if (input[cursor] == '"') {
      ++cursor;
      while (cursor < input.size() && input[cursor] != '"')
        ++cursor;
      if (cursor == input.size()) {
        // An unfinished quote is useful while completing but is never an
        // executable token. No temporary string or escape rewriting is used.
        result.valid = completion;
      } else {
        ++cursor;
      }
      if (!result.valid)
        return result;
    } else {
      while (cursor < input.size() && !ascii_space(input[cursor]))
        ++cursor;
    }
    result.tokens[result.count++] = input.substr(begin, cursor - begin);
    if (cursor < input.size() && !ascii_space(input[cursor])) {
      result.valid = false;
      return result;
    }
  }
  return result;
}

constexpr std::uint8_t engine_mask(CliEngine engine) noexcept {
  // Engine availability comes from the generated release schema. A compact
  // bit mask keeps the hot schema scan branch-only and avoids dynamic sets.
  return engine == CliEngine::md ? 1U : 2U;
}

bool configuration_only(cli_schema::CommandId id) noexcept {
  // These rows are legal only after MD-CLI has entered a candidate workflow.
  // Classic uses the same configuration rows with immediate semantics and is
  // therefore unaffected by this MD-specific availability filter.
  using enum cli_schema::CommandId;
  switch (id) {
  case configure_card_type:
  case configure_mda_type:
  case configure_system_name:
  case md_port_enable:
  case md_port_disable:
  case md_port_description:
  case md_port_mtu:
  case md_interface_enable:
  case md_interface_disable:
  case md_static_route:
  case md_delete_card:
  case md_delete_mda:
  case md_delete_port_description:
  case md_delete_static_route:
  case md_compare:
  case md_commit:
  case md_discard:
    return true;
  default:
    return false;
  }
}

bool available(const cli_schema::CommandSpec &spec,
               const CliSession &session) noexcept {
  if (!(spec.engine_mask & engine_mask(session.engine)))
    return false;
  if (session.engine != CliEngine::md)
    return true;
  const bool configuring = session.md_workflow != MdCliWorkflow::operational;
  if (configuration_only(spec.id))
    return configuring;
  if (spec.id == cli_schema::CommandId::md_configure_exclusive)
    return !configuring;
  if (spec.id == cli_schema::CommandId::md_edit_config_exclusive)
    return session.md_workflow != MdCliWorkflow::explicit_exclusive;
  if (spec.id == cli_schema::CommandId::md_quit_config)
    return session.md_workflow == MdCliWorkflow::explicit_exclusive;
  return true;
}

bool accepts(const cli_schema::TokenSpec &token, std::string_view value) {
  // Both SR OS engines accept an unambiguous keyword abbreviation. Quoted list
  // keys and symbolic commands are values rather than abbreviable keywords.
  // Ambiguity is rejected after all complete schema rows have been scanned.
  if (token.kind != cli_schema::TokenKind::literal)
    return !value.empty();
  if (token.display.starts_with('"') || token.display == "//")
    return value == token.display;
  return !value.empty() && token.display.starts_with(value);
}

const DeviceConfiguration &active_configuration(const DeviceState &state,
                                                CliEngine engine) noexcept {
  // MD completion follows candidate state because newly provisioned parents
  // must expose their children before commit. Classic completion follows the
  // running datastore because every accepted change is immediate.
  return engine == CliEngine::md ? state.configuration.candidate
                                 : state.configuration.running;
}

void add_candidate(std::vector<Candidate> &items, std::string value,
                   bool completable, bool keyword, std::string_view partial,
                   std::string_view description, bool context) {
  // Several schema rows can share the same next token. Deduplication is done
  // before sorting so help never repeats a keyword for each descendant row.
  if (!std::string_view(value).starts_with(partial))
    return;
  const auto duplicate =
      std::find_if(items.begin(), items.end(), [&value](const Candidate &item) {
        return item.value == value;
      });
  if (duplicate == items.end()) {
    items.push_back({std::move(value), std::string{description}, completable,
                     keyword, context});
  } else {
    // A token shared by a leaf and a branch is shown as a branch. This mirrors
    // the SR OS '+' marker and prevents generated schema order from choosing
    // presentation semantics.
    duplicate->context = duplicate->context || context;
  }
}

void parameter_candidates(const DeviceState &state, CliEngine engine,
                          const cli_schema::TokenSpec &token,
                          std::string_view partial,
                          std::vector<Candidate> &items, bool context) {
  using enum cli_schema::TokenKind;
  // Syntax is release data, while concrete identifiers come from the current
  // device model. This is the boundary that prevents canned demo commands from
  // appearing as terminal completion.
  const auto &configuration = active_configuration(state, engine);
  switch (token.kind) {
  case literal:
    add_candidate(items, std::string{token.display}, true, true, partial,
                  token.description, context);
    break;
  case card_slot:
    add_candidate(items, std::to_string(profile::line_card_slot), true, false,
                  partial, token.description, context);
    break;
  case mda_slot:
    add_candidate(items, std::to_string(profile::mda_slot), true, false,
                  partial, token.description, context);
    break;
  case card_type:
    add_candidate(items, profile::line_card_type, true, false, partial,
                  token.description, context);
    break;
  case mda_type:
    add_candidate(items, profile::modeled_mda_type, true, false, partial,
                  token.description, context);
    break;
  case port_id:
    // SR OS permits port configuration after the MDA type is provisioned even
    // if the physical module is absent. Equipment controls operational state,
    // while the configured parent controls whether port nodes exist in CLI.
    for (std::size_t index = 0;
         index < (profile_mda(configuration).type ? profile::port_count : 0U);
         ++index)
      add_candidate(items, profile::port_ids[index], true, false, partial,
                    token.description, context);
    break;
  case interface_name:
    // The placeholder documents the parameter shape. Only existing interface
    // names are marked as safe replacements for the editable command line.
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    for (std::size_t index = 0; index < configuration.interface_count;
         ++index) {
      if (configuration.interfaces[index].valid)
        add_candidate(items, configuration.interfaces[index].name, true, false,
                      partial, token.description, context);
    }
    break;
  case ipv4:
    // An IP address is an unconstrained scalar, not a reference into the lab
    // topology. Exposing project host addresses here would leak UI knowledge
    // into router help and incorrectly imply that other destinations are not
    // valid.
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    break;
  case ipv4_key:
    // A new static next-hop key is also arbitrary. Existing project endpoints
    // are not router configuration objects and therefore are never completion
    // candidates.
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    break;
  case ipv4_prefix:
  case count:
  case mtu:
  case levels:
  case system_name:
  case description:
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    break;
  }
}

} // namespace

std::optional<ParsedCommand> parse_command(const DeviceState &,
                                           const CliSession &session,
                                           std::string_view input) {
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return std::nullopt;
  // Generated rows are the sole syntax catalog. Handlers receive a stable ID
  // only after every literal and parameter position has matched that catalog.
  const cli_schema::CommandSpec *match{};
  for (const auto &spec : cli_schema::commands) {
    if (!available(spec, session) || spec.token_count != line.count)
      continue;
    bool matched = true;
    for (std::size_t index = 0; index < line.count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        matched = false;
        break;
      }
    }
    if (matched) {
      // Two complete rows matched by the same abbreviation means the command
      // is ambiguous. Never let schema order choose behavior on the user's
      // behalf because SR OS asks for more input in this case.
      if (match)
        return std::nullopt;
      match = &spec;
    }
  }
  return match ? std::optional{ParsedCommand{match, line.tokens, line.count}}
               : std::nullopt;
}

std::optional<std::string_view> argument(const ParsedCommand &command,
                                         cli_schema::TokenKind kind) noexcept {
  // Each current command uses a parameter kind at most once. Looking up by
  // kind keeps execution independent from token offsets in release schemas.
  for (std::size_t index = 0; index < command.token_count; ++index) {
    if (command.spec->tokens[index].kind == kind)
      return command.tokens[index];
  }
  return std::nullopt;
}

std::string complete_command(const DeviceState &state,
                             const CliSession &session, std::string_view raw,
                             CliCompletionTrigger trigger) {
  const auto engine = session.engine;
  // Completion must preserve the final separator. In SR OS, `ping<Space>` asks
  // for the next token, while `ping` still names the current partial token.
  // Execution may trim both ends, but doing so here changes completion level.
  auto input = raw;
  while (!input.empty() && ascii_space(input.front()))
    input.remove_prefix(1);
  const auto line = tokenize(input, true);
  if (!line.valid)
    return {};
  std::size_t completed_count =
      line.trailing_space ? line.count : (line.count ? line.count - 1U : 0U);
  std::string_view partial = line.trailing_space || !line.count
                                 ? std::string_view{}
                                 : line.tokens[line.count - 1U];
  if (!line.trailing_space && line.count) {
    // Tab on an already complete keyword advances to its child context. This
    // differs from an abbreviation such as "sho", which completes to "show".
    const auto exact_keyword = std::any_of(
        cli_schema::commands.begin(), cli_schema::commands.end(),
        [&](const cli_schema::CommandSpec &spec) {
          if (!available(spec, session) || spec.token_count <= line.count)
            return false;
          for (std::size_t index = 0; index < line.count; ++index) {
            if (!accepts(spec.tokens[index], line.tokens[index]))
              return false;
          }
          const auto &last = spec.tokens[line.count - 1U];
          return last.kind == cli_schema::TokenKind::literal &&
                 last.display == line.tokens[line.count - 1U];
        });
    if (exact_keyword && trigger != CliCompletionTrigger::space) {
      completed_count = line.count;
      partial = {};
    }
  }
  std::vector<Candidate> candidates;

  // Completion scans only rows for the active engine and matching prefix.
  // Schema size is fixed for a release, while candidate allocation is limited
  // to the distinct children of one context.
  for (const auto &spec : cli_schema::commands) {
    if (!available(spec, session) || completed_count >= spec.token_count)
      continue;
    bool prefix_matches = true;
    for (std::size_t index = 0; index < completed_count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        prefix_matches = false;
        break;
      }
    }
    if (prefix_matches)
      parameter_candidates(state, engine, spec.tokens[completed_count], partial,
                           candidates, spec.token_count > completed_count + 1U);
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate &left, const Candidate &right) {
              return left.value < right.value;
            });
  if (candidates.empty())
    return {};
  if (engine == CliEngine::md && trigger == CliCompletionTrigger::space &&
      std::none_of(
          candidates.begin(), candidates.end(),
          [](const Candidate &candidate) { return candidate.keyword; })) {
    // MD-CLI Space completion is keyword-only; variable keys require Tab.
    // Classic CLI documents Space and Tab for command and key completion, so
    // its concrete model values remain visible through the same candidate set.
    return {};
  }
  if (candidates.size() == 1U && candidates.front().completable &&
      trigger != CliCompletionTrigger::question &&
      (trigger == CliCompletionTrigger::tab || candidates.front().keyword)) {
    // A unique concrete choice replaces the current token. This is separate
    // from list output so the terminal model does not parse presentation text.
    std::string result;
    for (std::size_t index = 0; index < completed_count; ++index) {
      if (!result.empty())
        result += ' ';
      result += line.tokens[index];
    }
    if (!result.empty())
      result += ' ';
    result += candidates.front().value;
    return result;
  }
  std::ostringstream out;
  // Multiple choices remain display-only and leave the editable line intact.
  // Newline framing is consumed by the terminal session, not by React.
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    if (index)
      out << '\n';
    if (trigger == CliCompletionTrigger::question) {
      // Online help aligns the token, then uses '+' for a context and '-' for
      // an executable leaf. This is router syntax, not decoration invented by
      // React, so it is produced alongside schema-owned descriptions.
      out << ' ' << std::left << std::setw(22) << candidates[index].value
          << (candidates[index].context ? "+ " : "- ");
      out << candidates[index].description;
    } else {
      out << candidates[index].value;
    }
  }
  // A display-only singleton gets an empty second line. This keeps the current
  // string transport unambiguous without mistaking a parameter label for text
  // that should replace the user's editable command line.
  if (candidates.size() == 1U)
    out << '\n';
  return out.str();
}

std::string incomplete_command_help(const DeviceState &state,
                                    const CliSession &session,
                                    std::string_view input) {
  // A syntactically valid prefix such as "ping" is incomplete, not unknown.
  // Requiring exact supplied literals prevents an arbitrary abbreviation from
  // being reported as a complete command context after Enter.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return {};
  const auto incomplete = std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [&](const cli_schema::CommandSpec &spec) {
        if (!available(spec, session) || spec.token_count <= line.count)
          return false;
        for (std::size_t index = 0; index < line.count; ++index) {
          if (!accepts(spec.tokens[index], line.tokens[index]))
            return false;
        }
        return true;
      });
  return incomplete ? complete_command(state, session, input,
                                       CliCompletionTrigger::question)
                    : std::string{};
}

bool navigable_command_prefix(const CliSession &session,
                              std::string_view input) {
  // Navigation is legal only for an exact number of supplied context tokens.
  // A literal child proves the path names a container rather than a command
  // awaiting a scalar value such as ping's destination.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return false;
  return std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [&](const cli_schema::CommandSpec &spec) {
        if (!available(spec, session) || spec.token_count <= line.count ||
            spec.tokens[line.count].kind != cli_schema::TokenKind::literal)
          return false;
        for (std::size_t index = 0; index < line.count; ++index) {
          if (!accepts(spec.tokens[index], line.tokens[index]))
            return false;
        }
        return true;
      });
}

std::string canonical_command_prefix(const CliSession &session,
                                     std::string_view input) {
  // Every descendant row of one real context has the same canonical tokens up
  // to that context. Comparing generated results makes abbreviation ambiguity
  // explicit without introducing a second handwritten command tree.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return {};
  std::string canonical;
  bool found = false;
  for (const auto &spec : cli_schema::commands) {
    if (!available(spec, session) || spec.token_count <= line.count)
      continue;
    bool matches = true;
    std::string candidate;
    for (std::size_t index = 0; index < line.count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        matches = false;
        break;
      }
      if (!candidate.empty())
        candidate += ' ';
      if (spec.tokens[index].kind == cli_schema::TokenKind::literal) {
        candidate += spec.tokens[index].display;
      } else if (session.engine == CliEngine::md &&
                 spec.tokens[index].kind ==
                     cli_schema::TokenKind::interface_name &&
                 !line.tokens[index].starts_with('"')) {
        // MD-CLI renders string list keys quoted in its two-line prompt even
        // when the user entered a simple unquoted name.
        candidate += '"';
        candidate += line.tokens[index];
        candidate += '"';
      } else {
        candidate += line.tokens[index];
      }
    }
    if (!matches)
      continue;
    if (found && candidate != canonical)
      return {};
    canonical = std::move(candidate);
    found = true;
  }
  return canonical;
}

std::string parent_command_prefix(const CliSession &session,
                                  std::string_view input) {
  // A context may end with a list key, for example "card 1". Removing only
  // the final token would leave an impossible "card" context. Search shorter
  // prefixes against the same generated tree and return the nearest container.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || line.count < 2)
    return {};
  for (std::size_t count = line.count - 1; count > 0; --count) {
    std::string candidate;
    for (std::size_t index = 0; index < count; ++index) {
      if (!candidate.empty())
        candidate += ' ';
      candidate += line.tokens[index];
    }
    if (navigable_command_prefix(session, candidate))
      return canonical_command_prefix(session, candidate);
  }
  return {};
}

} // namespace router::cli_detail
