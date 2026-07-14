// Token parser and context completion for the generated SR OS CLI schema.
// Source: nokia.sros.26_7.md_cli.command_completion

#include "cli_parser.hpp"

#include "router/generated_profile.hpp"

#include <algorithm>
#include <array>
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
  bool completable{};
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

bool accepts(const cli_schema::TokenSpec &token, std::string_view value) {
  // Literal structure selects the handler. Parameter range and model checks
  // stay in that handler so malformed input receives a precise CLI error.
  return token.kind == cli_schema::TokenKind::literal
             ? value == token.display
             : !value.empty();
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
                   bool completable, std::string_view partial) {
  // Several schema rows can share the same next token. Deduplication is done
  // before sorting so help never repeats a keyword for each descendant row.
  if (!std::string_view(value).starts_with(partial))
    return;
  const auto duplicate = std::find_if(items.begin(), items.end(),
                                      [&value](const Candidate &item) {
                                        return item.value == value;
                                      });
  if (duplicate == items.end())
    items.push_back({std::move(value), completable});
}

std::string ipv4_text(const packet::Ipv4 &address) {
  // Formatting is local and deterministic. It does not depend on libc network
  // helpers that differ between the browser and native Windows builds.
  std::ostringstream out;
  out << static_cast<unsigned>(address[0]) << '.'
      << static_cast<unsigned>(address[1]) << '.'
      << static_cast<unsigned>(address[2]) << '.'
      << static_cast<unsigned>(address[3]);
  return out.str();
}

void parameter_candidates(const DeviceState &state, CliEngine engine,
                          const cli_schema::TokenSpec &token,
                          std::string_view partial,
                          std::vector<Candidate> &items) {
  using enum cli_schema::TokenKind;
  // Syntax is release data, while concrete identifiers come from the current
  // device model. This is the boundary that prevents canned demo commands from
  // appearing as terminal completion.
  const auto &configuration = active_configuration(state, engine);
  switch (token.kind) {
  case literal:
    add_candidate(items, std::string{token.display}, true, partial);
    break;
  case card_slot:
    add_candidate(items, std::to_string(profile::line_card_slot), true,
                  partial);
    break;
  case mda_slot:
    add_candidate(items, std::to_string(profile::mda_slot), true, partial);
    break;
  case card_type:
    add_candidate(items, profile::line_card_type, true, partial);
    break;
  case mda_type:
    add_candidate(items, profile::modeled_mda_type, true, partial);
    break;
  case port_id:
    // SR OS permits port configuration after the MDA type is provisioned even
    // if the physical module is absent. Equipment controls operational state,
    // while the configured parent controls whether port nodes exist in CLI.
    for (std::size_t index = 0;
         index < (configuration.mda_provisioned ? profile::port_count : 0U);
         ++index)
      add_candidate(items, profile::port_ids[index], true, partial);
    break;
  case interface_name:
    // The placeholder documents the parameter shape. Only existing interface
    // names are marked as safe replacements for the editable command line.
    add_candidate(items, std::string{token.display}, false, partial);
    for (std::size_t index = 0; index < configuration.interface_count; ++index) {
      if (configuration.interfaces[index].valid)
        add_candidate(items, configuration.interfaces[index].name, true,
                      partial);
    }
    break;
  case ipv4:
    // Destination choices are derived from project endpoints. Adding or
    // changing a host therefore updates help without changing CLI source code.
    add_candidate(items, std::string{token.display}, false, partial);
    for (const auto &host : state.project.hosts)
      add_candidate(items, ipv4_text(host.address), true, partial);
    break;
  case ipv4_prefix:
  case count:
  case mtu:
  case system_name:
  case description:
    add_candidate(items, std::string{token.display}, false, partial);
    break;
  }
}

} // namespace

std::optional<ParsedCommand> parse_command(const DeviceState &,
                                           CliEngine engine,
                                           std::string_view input) {
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return std::nullopt;
  // Generated rows are the sole syntax catalog. Handlers receive a stable ID
  // only after every literal and parameter position has matched that catalog.
  for (const auto &spec : cli_schema::commands) {
    if (!(spec.engine_mask & engine_mask(engine)) ||
        spec.token_count != line.count)
      continue;
    bool matched = true;
    for (std::size_t index = 0; index < line.count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        matched = false;
        break;
      }
    }
    if (matched)
      return ParsedCommand{&spec, line.tokens, line.count};
  }
  return std::nullopt;
}

std::optional<std::string_view>
argument(const ParsedCommand &command, cli_schema::TokenKind kind) noexcept {
  // Each current command uses a parameter kind at most once. Looking up by
  // kind keeps execution independent from token offsets in release schemas.
  for (std::size_t index = 0; index < command.token_count; ++index) {
    if (command.spec->tokens[index].kind == kind)
      return command.tokens[index];
  }
  return std::nullopt;
}

std::string complete_command(const DeviceState &state, CliEngine engine,
                             std::string_view raw) {
  const auto input = trim_view(raw);
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
          if (!(spec.engine_mask & engine_mask(engine)) ||
              spec.token_count <= line.count)
            return false;
          for (std::size_t index = 0; index < line.count; ++index) {
            if (!accepts(spec.tokens[index], line.tokens[index]))
              return false;
          }
          const auto &last = spec.tokens[line.count - 1U];
          return last.kind == cli_schema::TokenKind::literal &&
                 last.display == line.tokens[line.count - 1U];
        });
    if (exact_keyword) {
      completed_count = line.count;
      partial = {};
    }
  }
  std::vector<Candidate> candidates;

  // Completion scans only rows for the active engine and matching prefix.
  // Schema size is fixed for a release, while candidate allocation is limited
  // to the distinct children of one context.
  for (const auto &spec : cli_schema::commands) {
    if (!(spec.engine_mask & engine_mask(engine)) ||
        completed_count >= spec.token_count)
      continue;
    bool prefix_matches = true;
    for (std::size_t index = 0; index < completed_count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        prefix_matches = false;
        break;
      }
    }
    if (prefix_matches)
      parameter_candidates(state, engine, spec.tokens[completed_count],
                           partial, candidates);
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate &left, const Candidate &right) {
              return left.value < right.value;
            });
  if (candidates.empty())
    return {};
  if (candidates.size() == 1U && candidates.front().completable) {
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
    out << candidates[index].value;
  }
  // A display-only singleton gets an empty second line. This keeps the current
  // string transport unambiguous without mistaking a parameter label for text
  // that should replace the user's editable command line.
  if (candidates.size() == 1U)
    out << '\n';
  return out.str();
}

std::string incomplete_command_help(const DeviceState &state, CliEngine engine,
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
        if (!(spec.engine_mask & engine_mask(engine)) ||
            spec.token_count <= line.count)
          return false;
        for (std::size_t index = 0; index < line.count; ++index) {
          if (!accepts(spec.tokens[index], line.tokens[index]))
            return false;
        }
        return true;
      });
  return incomplete ? complete_command(state, engine, input) : std::string{};
}

} // namespace router::cli_detail
