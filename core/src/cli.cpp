// Shared operational commands, parsing primitives and terminal engine routing.
// Read-only commands may inspect the aggregate. Configuration commands receive
// only ConfigurationState and cannot mutate hardware or operational
// projections.

#include "router/cli.hpp"

#include "cli_internal.hpp"
#include "router/routing.hpp"

#include <algorithm>
#include <charconv>
#include <functional>
#include <iomanip>
#include <optional>
#include <sstream>
#include <vector>

namespace router::cli_detail {

// Removes terminal whitespace at the parser boundary while preserving spaces
// inside quoted tokens handled by cli_parser.
std::string trim(std::string_view value) {
  const auto first = value.find_first_not_of(" \r\n\t");
  if (first == std::string::npos)
    return {};
  const auto last = value.find_last_not_of(" \r\n\t");
  return std::string{value.substr(first, last - first + 1)};
}

// Resolves a generated port identity to its stable profile array index.
std::optional<std::size_t> port_index(std::string_view text) {
  for (std::size_t index = 0; index < profile::port_ids.size(); ++index) {
    if (text == profile::port_ids[index])
      return index;
  }
  return std::nullopt;
}

namespace {

// Parses strict dotted decimal without locale, shorthand or platform socket
// rules that could differ between native tests and WebAssembly.
std::optional<std::uint32_t> ipv4_value(std::string_view text) {
  std::uint32_t result{};
  for (int octet = 0; octet < 4; ++octet) {
    const auto separator = text.find('.');
    const auto token = text.substr(0, separator);
    unsigned value{};
    const auto parsed =
        std::from_chars(token.data(), token.data() + token.size(), value);
    if (token.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != token.data() + token.size() || value > 255)
      return std::nullopt;
    result = (result << 8) | value;
    if (octet == 3) {
      if (separator != std::string_view::npos)
        return std::nullopt;
    } else {
      if (separator == std::string_view::npos)
        return std::nullopt;
      text.remove_prefix(separator + 1);
    }
  }
  return result;
}

// Builds equipment output from generic chassis arrays. Provisioning, inventory
// and lifecycle remain separate columns instead of a synthesized up flag.
std::string hardware_table(const DeviceState &state) {
  const auto &running = state.configuration.running;
  const auto &hardware = state.hardware;
  std::ostringstream out;
  out << "Slot  Provisioned       Equipped          Admin  Operational\n"
      << std::left << std::setw(6) << profile::control_slot << std::setw(18)
      << profile::control_card_type << std::setw(18)
      << profile::control_card_type << std::setw(7) << "up"
      << profile::control_initial_state;
  for (std::size_t card_index = 0; card_index < running.cards.size();
       ++card_index) {
    const auto &card = running.cards[card_index];
    const auto &equipped = hardware.cards[card_index];
    if (!card.type && !equipped.type)
      continue;
    out << '\n'
        << std::setw(6) << card_index + 1U << std::setw(18)
        << (card.type ? card.type : "-") << std::setw(18)
        << (equipped.type ? equipped.type : "-") << std::setw(7)
        << (card.admin_enabled ? "up" : "down") << equipped.equipment.reason;
    for (std::size_t mda_index = 0; mda_index < card.mdas.size(); ++mda_index) {
      const auto &mda = card.mdas[mda_index];
      const auto &equipped_mda = equipped.mdas[mda_index];
      if (!mda.type && !equipped_mda.type)
        continue;
      out << '\n'
          << std::to_string(card_index + 1U) + "/" +
                 std::to_string(mda_index + 1U)
          << std::string(5, ' ') << std::setw(18) << (mda.type ? mda.type : "-")
          << std::setw(18) << (equipped_mda.type ? equipped_mda.type : "-")
          << std::setw(7) << (mda.admin_enabled ? "up" : "down")
          << equipped_mda.equipment.reason;
    }
  }
  return out.str();
}

// Formats profile speed with an exact G suffix only for whole gigabits.
std::string port_speed_text() {
  // The speed is a compile-time profile property. if constexpr removes the
  // unreachable formatter branch and keeps MSVC /W4 free of C4127.
  if constexpr (profile::port_speed_mbps % 1000U == 0U) {
    return std::to_string(profile::port_speed_mbps / 1000U) + "G";
  } else {
    return std::to_string(profile::port_speed_mbps) + "M";
  }
}

// Projects every currently inventoried physical port and its control-owned
// counters without exposing unequipped configuration entries as hardware.
std::string port_table(const DeviceState &state) {
  const auto &running = state.configuration.running;
  std::ostringstream out;
  out << "Port    Admin  Oper  Speed   MTU   Rx Packets  Tx Packets  "
         "Description\n";
  const auto speed = port_speed_text();
  const auto count = state.inventory_port_count();
  for (std::size_t index = 0; index < count; ++index) {
    const auto &port = running.ports[index];
    const auto &counters = state.operational.port_counters[index];
    out << profile::port_ids[index] << "   "
        << (port.admin_enabled ? "up     " : "down   ")
        << (state.port_operational(index) ? "up    " : "down  ") << std::left
        << std::setw(8) << speed << port.mtu << "  " << counters.rx_packets
        << "           " << counters.tx_packets << "           "
        << port.description.data();
    if (index + 1 < count)
      out << '\n';
  }
  return out.str();
}

// Formats only valid forwarding-returned adjacency entries. An empty table is
// explicit and never inferred from the topology editor.
std::string arp_table(const DeviceState &state) {
  const auto &entries = state.operational.arp;
  const auto any = std::any_of(entries.begin(), entries.end(),
                               [](const auto &entry) { return entry.valid; });
  if (!any)
    return "No ARP entries";
  std::ostringstream out;
  out << "IP Address       MAC Address         Port";
  for (const auto &entry : entries) {
    if (!entry.valid)
      continue;
    out << '\n'
        << std::dec << static_cast<unsigned>(entry.address[0]) << '.'
        << static_cast<unsigned>(entry.address[1]) << '.'
        << static_cast<unsigned>(entry.address[2]) << '.'
        << static_cast<unsigned>(entry.address[3]) << "        "
        << std::uppercase << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < entry.mac.size(); ++index) {
      if (index)
        out << ':';
      out << std::setw(2) << static_cast<unsigned>(entry.mac[index]);
    }
    out << "   " << profile::port_ids[entry.port_index];
  }
  return out.str();
}

std::optional<std::string> operational_command(const DeviceState &state,
                                               const ParsedCommand &command,
                                               const CliPing &send_ping) {
  // Command IDs come from the generated grammar. This dispatcher implements
  // read-only device operations shared by both terminal engines.
  using enum cli_schema::CommandId;
  const auto &running = state.configuration.running;
  if (command.spec->id == show_system_information) {
    return std::string{"System Name            : "} +
           running.system_name.data() +
           "\nSystem Type            : " + profile::chassis +
           "\nSystem Version         : " + profile::release +
           "\nControl Processor      : " + profile::control_card_type + " " +
           profile::control_slot + " " + profile::control_initial_state;
  }
  if (command.spec->id == show_card || command.spec->id == show_mda)
    return hardware_table(state);
  if (command.spec->id == show_port)
    return port_table(state);
  if (command.spec->id == show_router_interface) {
    std::ostringstream out;
    out << "Interface    Port    Admin  Oper  IP Address\n";
    for (std::size_t index = 0; index < running.interface_count; ++index) {
      const auto &interface = running.interfaces[index];
      if (!interface.valid)
        continue;
      out << interface.name << "  " << profile::port_ids[interface.port_index]
          << "   " << (interface.admin_enabled ? "up     " : "down   ")
          << (state.interface_operational(index) ? "up    " : "down  ")
          << interface.address;
      if (index + 1 < running.interface_count)
        out << '\n';
    }
    return out.str();
  }
  if (command.spec->id == show_router_route_table ||
      command.spec->id == show_router_fib) {
    std::ostringstream out;
    out << "Prefix              Type   Next Hop       Interface";
    bool any = false;
    for (std::size_t index = 0; index < running.interface_count; ++index) {
      const auto &interface = running.interfaces[index];
      if (!interface.valid || !state.interface_operational(index))
        continue;
      out << '\n'
          << interface.prefix << "        Local  -              "
          << interface.name;
      any = true;
    }
    for (const auto &route : running.static_routes) {
      if (!route.valid)
        continue;
      out << '\n'
          << ((route.network >> 24) & 255) << '.'
          << ((route.network >> 16) & 255) << '.'
          << ((route.network >> 8) & 255) << '.' << (route.network & 255) << '/'
          << static_cast<unsigned>(route.prefix_length) << "        Static "
          << ((route.next_hop >> 24) & 255) << '.'
          << ((route.next_hop >> 16) & 255) << '.'
          << ((route.next_hop >> 8) & 255) << '.' << (route.next_hop & 255)
          << "   resolved";
      any = true;
    }
    return any ? out.str()
               : "No active routes: forwarding hardware or interface is not "
                 "operational";
  }
  if (command.spec->id == show_router_arp)
    return arp_table(state);
  if (command.spec->id == show_system_alarms) {
    if (!state.operational.alarm_count)
      return "No active alarms";
    std::ostringstream out;
    out << "Severity  Object       Reason";
    for (std::size_t index = 0; index < state.operational.alarm_count;
         ++index) {
      const auto &alarm = state.operational.alarms[index];
      out << '\n'
          << alarm.severity << "     " << alarm.id << "   " << alarm.reason;
    }
    return out.str();
  }
  if (command.spec->id == cli_schema::CommandId::ping ||
      command.spec->id == ping_count) {
    const auto destination = *argument(command, cli_schema::TokenKind::ipv4);
    // Nokia-compatible defaults and bounds belong to the pinned release
    // profile, not to the generic parser or packet encoder.
    std::uint32_t count = profile::default_ping_count;
    const auto destination_value = ipv4_value(destination);
    if (!destination_value)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    if (command.spec->id == ping_count) {
      const auto text = *argument(command, cli_schema::TokenKind::count);
      const auto parsed =
          std::from_chars(text.data(), text.data() + text.size(), count);
      if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
          count < 1 || count > profile::maximum_ping_count)
        return "MINOR: MGMT_CORE #2301: Invalid element value";
    }
    return send_ping({static_cast<std::uint8_t>(*destination_value >> 24),
                      static_cast<std::uint8_t>(*destination_value >> 16),
                      static_cast<std::uint8_t>(*destination_value >> 8),
                      static_cast<std::uint8_t>(*destination_value)},
                     count);
  }
  return std::nullopt;
}

} // namespace

std::optional<ParsedStaticRoute>
parse_static_route(std::string_view prefix_text, std::string_view next_text) {
  // Network host bits are rejected before insertion, keeping one canonical key
  // per prefix and avoiding restore-order route selection.
  const auto slash = prefix_text.find('/');
  if (slash == std::string_view::npos)
    return std::nullopt;
  const auto network = ipv4_value(prefix_text.substr(0, slash));
  unsigned prefix{};
  prefix_text.remove_prefix(slash + 1);
  const auto parsed = std::from_chars(
      prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
  const auto next_hop = ipv4_value(next_text);
  if (!network || !next_hop || parsed.ec != std::errc{} ||
      parsed.ptr != prefix_text.data() + prefix_text.size() || prefix > 32) {
    return std::nullopt;
  }
  const auto mask = routing::prefix_mask(static_cast<std::uint8_t>(prefix));
  if ((*network & mask) != *network)
    return std::nullopt;
  return ParsedStaticRoute{*network, static_cast<std::uint8_t>(prefix),
                           *next_hop};
}

bool install_static(DeviceConfiguration &configuration,
                    ParsedStaticRoute route) {
  // Replace an existing prefix in place or consume the first free bounded slot.
  // False reports real capacity exhaustion and never drops another route.
  auto slot = std::find_if(configuration.static_routes.begin(),
                           configuration.static_routes.end(),
                           [route](const auto &item) {
                             return item.valid &&
                                    item.network == route.network &&
                                    item.prefix_length == route.prefix;
                           });
  if (slot == configuration.static_routes.end()) {
    slot = std::find_if(configuration.static_routes.begin(),
                        configuration.static_routes.end(),
                        [](const auto &item) { return !item.valid; });
  }
  if (slot == configuration.static_routes.end())
    return false;
  *slot = {.valid = true,
           .network = route.network,
           .next_hop = route.next_hop,
           .prefix_length = route.prefix};
  return true;
}

// Removes one balanced quote pair after tokenizer validation. Returned storage
// remains borrowed from the parsed command for the duration of execution.
std::string_view unquote(std::string_view value) noexcept {
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
    return value.substr(1, value.size() - 2);
  return value;
}

void synchronize_candidate(ConfigurationState &configuration,
                           CliSession &session, bool running_changed) noexcept {
  // A classic write rebases a clean MD candidate but marks a dirty candidate
  // stale, preventing a later commit from overwriting concurrent running state.
  if (!running_changed)
    return;
  if (session.candidate_dirty) {
    session.candidate_outdated = true;
  } else {
    configuration.candidate = configuration.running;
  }
}

std::string prompt(const DeviceConfiguration &configuration,
                   const CliSession &session) {
  // Prompt markers reflect candidate state and the current running system name.
  // This function is the sole prompt renderer used by C++ and the browser ABI.
  const auto name = configuration.system_name.data();
  if (session.engine == CliEngine::classic)
    return "\nA:" + std::string{name} + "# ";
  if (session.candidate_outdated && session.candidate_dirty) {
    return "\n!*[ex:/]\nA:admin@" + std::string{name} + "# ";
  }
  return session.candidate_dirty
             ? "\n*[ex:/]\nA:admin@" + std::string{name} + "# "
             : "\n[ex:/]\nA:admin@" + std::string{name} + "# ";
}

} // namespace router::cli_detail

namespace router {

std::string execute_cli(DeviceState &state, CliSession &session,
                        const std::string &raw, const CliPing &ping) {
  // Public execution validates grammar first, routes common operations, then
  // delegates configuration semantics to exactly one active engine.
  const auto input = cli_detail::trim(raw);
  std::string output;
  if (input.empty())
    return cli_detail::prompt(state.configuration.running, session);

  const auto command = cli_detail::parse_command(state, session.engine, input);
  if (!command) {
    if (session.engine == CliEngine::classic) {
      output = "Error: Bad command.";
    } else if (const auto help = cli_detail::incomplete_command_help(
                   state, session.engine, input);
               !help.empty()) {
      // Enter completion is enabled by default in MD-CLI. A known but
      // incomplete path displays its next context instead of claiming that the
      // already matched keyword is unknown.
      output = help;
    } else {
      const auto separator = input.find(' ');
      output = "MINOR: MGMT_CORE #2201: Unknown element - '" +
               input.substr(0, separator) + "'";
    }
  } else if (command->spec->id == cli_schema::CommandId::switch_engine) {
    session.engine =
        session.engine == CliEngine::md ? CliEngine::classic : CliEngine::md;
    output = session.engine == CliEngine::md
                 ? "INFO: CLI #2052: Switching to the MD-CLI engine"
                 : "INFO: CLI #2051: Switching to the classic CLI engine";
  } else if (command->spec->id == cli_schema::CommandId::help ||
             command->spec->id == cli_schema::CommandId::help_question) {
    // Root help is the root completion projection of the active release
    // schema. It cannot drift when commands are added or removed.
    output = cli_detail::complete_command(state, session.engine, "");
  } else if (const auto common =
                 cli_detail::operational_command(state, *command, ping)) {
    output = *common;
  } else if (session.engine == CliEngine::md) {
    output = cli_detail::execute_md(state.configuration, session, *command);
  } else {
    output =
        cli_detail::execute_classic(state.configuration, session, *command);
  }
  return output + cli_detail::prompt(state.configuration.running, session);
}

std::string complete_cli(const DeviceState &state, const CliSession &session,
                         const std::string &raw) {
  // Completion reads schema and device candidates but cannot execute or mutate.
  return cli_detail::complete_command(state, session.engine, raw);
}

std::string cli_prompt(const DeviceState &state, const CliSession &session) {
  // Expose prompt rendering without exposing cli_detail to runtime consumers.
  return cli_detail::prompt(state.configuration.running, session);
}

} // namespace router
