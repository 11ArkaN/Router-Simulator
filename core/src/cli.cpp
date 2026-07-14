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

std::string trim(std::string_view value) {
  const auto first = value.find_first_not_of(" \r\n\t");
  if (first == std::string::npos)
    return {};
  const auto last = value.find_last_not_of(" \r\n\t");
  return std::string{value.substr(first, last - first + 1)};
}

std::optional<std::size_t> port_index(std::string_view text) {
  for (std::size_t index = 0; index < profile::port_ids.size(); ++index) {
    if (text == profile::port_ids[index])
      return index;
  }
  return std::nullopt;
}

namespace {

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

std::string endpoint_ipv4(const LabHostConfiguration &host) {
  std::ostringstream out;
  out << static_cast<unsigned>(host.address[0]) << '.'
      << static_cast<unsigned>(host.address[1]) << '.'
      << static_cast<unsigned>(host.address[2]) << '.'
      << static_cast<unsigned>(host.address[3]);
  return out.str();
}

std::string hardware_table(const DeviceState &state) {
  const auto &running = state.configuration.running;
  const auto &hardware = state.hardware;
  std::ostringstream out;
  out << "Slot  Provisioned       Equipped          Admin  Operational\n"
      << "A     cpm5              cpm5              up     up/active\n"
      << "1     "
      << (running.card_provisioned ? "iom4-e            "
                                   : "-                 ")
      << (hardware.card.present ? "iom4-e            " : "-                 ")
      << "up     " << (state.hardware_operational() ? "up" : "down") << '\n'
      << "1/1   "
      << (running.mda_provisioned ? "me10-10gb-sfp+   " : "-                 ")
      << (hardware.mda.present
              ? (hardware.mda.compatible ? "me10-10gb-sfp+   "
                                         : "me1-100gb-cfp2    ")
              : "-                 ")
      << "up     " << (state.hardware_operational() ? "up" : "down");
  return out.str();
}

std::string port_table(const DeviceState &state) {
  const auto &running = state.configuration.running;
  std::ostringstream out;
  out << "Port    Admin  Oper  Speed   MTU   Rx Packets  Tx Packets  "
         "Description\n";
  const auto count = state.inventory_port_count();
  for (std::size_t index = 0; index < count; ++index) {
    const auto &port = running.ports[index];
    const auto &counters = state.operational.port_counters[index];
    out << profile::port_ids[index] << "   "
        << (port.admin_enabled ? "up     " : "down   ")
        << (state.port_operational(index) ? "up    " : "down  ") << "10G     "
        << port.mtu << "  " << counters.rx_packets << "           "
        << counters.tx_packets << "           " << port.description.data();
    if (index + 1 < count)
      out << '\n';
  }
  return out.str();
}

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

std::optional<std::string>
operational_command(const DeviceState &state, const ParsedCommand &command,
                    const std::function<std::string(std::uint32_t)> &send_ping) {
  using enum cli_schema::CommandId;
  const auto &running = state.configuration.running;
  if (command.spec->id == show_system_information) {
    return std::string{"System Name            : "} +
           running.system_name.data() +
           "\nSystem Type            : " + profile::chassis +
           "\nSystem Version         : " + profile::release +
           "\nControl Processor      : CPM A active/ready";
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
    const auto destination =
        *argument(command, cli_schema::TokenKind::ipv4);
    std::uint32_t count = 5;
    if (destination != endpoint_ipv4(state.project.hosts.back()))
      return "MINOR: CLI Destination unreachable";
    if (command.spec->id == ping_count) {
      const auto text = *argument(command, cli_schema::TokenKind::count);
      const auto parsed =
          std::from_chars(text.data(), text.data() + text.size(), count);
      if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
          count < 1 || count > 100)
        return "MINOR: MGMT_CORE #2301: Invalid element value";
    }
    return send_ping(count);
  }
  return std::nullopt;
}

} // namespace

std::optional<ParsedStaticRoute> parse_static_route(std::string_view prefix_text,
                                                    std::string_view next_text) {
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

std::string_view unquote(std::string_view value) noexcept {
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
    return value.substr(1, value.size() - 2);
  return value;
}

void synchronize_candidate(ConfigurationState &configuration,
                           CliSession &session, bool running_changed) noexcept {
  if (!running_changed)
    return;
  if (session.candidate_dirty) {
    session.candidate_outdated = true;
  } else {
    configuration.candidate = configuration.running;
  }
}

std::string prompt(const CliSession &session) {
  if (session.engine == CliEngine::classic)
    return "\nA:R1# ";
  if (session.candidate_outdated && session.candidate_dirty) {
    return "\n!*[ex:/]\nA:admin@R1# ";
  }
  return session.candidate_dirty ? "\n*[ex:/]\nA:admin@R1# "
                                 : "\n[ex:/]\nA:admin@R1# ";
}

} // namespace router::cli_detail

namespace router {

std::string execute_cli(DeviceState &state, CliSession &session,
                        const std::string &raw,
                        const std::function<std::string(std::uint32_t)> &ping) {
  const auto input = cli_detail::trim(raw);
  std::string output;
  if (input.empty())
    return cli_detail::prompt(session);

  const auto command = cli_detail::parse_command(state, session.engine, input);
  if (!command) {
    if (session.engine == CliEngine::classic) {
      output = "Error: Bad command.";
    } else if (const auto help =
                   cli_detail::incomplete_command_help(state, session.engine,
                                                       input);
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
  } else if (const auto common =
                 cli_detail::operational_command(state, *command, ping)) {
    output = *common;
  } else if (session.engine == CliEngine::md) {
    output = cli_detail::execute_md(state.configuration, session, *command);
  } else {
    output = cli_detail::execute_classic(state.configuration, session, *command);
  }
  return output + cli_detail::prompt(session);
}

std::string complete_cli(const DeviceState &state, const CliSession &session,
                         const std::string &raw) {
  return cli_detail::complete_command(state, session.engine, raw);
}

} // namespace router
