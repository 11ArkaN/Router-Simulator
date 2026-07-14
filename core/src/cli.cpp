// Sourced MD-CLI and classic CLI parsers for the implemented milestone schema.
// Both engines operate on one DeviceState and preserve their session semantics.

#include "router/cli.hpp"
#include "router/routing.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <vector>

namespace router {
namespace {

std::string trim(std::string value) {
  const auto first = value.find_first_not_of(" \r\n\t");
  if (first == std::string::npos) return {};
  const auto last = value.find_last_not_of(" \r\n\t");
  return value.substr(first, last - first + 1);
}

bool starts_with(const std::string& value, const std::string& prefix) {
  return value.rfind(prefix, 0) == 0;
}

std::optional<std::size_t> port_index(std::string_view text) {
  for (std::size_t index = 0; index < profile::port_ids.size(); ++index) {
    if (text == profile::port_ids[index]) return index;
  }
  return std::nullopt;
}

std::optional<std::size_t> interface_index(std::string_view input) {
  for (std::size_t index = 0; index < profile::interface_names.size(); ++index) {
    if (input.find(profile::interface_names[index]) != std::string_view::npos) return index;
  }
  return std::nullopt;
}

std::optional<std::uint32_t> ipv4_value(std::string_view text) {
  std::uint32_t result{};
  for (int octet = 0; octet < 4; ++octet) {
    const auto separator = text.find('.');
    const auto token = text.substr(0, separator);
    unsigned value{};
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value);
    if (token.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != token.data() + token.size() || value > 255) return std::nullopt;
    result = (result << 8) | value;
    if (octet == 3) {
      if (separator != std::string_view::npos) return std::nullopt;
    } else {
      if (separator == std::string_view::npos) return std::nullopt;
      text.remove_prefix(separator + 1);
    }
  }
  return result;
}

struct ParsedStaticRoute { std::uint32_t network; std::uint8_t prefix; std::uint32_t next_hop; };

std::optional<ParsedStaticRoute> static_route(std::string_view text) {
  const auto slash = text.find('/');
  const auto next = text.find(" next-hop ");
  if (slash == std::string_view::npos || next == std::string_view::npos || slash > next) return std::nullopt;
  const auto network = ipv4_value(text.substr(0, slash));
  unsigned prefix{};
  const auto prefix_text = text.substr(slash + 1, next - slash - 1);
  const auto parsed = std::from_chars(prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
  const auto next_hop = ipv4_value(text.substr(next + 10));
  if (!network || !next_hop || parsed.ec != std::errc{} ||
      parsed.ptr != prefix_text.data() + prefix_text.size() || prefix > 32) return std::nullopt;
  const auto mask = routing::prefix_mask(static_cast<std::uint8_t>(prefix));
  if ((*network & mask) != *network) return std::nullopt;
  return ParsedStaticRoute{*network, static_cast<std::uint8_t>(prefix), *next_hop};
}

bool install_candidate_static(DeviceState& state, ParsedStaticRoute route) {
  auto slot = std::find_if(state.static_routes.begin(), state.static_routes.end(),
                            [route](const auto& item) {
                              return item.candidate_valid && item.candidate_network == route.network &&
                                     item.candidate_prefix_length == route.prefix;
                            });
  if (slot == state.static_routes.end()) {
    slot = std::find_if(state.static_routes.begin(), state.static_routes.end(),
                        [](const auto& item) { return !item.candidate_valid; });
  }
  if (slot == state.static_routes.end()) return false;
  slot->candidate_valid = true;
  slot->candidate_network = route.network;
  slot->candidate_prefix_length = route.prefix;
  slot->candidate_next_hop = route.next_hop;
  return true;
}

template <std::size_t N>
bool copy_config_text(std::array<char, N>& destination, std::string_view value) {
  // Configuration text has fixed storage so commit, discard and cross-shard
  // projections never transfer allocator ownership. A rejected oversized leaf
  // leaves the previous candidate unchanged.
  if (value.size() >= N) return false;
  std::memcpy(destination.data(), value.data(), value.size());
  destination[value.size()] = '\0';
  return true;
}

std::optional<std::pair<std::size_t, std::string_view>> port_tail(
    const std::string& input, std::string_view prefix) {
  if (!starts_with(input, std::string(prefix))) return std::nullopt;
  const auto remaining = std::string_view(input).substr(prefix.size());
  const auto separator = remaining.find(' ');
  if (separator == std::string_view::npos) return std::nullopt;
  const auto index = port_index(remaining.substr(0, separator));
  if (!index) return std::nullopt;
  return std::pair{*index, remaining.substr(separator + 1)};
}

std::string ipv4_text(const DeviceState::LabHost& host) {
  std::ostringstream out;
  out << static_cast<unsigned>(host.address[0]) << '.'
      << static_cast<unsigned>(host.address[1]) << '.'
      << static_cast<unsigned>(host.address[2]) << '.'
      << static_cast<unsigned>(host.address[3]);
  return out.str();
}

std::string hardware(const DeviceState& state) {
  // Provisioned and equipped columns intentionally come from different state.
  // CLI configuration cannot make physical equipment appear in the chassis.
  std::ostringstream out;
  out << "Slot  Provisioned       Equipped          Admin  Operational\n"
      << "A     cpm5              cpm5              up     up/active\n"
      << "1     " << (state.card_provisioned ? "iom4-e            " : "-                 ")
      << (state.card_present ? "iom4-e            " : "-                 ")
      << "up     " << (state.hardware_operational() ? "up" : "down") << '\n'
      << "1/1   " << (state.mda_provisioned ? "me10-10gb-sfp+   " : "-                 ")
      << (state.mda_present
              ? (state.mda_compatible ? "me10-10gb-sfp+   " : "me1-100gb-cfp2    ")
              : "-                 ")
      << "up     " << (state.hardware_operational() ? "up" : "down");
  return out.str();
}

std::string ports(const DeviceState& state) {
  std::ostringstream out;
  out << "Port    Admin  Oper  Speed   MTU   Rx Packets  Tx Packets  Description\n";
  for (std::size_t index = 0; index < state.inventory_port_count(); ++index) {
    const auto& port = state.ports[index];
    out << port.id << "   " << (port.admin_enabled ? "up     " : "down   ")
        << (state.port_operational(index) ? "up    " : "down  ") << "10G     "
        << port.mtu << "  " << port.rx_packets << "           " << port.tx_packets
        << "           " << port.description.data();
    if (index + 1 < state.ports.size()) out << '\n';
  }
  return out.str();
}

std::string arp_table(const DeviceState& state) {
  const auto any = std::any_of(state.arp.begin(), state.arp.end(),
                               [](const auto& entry) { return entry.valid; });
  if (!any) return "No ARP entries";
  std::ostringstream out;
  out << "IP Address       MAC Address         Port";
  for (const auto& entry : state.arp) {
    if (!entry.valid) continue;
    out << '\n' << std::dec << static_cast<unsigned>(entry.address[0]) << '.'
        << static_cast<unsigned>(entry.address[1]) << '.'
        << static_cast<unsigned>(entry.address[2]) << '.'
        << static_cast<unsigned>(entry.address[3]) << "        " << std::uppercase
        << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < entry.mac.size(); ++index) {
      if (index) out << ':';
      out << std::setw(2) << static_cast<unsigned>(entry.mac[index]);
    }
    out << "   " << state.ports[entry.port_index].id;
  }
  return out.str();
}

std::optional<std::string> operational(
    const DeviceState& state, const std::string& input,
    const std::function<std::string(std::uint32_t)>& ping) {
  if (input == "show system information") {
    return std::string{"System Name            : "} + state.system_name.data() +
           "\nSystem Type            : " +
           profile::chassis + "\nSystem Version         : " + profile::release +
           "\nControl Processor      : CPM A active/ready";
  }
  if (input == "show card" || input == "show mda") return hardware(state);
  if (input == "show port") return ports(state);
  if (input == "show router interface") {
    std::ostringstream out;
    out << "Interface    Port    Admin  Oper  IP Address\n";
    for (std::size_t index = 0; index < state.interfaces.size(); ++index) {
      const auto& interface = state.interfaces[index];
      out << interface.name << "  " << state.ports[interface.port_index].id << "   "
          << (interface.admin_enabled ? "up     " : "down   ")
          << (state.interface_operational(index) ? "up    " : "down  ")
          << interface.address;
      if (index + 1 < state.interfaces.size()) out << '\n';
    }
    return out.str();
  }
  if (input == "show router route-table" || input == "show router fib") {
    std::ostringstream out;
    out << "Prefix              Type   Next Hop       Interface";
    bool any = false;
    for (std::size_t index = 0; index < state.interfaces.size(); ++index) {
      if (!state.interface_operational(index)) continue;
      out << '\n' << state.interfaces[index].prefix << "        Local  -              "
          << state.interfaces[index].name;
      any = true;
    }
    for (const auto& route : state.static_routes) {
      if (!route.valid) continue;
      out << '\n' << ((route.network >> 24) & 255) << '.' << ((route.network >> 16) & 255)
          << '.' << ((route.network >> 8) & 255) << '.' << (route.network & 255) << '/'
          << static_cast<unsigned>(route.prefix_length) << "        Static "
          << ((route.next_hop >> 24) & 255) << '.' << ((route.next_hop >> 16) & 255)
          << '.' << ((route.next_hop >> 8) & 255) << '.' << (route.next_hop & 255)
          << "   resolved";
      any = true;
    }
    return any ? out.str()
               : "No active routes: forwarding hardware or interface is not operational";
  }
  if (input == "show router arp") return arp_table(state);
  if (input == "show system alarms") {
    if (!state.alarm_count) return "No active alarms";
    std::ostringstream out;
    out << "Severity  Object       Reason";
    for (std::size_t index = 0; index < state.alarm_count; ++index) {
      const auto& alarm = state.alarms[index];
      out << '\n' << alarm.severity << "     " << alarm.id << "   " << alarm.reason;
    }
    return out.str();
  }
  if (starts_with(input, "ping ")) {
    std::istringstream tokens(input);
    std::string command;
    std::string destination;
    std::string option;
    std::string trailing;
    std::uint32_t count = 5;
    tokens >> command >> destination;
    if (destination != ipv4_text(state.lab_hosts[1])) {
      return "MINOR: destination is outside the implemented milestone topology";
    }
    if (tokens >> option) {
      if (option != "count" || !(tokens >> count) || count < 1 || count > 100 ||
          (tokens >> trailing)) {
        return "MINOR: invalid ping parameters";
      }
    }
    return ping(count);
  }
  return std::nullopt;
}

std::string execute_md(DeviceState& state, CliSession& session,
                       const std::string& input) {
  if (input == "?" || input == "help") {
    return "show | configure | delete | compare | commit | discard | //";
  }
  if (input == "configure card 1 card-type iom4-e") {
    state.candidate_card = true;
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  if (input == "configure card 1 mda 1 mda-type me10-10gb-sfp+") {
    state.candidate_card = true;
    state.candidate_mda = true;
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  if (starts_with(input, "configure system name ")) {
    const auto name = std::string_view(input).substr(22);
    if (name.empty() || !copy_config_text(state.candidate_system_name, name)) {
      return "MINOR: system name must contain 1 to 64 characters";
    }
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  if (const auto parsed = port_tail(input, "configure port ")) {
    const auto [index, tail] = *parsed;
    if (tail == "admin-state enable" || tail == "admin-state disable") {
      state.ports[index].candidate_admin_enabled = tail.ends_with("enable");
    } else if (tail.starts_with("description ")) {
      auto value = tail.substr(12);
      if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
      }
      if (!copy_config_text(state.ports[index].candidate_description, value)) {
        return "MINOR: port description exceeds 64 characters";
      }
    } else if (tail.starts_with("ethernet mtu ")) {
      unsigned mtu{};
      const auto text = tail.substr(13);
      const auto result = std::from_chars(text.data(), text.data() + text.size(), mtu);
      // Source: nokia.sros.26_7.port.configuration. This profile supports an
      // untagged Ethernet payload and rejects values beyond Frame capacity.
      if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
          mtu < 576 || mtu > 1500) {
        return "MINOR: MTU must be between 576 and 1500 in this profile";
      }
      state.ports[index].candidate_mtu = static_cast<std::uint16_t>(mtu);
    } else {
      return std::string{"MINOR: unsupported MD-CLI port command in the "} +
             profile::release + " milestone profile";
    }
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  if (starts_with(input, "configure router \"Base\" interface ") &&
      input.find(" admin-state ") != std::string::npos) {
    const auto index = interface_index(input);
    if (!index || (!input.ends_with(" enable") && !input.ends_with(" disable"))) {
      return "MINOR: invalid router interface admin-state";
    }
    state.interfaces[*index].candidate_admin_enabled = input.ends_with(" enable");
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  constexpr std::string_view md_static = "configure router \"Base\" static-routes route ";
  if (starts_with(input, std::string(md_static))) {
    const auto parsed = static_route(std::string_view(input).substr(md_static.size()));
    if (!parsed) return "MINOR: invalid static route prefix or next hop";
    if (!install_candidate_static(state, *parsed)) return "MINOR: static route capacity reached";
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  if (input == "delete card 1") {
    state.candidate_card = false;
    state.candidate_mda = false;
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  if (input == "delete card 1 mda 1") {
    state.candidate_mda = false;
    session.candidate_dirty = true;
    return "Candidate updated";
  }
  if (input == "compare") {
    if (!session.candidate_dirty) return "No differences";
    std::string difference;
    if (state.candidate_card != state.card_provisioned) {
      difference = state.candidate_card ? "+ card 1 iom4-e" : "- card 1 iom4-e";
    }
    if (state.candidate_mda != state.mda_provisioned) {
      if (!difference.empty()) difference += '\n';
      difference += state.candidate_mda ? "+ mda 1 me10-10gb-sfp+"
                                        : "- mda 1 me10-10gb-sfp+";
    }
    if (state.candidate_system_name != state.system_name) {
      if (!difference.empty()) difference += '\n';
      difference += std::string{"~ system name "} + state.candidate_system_name.data();
    }
    for (std::size_t index = 0; index < state.ports.size(); ++index) {
      const auto& port = state.ports[index];
      if (port.admin_enabled != port.candidate_admin_enabled ||
          port.mtu != port.candidate_mtu ||
          port.description != port.candidate_description) {
        if (!difference.empty()) difference += '\n';
        difference += std::string{"~ port "} + port.id;
      }
    }
    for (const auto& route : state.static_routes) {
      if (route.valid != route.candidate_valid || route.network != route.candidate_network ||
          route.prefix_length != route.candidate_prefix_length ||
          route.next_hop != route.candidate_next_hop) {
        if (!difference.empty()) difference += '\n';
        difference += "~ static route";
      }
    }
    return difference.empty() ? "No differences" : difference;
  }
  if (input == "commit") {
    // Source: nokia.sros.26_7.md_cli.navigation. The documentation exposes an
    // out-of-date baseline indicator after another configuration owner changes
    // running state. Automatic conflict resolution is not implemented, so a
    // stale commit is rejected rather than guessed or silently rebased.
    if (session.candidate_outdated) {
      return "MINOR: candidate baseline is out of date; discard or update is required";
    }
    state.card_provisioned = state.candidate_card;
    state.mda_provisioned = state.candidate_card && state.candidate_mda;
    state.system_name = state.candidate_system_name;
    for (auto& port : state.ports) {
      port.admin_enabled = port.candidate_admin_enabled;
      port.mtu = port.candidate_mtu;
      port.description = port.candidate_description;
    }
    for (auto& interface : state.interfaces) {
      interface.admin_enabled = interface.candidate_admin_enabled;
    }
    for (auto& route : state.static_routes) {
      route.valid = route.candidate_valid;
      route.network = route.candidate_network;
      route.prefix_length = route.candidate_prefix_length;
      route.next_hop = route.candidate_next_hop;
    }
    session.candidate_dirty = false;
    return "Commit complete";
  }
  if (input == "discard") {
    state.candidate_card = state.card_provisioned;
    state.candidate_mda = state.mda_provisioned;
    state.candidate_system_name = state.system_name;
    for (auto& port : state.ports) {
      port.candidate_admin_enabled = port.admin_enabled;
      port.candidate_mtu = port.mtu;
      port.candidate_description = port.description;
    }
    for (auto& interface : state.interfaces) {
      interface.candidate_admin_enabled = interface.admin_enabled;
    }
    for (auto& route : state.static_routes) {
      route.candidate_valid = route.valid;
      route.candidate_network = route.network;
      route.candidate_prefix_length = route.prefix_length;
      route.candidate_next_hop = route.next_hop;
    }
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    return "Candidate discarded";
  }
  return std::string{"MINOR: unsupported MD-CLI command in the "} +
         profile::release + " milestone profile";
}

std::string execute_classic(DeviceState& state, CliSession& session,
                            const std::string& input) {
  if (input == "?" || input == "help") return "show | configure | //";
  if (input == "configure card 1 card-type iom4-e") {
    const bool changed = !state.card_provisioned;
    state.card_provisioned = true;
    // Source: nokia.sros.26_7.md_cli.navigation. Classic changes are immediate,
    // but uncommitted MD changes survive an engine switch. Only a clean
    // candidate follows running state; a dirty one keeps its values and marks
    // its baseline out of date for the MD prompt and commit guard.
    if (session.candidate_dirty && changed) {
      session.candidate_outdated = true;
    } else if (!session.candidate_dirty) {
      state.candidate_card = true;
    }
    return "Card 1 provisioned";
  }
  if (input == "configure card 1 no card-type") {
    const bool changed = state.card_provisioned || state.mda_provisioned;
    // Removing parent provisioning also removes child provisioning. Physical
    // presence remains a chassis fact and is never changed by a CLI command.
    state.card_provisioned = false;
    state.mda_provisioned = false;
    if (session.candidate_dirty && changed) {
      session.candidate_outdated = true;
    } else if (!session.candidate_dirty) {
      state.candidate_card = false;
      state.candidate_mda = false;
    }
    return "Card 1 provisioning removed";
  }
  if (input == "configure card 1 mda 1 mda-type me10-10gb-sfp+") {
    if (!state.card_provisioned) return "MINOR: card 1 is not provisioned";
    const bool changed = !state.mda_provisioned;
    state.mda_provisioned = true;
    if (session.candidate_dirty && changed) {
      session.candidate_outdated = true;
    } else if (!session.candidate_dirty) {
      state.candidate_mda = true;
    }
    return "MDA 1/1 provisioned";
  }
  if (input == "configure card 1 mda 1 no mda-type") {
    const bool changed = state.mda_provisioned;
    state.mda_provisioned = false;
    if (session.candidate_dirty && changed) {
      session.candidate_outdated = true;
    } else if (!session.candidate_dirty) {
      state.candidate_mda = false;
    }
    return "MDA 1/1 provisioning removed";
  }
  if (starts_with(input, "configure system name ")) {
    const auto name = std::string_view(input).substr(22);
    if (name.empty() || !copy_config_text(state.system_name, name)) {
      return "MINOR: system name must contain 1 to 64 characters";
    }
    if (session.candidate_dirty) session.candidate_outdated = true;
    else state.candidate_system_name = state.system_name;
    return "System name updated";
  }
  if (const auto parsed = port_tail(input, "configure port ")) {
    const auto [index, tail] = *parsed;
    auto& port = state.ports[index];
    if (tail == "shutdown" || tail == "no shutdown") {
      port.admin_enabled = tail == "no shutdown";
    } else if (tail.starts_with("description ")) {
      auto value = tail.substr(12);
      if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
      }
      if (!copy_config_text(port.description, value)) {
        return "MINOR: port description exceeds 64 characters";
      }
    } else if (tail.starts_with("ethernet mtu ")) {
      unsigned mtu{};
      const auto text = tail.substr(13);
      const auto result = std::from_chars(text.data(), text.data() + text.size(), mtu);
      if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
          mtu < 576 || mtu > 1500) {
        return "MINOR: MTU must be between 576 and 1500 in this profile";
      }
      port.mtu = static_cast<std::uint16_t>(mtu);
    } else {
      return std::string{"MINOR: unsupported classic CLI port command in the "} +
             profile::release + " milestone profile";
    }
    if (session.candidate_dirty) session.candidate_outdated = true;
    else {
      port.candidate_admin_enabled = port.admin_enabled;
      port.candidate_mtu = port.mtu;
      port.candidate_description = port.description;
    }
    return "Port configuration updated";
  }
  if (starts_with(input, "configure router interface ") &&
      (input.ends_with(" shutdown") || input.ends_with(" no shutdown"))) {
    const auto index = interface_index(input);
    if (!index) return "MINOR: unsupported router interface";
    state.interfaces[*index].admin_enabled = input.ends_with(" no shutdown");
    if (session.candidate_dirty) session.candidate_outdated = true;
    else state.interfaces[*index].candidate_admin_enabled =
        state.interfaces[*index].admin_enabled;
    return "Router interface configuration updated";
  }
  constexpr std::string_view classic_static = "configure router static-route-entry ";
  if (starts_with(input, std::string(classic_static))) {
    const auto parsed = static_route(std::string_view(input).substr(classic_static.size()));
    if (!parsed) return "MINOR: invalid static route prefix or next hop";
    auto slot = std::find_if(state.static_routes.begin(), state.static_routes.end(),
                              [parsed](const auto& item) {
                                return item.valid && item.network == parsed->network &&
                                       item.prefix_length == parsed->prefix;
                              });
    if (slot == state.static_routes.end()) {
      slot = std::find_if(state.static_routes.begin(), state.static_routes.end(),
                          [](const auto& item) { return !item.valid; });
    }
    if (slot == state.static_routes.end()) return "MINOR: static route capacity reached";
    slot->valid = true;
    slot->network = parsed->network;
    slot->prefix_length = parsed->prefix;
    slot->next_hop = parsed->next_hop;
    if (session.candidate_dirty) session.candidate_outdated = true;
    else {
      slot->candidate_valid = true;
      slot->candidate_network = slot->network;
      slot->candidate_prefix_length = slot->prefix_length;
      slot->candidate_next_hop = slot->next_hop;
    }
    return "Static route configured";
  }
  return std::string{"MINOR: unsupported classic CLI command in the "} +
         profile::release + " milestone profile";
}

std::string prompt(const CliSession& session) {
  if (session.engine == CliEngine::classic) return "\nA:R1# ";
  if (session.candidate_outdated && session.candidate_dirty) {
    return "\n!*[ex:/]\nA:admin@R1# ";
  }
  return session.candidate_dirty ? "\n*[ex:/]\nA:admin@R1# "
                                 : "\n[ex:/]\nA:admin@R1# ";
}

}  // namespace

std::string execute_cli(DeviceState& state, CliSession& session, const std::string& raw,
                        const std::function<std::string(std::uint32_t)>& ping) {
  const auto input = trim(raw);
  std::string output;
  if (input == "//") {
    session.engine = session.engine == CliEngine::md ? CliEngine::classic : CliEngine::md;
    // Source: nokia.sros.26_7.md_cli.navigation.
    output = session.engine == CliEngine::md
                 ? "INFO: CLI #2052: Switching to the MD-CLI engine"
                 : "INFO: CLI #2051: Switching to the classic CLI engine";
  } else if (input.empty()) {
    output.clear();
  } else if (const auto common = operational(state, input, ping)) {
    output = *common;
  } else if (session.engine == CliEngine::md) {
    output = execute_md(state, session, input);
  } else {
    output = execute_classic(state, session, input);
  }
  return output + prompt(session);
}

std::string complete_cli(const DeviceState& state, const CliSession& session,
                         const std::string& raw) {
  // Source: nokia.sros.26_7.md_cli.command_completion. Only executable commands
  // are exposed. Schema-only future commands never enter this list.
  const std::vector<std::string> common{
      "show system information", "show system alarms", "show card", "show mda",
      "show port", "show router interface", "show router route-table",
      "show router fib", "show router arp", "ping " + ipv4_text(state.lab_hosts[1])};
  static const std::vector<std::string> md{
      "compare", "commit", "discard", "configure card 1 card-type iom4-e",
      "configure card 1 mda 1 mda-type me10-10gb-sfp+", "delete card 1",
      "delete card 1 mda 1"};
  static const std::vector<std::string> classic{
      "configure card 1 card-type iom4-e",
      "configure card 1 mda 1 mda-type me10-10gb-sfp+",
      "configure card 1 no card-type", "configure card 1 mda 1 no mda-type"};
  const auto input = trim(raw);
  std::vector<std::string> matches;
  const auto collect = [&](const auto& commands) {
    for (const auto& command : commands) {
      if (command.rfind(input, 0) == 0) matches.push_back(command);
    }
  };
  collect(common);
  collect(session.engine == CliEngine::md ? md : classic);
  if (matches.empty()) return {};
  if (matches.size() == 1) return matches.front();
  std::ostringstream out;
  for (std::size_t index = 0; index < matches.size(); ++index) {
    if (index) out << '\n';
    out << matches[index];
  }
  return out.str();
}

}  // namespace router
