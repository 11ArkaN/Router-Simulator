// Shared operational commands, parsing primitives and terminal engine routing.
// Read-only commands may inspect the aggregate. Configuration commands receive
// only ConfigurationState and cannot mutate hardware or operational
// projections.

#include "router/cli.hpp"

#include "cli_internal.hpp"
#include "bof_cli_configuration.hpp"
#include "router/routing.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <ctime>
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

constexpr std::string_view table_rule{
    "=========================================================================="
    "====="};
constexpr std::string_view row_rule{"------------------------------------------"
                                    "-------------------------------------"};

std::string equipment_oper_state(EquipmentLifecycle lifecycle) {
  // SR OS summary tables expose Up or Down, while internal lifecycle reasons
  // remain available to the alarm model. Initializing is not operational Up.
  return lifecycle == EquipmentLifecycle::ready ? "up" : "down";
}

std::string uptime_text(std::chrono::milliseconds elapsed, bool rolling) {
  // SR OS prints uptime with centisecond precision. The legacy 32-bit value
  // rolls after 2^32 hundredths of a second, while the 64-bit line does not.
  std::uint64_t centiseconds =
      static_cast<std::uint64_t>(std::max<std::int64_t>(0, elapsed.count())) /
      10U;
  if (rolling)
    centiseconds &= 0xffffffffULL;
  const auto days = centiseconds / 8640000U;
  centiseconds %= 8640000U;
  const auto hours = centiseconds / 360000U;
  centiseconds %= 360000U;
  const auto minutes = centiseconds / 6000U;
  centiseconds %= 6000U;
  const auto seconds = centiseconds / 100U;
  const auto hundredths = centiseconds % 100U;
  std::ostringstream out;
  out << days << " days, " << std::setfill('0') << std::setw(2) << hours << ':'
      << std::setw(2) << minutes << ':' << std::setw(2) << seconds << '.'
      << std::setw(2) << hundredths << " (hr:min:sec)";
  return out.str();
}

std::string local_date_time(std::chrono::system_clock::time_point value) {
  // SR OS uses the session time-zone setting for show output. The milestone
  // does not expose that setting yet, so the process local zone is the only
  // truthful projection. The reentrant platform variants avoid shared tm
  // storage when control and forwarding shards render concurrently.
  const auto seconds = std::chrono::system_clock::to_time_t(value);
  std::tm local{};
#ifdef _WIN32
  localtime_s(&local, &seconds);
#else
  localtime_r(&seconds, &local);
#endif
  std::ostringstream out;
  out << std::put_time(&local, "%Y/%m/%d %H:%M:%S");
  return out.str();
}

std::string mode_duration_text(std::chrono::milliseconds elapsed) {
  // The Last Mode Changed line uses a different duration grammar from uptime:
  // whole days followed by zero-padded hours, minutes and seconds.
  auto seconds = static_cast<std::uint64_t>(
      std::max<std::int64_t>(0, elapsed.count()) / 1000);
  const auto days = seconds / 86400U;
  seconds %= 86400U;
  const auto hours = seconds / 3600U;
  seconds %= 3600U;
  const auto minutes = seconds / 60U;
  seconds %= 60U;
  std::ostringstream out;
  out << days << "d " << std::setfill('0') << std::setw(2) << hours << ':'
      << std::setw(2) << minutes << ':' << std::setw(2) << seconds;
  return out.str();
}

std::string
route_age_text(std::chrono::steady_clock::time_point selected_since) {
  // The documented route-table age is elapsed time in HHhMMmSSs form. A zero
  // clock is possible in isolated CLI unit tests before Runtime reconciles the
  // RIB and is rendered as a newly selected route rather than an epoch age.
  const auto now = std::chrono::steady_clock::now();
  auto seconds = selected_since != std::chrono::steady_clock::time_point{} &&
                         now > selected_since
                     ? static_cast<std::uint64_t>(
                           std::chrono::duration_cast<std::chrono::seconds>(
                               now - selected_since)
                               .count())
                     : 0U;
  const auto days = seconds / 86400U;
  seconds %= 86400U;
  const auto hours = seconds / 3600U;
  seconds %= 3600U;
  const auto minutes = seconds / 60U;
  seconds %= 60U;
  std::ostringstream out;
  out << std::setfill('0');
  if (days) {
    // Route-table summary trades seconds for a day field after 24 hours while
    // retaining the fixed ten-character column documented by Nokia.
    out << std::setw(2) << days << 'd' << std::setw(2) << hours << 'h'
        << std::setw(2) << minutes << 'm';
  } else {
    out << std::setw(2) << hours << 'h' << std::setw(2) << minutes << 'm'
        << std::setw(2) << seconds << 's';
  }
  return out.str();
}

std::string alarm_time(std::uint64_t epoch_ms) {
  // Facility output follows the router's local time zone and prints
  // centiseconds. localtime_s is used on Windows and localtime_r elsewhere;
  // both write caller-owned storage and avoid sharing a mutable tm object.
  const auto seconds = static_cast<std::time_t>(epoch_ms / 1000U);
  std::tm local{};
#ifdef _WIN32
  localtime_s(&local, &seconds);
#else
  localtime_r(&seconds, &local);
#endif
  std::ostringstream out;
  out << std::put_time(&local, "%Y/%m/%d %H:%M:%S") << '.' << std::setfill('0')
      << std::setw(2) << (epoch_ms % 1000U) / 10U;
  return out.str();
}

// Builds the documented show card summary. Provisioned and equipped identities
// remain distinct so a mismatch is rendered on the continuation line used by
// SR OS instead of being collapsed into an invented status value.
std::string card_table(const DeviceState &state) {
  const auto &running = state.configuration.running;
  const auto &hardware = state.hardware;
  std::ostringstream out;
  out << table_rule << "\nCard Summary\n"
      << table_rule
      << "\nSlot      Provisioned Type                         Admin "
         "Operational   Comments\n"
      << "          Equipped Type (if different)            State State\n"
      << row_rule;
  for (std::size_t card_index = 0; card_index < running.cards.size();
       ++card_index) {
    const auto &card = running.cards[card_index];
    const auto &equipped = hardware.cards[card_index];
    if (!card.type && !equipped.type)
      continue;
    out << '\n'
        << std::left << std::setw(10) << card_index + 1U << std::setw(41)
        << (card.type ? card.type : "") << std::setw(6)
        << (card.admin_enabled ? "up" : "down") << std::setw(14)
        << equipment_oper_state(equipped.equipment.lifecycle);
    if (equipped.type &&
        (!card.type || std::string_view{equipped.type} != card.type))
      out << '\n' << std::setw(10) << "" << equipped.type;
  }
  out << '\n'
      << std::left << std::setw(10) << profile::control_slot << std::setw(41)
      << profile::control_card_type << std::setw(6) << "up" << std::setw(14)
      << "up/active" << '\n'
      << table_rule;
  return out.str();
}

// show mda uses its own Nokia summary layout and never reuses the card table.
std::string mda_table(const DeviceState &state) {
  const auto &running = state.configuration.running;
  const auto &hardware = state.hardware;
  std::ostringstream out;
  out << table_rule << "\nMDA Summary\n"
      << table_rule
      << "\nSlot  Mda   Provisioned Type                            Admin     "
         "Operational\n"
      << "                    Equipped Type (if different)        State     "
         "State\n"
      << row_rule;
  for (std::size_t card_index = 0; card_index < running.cards.size();
       ++card_index) {
    for (std::size_t mda_index = 0;
         mda_index < running.cards[card_index].mdas.size(); ++mda_index) {
      const auto &configured = running.cards[card_index].mdas[mda_index];
      const auto &equipped = hardware.cards[card_index].mdas[mda_index];
      if (!configured.type && !equipped.type)
        continue;
      out << '\n'
          << std::left << std::setw(6) << card_index + 1U << std::setw(6)
          << mda_index + 1U << std::setw(48)
          << (configured.type ? configured.type : "") << std::setw(10)
          << (configured.admin_enabled ? "up" : "down")
          << equipment_oper_state(equipped.equipment.lifecycle);
      if (equipped.type && (!configured.type ||
                            std::string_view{equipped.type} != configured.type))
        // The equipped identity is a continuation beneath the provisioned
        // field in Nokia's summary, with the same 20-column indent as the
        // documented secondary header.
        out << '\n' << std::setw(20) << "" << equipped.type;
    }
  }
  out << '\n' << table_rule;
  return out.str();
}

// Projects every currently inventoried physical port and its control-owned
// counters without exposing unequipped configuration entries as hardware.
std::string port_table(const DeviceState &state) {
  const auto &running = state.configuration.running;
  std::ostringstream out;
  out << table_rule << "\nPorts on Slot " << profile::line_card_slot << '\n'
      << table_rule
      << "\nPort          Admin Link Port    Cfg  Oper LAG/ Port Port Port   "
         "C/QS/S/XFP/\n"
      << "Id            State      State   MTU  MTU  Bndl Mode Encp Type   "
         "MDIMDX\n"
      << row_rule;
  const auto count = state.inventory_port_count();
  for (std::size_t index = 0; index < count; ++index) {
    const auto &port = running.ports[index];
    out << '\n'
        << std::left << std::setw(14) << profile::port_ids[index]
        << std::setw(6) << (port.admin_enabled ? "Up" : "Down") << std::setw(5)
        << (state.hardware.link_signal[index] ? "Yes" : "No") << std::setw(8)
        << (state.port_operational(index) ? "Up" : "Down") << std::setw(5)
        << port.mtu << std::setw(5)
        << port.mtu
        // The LAG/bundle column is right-aligned on SR OS, unlike the textual
        // fields around it. Restoring left alignment afterward keeps Mode,
        // Encap and Type at columns 48, 53 and 58 respectively.
        << std::right << std::setw(4) << "-" << std::left << ' ' << std::setw(5)
        << "netw" << std::setw(5) << "null" << std::setw(7) << "xgige";
  }
  out << '\n' << table_rule;
  return out.str();
}

// Formats only valid forwarding-returned adjacency entries. An empty table is
// explicit and never inferred from the topology editor.
std::string arp_table(const DeviceState &state) {
  const auto &entries = state.operational.arp;
  const auto now = std::chrono::steady_clock::now();
  std::ostringstream out;
  out << table_rule << "\nARP Table (Router: Base)\n"
      << table_rule
      << "\nIP Address      MAC Address       Expiry    Type   Interface\n"
      << row_rule;
  std::array<std::size_t, profile::port_count> ordered{};
  std::size_t count{};
  for (std::size_t index = 0; index < entries.size(); ++index) {
    if (entries[index].valid && entries[index].expires_at > now)
      ordered[count++] = index;
  }
  // SR OS documents the unfiltered table as sorted by IP address. Sorting a
  // bounded index array avoids moving adjacency state or allocating on show.
  std::sort(ordered.begin(), ordered.begin() + count,
            [&entries](std::size_t left, std::size_t right) {
              return entries[left].address < entries[right].address;
            });
  for (std::size_t position = 0; position < count; ++position) {
    const auto &entry = entries[ordered[position]];
    const auto remaining_seconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            entry.expires_at - now + std::chrono::milliseconds{999})
            .count());
    std::ostringstream expiry;
    expiry << std::setfill('0') << std::setw(2) << remaining_seconds / 3600U
           << 'h' << std::setw(2) << (remaining_seconds % 3600U) / 60U << 'm'
           << std::setw(2) << remaining_seconds % 60U << 's';
    out << '\n'
        << std::left << std::setw(16)
        << (std::to_string(entry.address[0]) + '.' +
            std::to_string(entry.address[1]) + '.' +
            std::to_string(entry.address[2]) + '.' +
            std::to_string(entry.address[3]))
        << std::right << std::hex << std::nouppercase << std::setfill('0');
    for (std::size_t index = 0; index < entry.mac.size(); ++index) {
      if (index)
        out << ':';
      out << std::setw(2) << static_cast<unsigned>(entry.mac[index]);
    }
    // Nokia's fixed-width report places exactly one separator after the
    // 17-character MAC address. Keeping Expiry at the documented column also
    // keeps Type and Interface aligned when a terminal copies the table.
    out << std::setfill(' ') << std::left << ' ' << std::setw(10)
        << expiry.str() << std::setw(7) << "Dyn[I]";
    const auto interface = std::find_if(
        state.configuration.running.interfaces.begin(),
        state.configuration.running.interfaces.end(), [&](const auto &item) {
          return item.valid && item.port_index == entry.port_index;
        });
    out << (interface == state.configuration.running.interfaces.end()
                ? "n/a"
                : interface->name);
  }
  out << '\n'
      << row_rule << "\nNo. of ARP Entries: " << std::dec << count << '\n'
      << table_rule;
  return out.str();
}

std::string ipv4_value_text(std::uint32_t address) {
  // Route state stores IPv4 in network byte significance. Formatting it here
  // keeps all operational tables independent from platform socket APIs.
  return std::to_string((address >> 24) & 255U) + '.' +
         std::to_string((address >> 16) & 255U) + '.' +
         std::to_string((address >> 8) & 255U) + '.' +
         std::to_string(address & 255U);
}

std::optional<std::size_t> resolving_interface(const DeviceState &state,
                                               std::uint32_t next_hop) {
  // A static next hop is active only through an operational connected prefix.
  // This is a read-only projection of the same longest-prefix prerequisite
  // used by route programming, not a UI topology shortcut.
  const auto &running = state.configuration.running;
  for (std::size_t index = 0; index < running.interface_count; ++index) {
    const auto &interface = running.interfaces[index];
    const auto mask = routing::prefix_mask(interface.prefix_length);
    if (interface.valid && state.interface_operational(index) &&
        (next_hop & mask) == interface.network)
      return index;
  }
  return std::nullopt;
}

std::optional<std::string> operational_command(const DeviceState &state,
                                               const ParsedCommand &command,
                                               const CliPing &send_ping) {
  // Command IDs come from the generated grammar. This dispatcher implements
  // read-only device operations shared by both terminal engines.
  using enum cli_schema::CommandId;
  const auto &running = state.configuration.running;
  if (command.spec->id == show_system_information) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - state.operational.started_at);
    // steady_clock is authoritative for duration. Converting the same elapsed
    // duration from system_clock::now gives the wall-clock instant at which
    // this fixed configuration mode became operational without using wall
    // time for timer decisions.
    const auto mode_changed_at = std::chrono::system_clock::now() - elapsed;
    std::ostringstream out;
    out << table_rule << "\nSystem Information\n"
        << table_rule
        << "\nSystem Name            : " << running.system_name.data()
        << "\nSystem Type            : " << profile::chassis
        << "\nChassis Topology       : Standalone"
        << "\nSystem Version         : " << profile::software_version
        << "\nCrypto Module Version  : " << profile::crypto_module_version
        << "\nSystem Contact         :"
        << "\nSystem Location        :"
        << "\nSystem Coordinates     :"
        << "\nSystem Active Slot     : " << profile::control_slot
        << "\nSystem Up Time         : " << uptime_text(elapsed, true)
        << "\nSystem Up Time (64-bit): " << uptime_text(elapsed, false)
        << "\nConfiguration Mode Cfg : " << profile::configuration_mode
        << "\nConfiguration Mode Oper: " << profile::configuration_mode
        << "\nLast Mode Changed      : " << local_date_time(mode_changed_at)
        << " Duration: " << mode_duration_text(elapsed)
        << "\n\nSNMP Port              : " << profile::snmp_port
        << "\nSNMP Engine ID         : N/A"
        << "\nSNMP Engine Boots      : 1"
        << "\nSNMP Max Message Size  : 1500"
        << "\nSNMP Max Bulk Duration : N/A"
        << "\nSNMP Admin State       : Disabled"
        << "\nSNMP Oper State        : Disabled"
        << "\nSNMP Index Boot Status : Not Persistent"
        << "\nSNMP Sync State        : N/A"
        << "\nTel/Tel6/SSH/FTP Admin : Disabled/Disabled/Disabled/Disabled"
        << "\nTel/Tel6/SSH/FTP Oper  : Down/Down/Down/Down"
        << "\nConsole Port Logins    : Enabled/Disabled"
        << "\nBOF Source             : N/A"
        << "\nImage Source           : N/A"
        << "\nConfig Source          : N/A"
        << "\nLast Booted Config File: N/A"
        << "\nLast Boot Cfg Version  : N/A"
        << "\nLast Boot Config Header: N/A"
        << "\nLast Boot Index Version: N/A"
        << "\nLast Boot Index Header : N/A"
        << "\nLast Saved Config      : N/A"
        << "\nTime Last Saved        : N/A"
        << "\nChanges Since Last Save: "
        << (state.configuration.running_unsaved ? "Yes" : "No")
        << "\nUser Last Modified     : admin"
        << "\nTime Last Modified     : N/A"
        << "\nMax Cfg/BOF Backup Rev : " << profile::config_backup_count
        << "\nCfg-OK Script          : N/A"
        << "\nCfg-OK Script Status   : not used"
        << "\nCfg-Fail Script        : N/A"
        << "\nCfg-Fail Script Status : not used"
        << "\nIPv4 autoconfiguration : Disabled"
        << "\nIPv6 autoconfiguration : Disabled"
        << "\nManagement IPv4 Addr   : N/A"
        << "\nManagement IPv6 Addr   : N/A"
        << "\nPrimary DNS Server     : N/A"
        << "\nSecondary DNS Server   : N/A"
        << "\nTertiary DNS Server    : N/A"
        << "\nDNS Domain             : N/A"
        << "\nDNS Resolve Preference : " << profile::dns_resolve_preference
        << "\nDNSSEC AD Validation   : False"
        << "\nDNSSEC Response Control: " << profile::dnssec_response_control
        << "\nBOF Static Routes      : None"
        << "\nICMP Vendor Enhancement: Disabled"
        << "\nEFM OAM Grace Tx Enable: False"
        << "\nEFM OAM Dying Gasp Rst : Disabled" << '\n'
        << "\nSystem Reboot Required : No"
        << "\nLast Reboot Reason     : other\n"
        << table_rule;
    return out.str();
  }
  if (command.spec->id == show_card)
    return card_table(state);
  if (command.spec->id == show_mda)
    return mda_table(state);
  if (command.spec->id == show_port)
    return port_table(state);
  if (command.spec->id == show_router_interface) {
    std::ostringstream out;
    out << table_rule << "\nInterface Table (Router: Base)\n"
        << table_rule
        << "\nInterface-Name                   Adm       Opr(v4/v6)  Mode    "
           "Port/SapId\n"
        << "   IP-Address                                                  "
           "PfxState\n"
        << row_rule;
    std::size_t count{};
    for (std::size_t index = 0; index < running.interface_count; ++index) {
      const auto &interface = running.interfaces[index];
      if (!interface.valid)
        continue;
      ++count;
      out << '\n'
          << std::left << std::setw(33) << interface.name << std::setw(10)
          << (interface.admin_enabled ? "Up" : "Down") << std::setw(12)
          << (state.interface_operational(index) ? "Up/Down" : "Down/Down")
          << std::setw(8) << "Network"
          << profile::port_ids[interface.port_index]
          // Address rows are children of an interface row in the SR OS
          // report. The three-column indent is part of that hierarchy, not a
          // cosmetic choice made by the browser terminal.
          << "\n   " << std::setw(61)
          << (ipv4_value_text(routing::ipv4(
                  interface.ipv4[0], interface.ipv4[1], interface.ipv4[2],
                  interface.ipv4[3])) +
              '/' + std::to_string(interface.prefix_length))
          << "n/a";
    }
    out << '\n' << row_rule << "\nInterfaces : " << count << '\n' << table_rule;
    return out.str();
  }
  if (command.spec->id == show_router_route_table) {
    std::ostringstream out;
    out << table_rule << "\nRoute Table (Router: Base)\n"
        << table_rule
        << "\nDest Prefix[Flags]                            Type    Proto     "
           "Age        Pref\n"
        << "      Next Hop[Interface Name]                                    "
           "Metric\n"
        << row_rule;
    std::size_t count{};
    for (std::size_t index = 0; index < running.interface_count; ++index) {
      const auto &interface = running.interfaces[index];
      if (!interface.valid || !state.interface_operational(index))
        continue;
      ++count;
      out << '\n'
          << std::left << std::setw(47)
          << (ipv4_value_text(interface.network) + '/' +
              std::to_string(interface.prefix_length))
          << std::setw(8)
          << "Local" << std::setw(10) << "Local" << std::setw(11)
          << route_age_text(state.operational.connected_route_since[index])
          << "0\n      " << std::setw(60) << interface.name << "0";
    }
    for (std::size_t index = 0; index < running.static_routes.size(); ++index) {
      const auto &route = running.static_routes[index];
      if (!route.valid || !resolving_interface(state, route.next_hop))
        continue;
      ++count;
      const auto prefix = ipv4_value_text(route.network) + '/' +
                          std::to_string(route.prefix_length);
      out << '\n'
          << std::left << std::setw(47) << prefix << std::setw(8) << "Remote"
          << std::setw(10) << "Static" << std::setw(11)
          << route_age_text(state.operational.static_route_since[index])
          << "5\n      " << std::setw(60) << ipv4_value_text(route.next_hop)
          << "1";
    }
    out << '\n'
        << row_rule << "\nNo. of Routes: " << count << '\n'
        << table_rule;
    return out.str();
  }
  if (command.spec->id == show_router_fib) {
    const auto slot = argument(command, cli_schema::TokenKind::card_slot);
    if (!slot || *slot != std::to_string(profile::line_card_slot))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    std::ostringstream out;
    out << table_rule << "\nFIB Display\n"
        << table_rule
        << "\nPrefix [Flags]                                              "
           "Protocol\n"
        << "  NextHop\n"
        << row_rule;
    std::size_t count{};
    for (std::size_t index = 0; index < running.interface_count; ++index) {
      const auto &interface = running.interfaces[index];
      if (!interface.valid || !state.interface_operational(index))
        continue;
      ++count;
      out << '\n'
          << std::left << std::setw(61)
          << (ipv4_value_text(interface.network) + '/' +
              std::to_string(interface.prefix_length))
          << "LOCAL\n  "
          << ipv4_value_text(interface.network) << " (" << interface.name
          << ')';
    }
    for (const auto &route : running.static_routes) {
      if (!route.valid || !resolving_interface(state, route.next_hop))
        continue;
      ++count;
      const auto prefix = ipv4_value_text(route.network) + '/' +
                          std::to_string(route.prefix_length);
      const auto interface_index = resolving_interface(state, route.next_hop);
      out << '\n'
          << std::left << std::setw(61) << prefix << "STATIC\n  "
          << ipv4_value_text(route.next_hop);
      if (interface_index)
        out << " (" << running.interfaces[*interface_index].name << ')';
    }
    out << '\n'
        << row_rule << "\nTotal Entries : " << count << '\n'
        << row_rule << '\n'
        << table_rule;
    return out.str();
  }
  if (command.spec->id == show_router_arp)
    return arp_table(state);
  if (command.spec->id == show_system_alarms) {
    std::ostringstream out;
    std::size_t critical{}, major{}, minor{}, warning{};
    for (std::size_t index = 0; index < state.operational.alarm_count;
         ++index) {
      const auto severity =
          std::string_view{state.operational.alarms[index].severity};
      critical += severity == "critical";
      major += severity == "major";
      minor += severity == "minor";
      warning += severity == "warning";
    }
    out << table_rule << "\nAlarms [Critical:" << critical << " Major:" << major
        << " Minor:" << minor << " Warning:" << warning
        << " Total:" << static_cast<unsigned>(state.operational.alarm_count)
        << "]\n"
        << table_rule
        << "\nIndex      Date/Time               Severity     Alarm         "
           "Resource\n"
        << "   Details\n"
        << row_rule;
    for (std::size_t reverse = state.operational.alarm_count; reverse > 0;
         --reverse) {
      const auto &alarm = state.operational.alarms[reverse - 1U];
      const bool card = std::string_view{alarm.id}.starts_with("card-");
      const bool mda = std::string_view{alarm.id}.starts_with("mda-");
      // Alarm ids are persisted text. Resolve by value instead of comparing
      // const-char pointers, which would only appear to work while both sides
      // happened to reference the same generated string literal.
      const auto alarm_port_index = port_index(alarm.id);
      const auto resource =
          card ? std::string{"Card "} + std::to_string(profile::line_card_slot)
          : mda
              ? std::string{"MDA "} + std::to_string(profile::line_card_slot) +
                    '/' + std::to_string(profile::mda_slot)
              : std::string{"Port "} + std::string{alarm.id};
      std::string severity{alarm.severity};
      std::transform(severity.begin(), severity.end(), severity.begin(),
                     [](unsigned char value) {
                       return static_cast<char>(std::toupper(value));
                     });
      std::string details;
      if (card || mda) {
        details = card ? "Class IOM Module: " : "Class MDA Module: ";
        details += std::string_view{alarm.reason} == "not-equipped"
                       ? "removed"
                       : "wrong type inserted";
      } else {
        const auto interface =
            std::find_if(running.interfaces.begin(), running.interfaces.end(),
                         [alarm_port_index](const auto &item) {
                           return alarm_port_index && item.valid &&
                                  item.port_index == *alarm_port_index;
                         });
        details = "Interface " +
                  (interface == running.interfaces.end()
                       ? std::string{alarm.id}
                       : std::string{interface->name}) +
                  " is not operational";
      }
      out << '\n'
          << std::left << std::setw(11) << reverse << std::setw(24)
          << alarm_time(alarm.raised_at_epoch_ms) << std::setw(13) << severity
          << std::setw(14) << alarm.code << resource << "\n   " << details
          << '\n';
    }
    out << table_rule;
    return out.str();
  }
  if (command.spec->id == cli_schema::CommandId::ping ||
      command.spec->id == cli_schema::CommandId::ping_count ||
      command.spec->id == cli_schema::CommandId::ping_size ||
      command.spec->id == cli_schema::CommandId::ping_do_not_fragment ||
      command.spec->id == cli_schema::CommandId::ping_size_do_not_fragment ||
      command.spec->id == cli_schema::CommandId::ping_count_size ||
      command.spec->id == cli_schema::CommandId::ping_count_do_not_fragment ||
      command.spec->id ==
          cli_schema::CommandId::ping_count_size_do_not_fragment) {
    const auto destination = *argument(command, cli_schema::TokenKind::ipv4);
    // Nokia-compatible defaults and bounds belong to the pinned release
    // profile, not to the generic parser or packet encoder.
    std::uint32_t count = profile::default_ping_count;
    if (const auto count_text =
            argument(command, cli_schema::TokenKind::count)) {
      unsigned parsed_count{};
      const auto parsed = std::from_chars(
          count_text->data(), count_text->data() + count_text->size(),
          parsed_count);
      if (parsed.ec != std::errc{} ||
          parsed.ptr != count_text->data() + count_text->size() ||
          parsed_count == 0 || parsed_count > profile::maximum_ping_count)
        return "MINOR: MGMT_CORE #2301: Invalid element value - " +
               std::string{*count_text} + " out of range 1.." +
               std::to_string(profile::maximum_ping_count);
      count = parsed_count;
    }
    std::uint16_t payload_octets = profile::default_ping_payload_octets;
    if (const auto size_text = argument(command, cli_schema::TokenKind::size)) {
      unsigned parsed_size{};
      const auto parsed = std::from_chars(
          size_text->data(), size_text->data() + size_text->size(),
          parsed_size);
      // The first endpoint profile supports one untagged 1500-byte IPv4
      // packet. Keeping this upper bound beside Frame prevents the CLI from
      // accepting data that its selected hardware profile cannot encode.
      if (parsed.ec != std::errc{} ||
          parsed.ptr != size_text->data() + size_text->size() ||
          parsed_size < profile::minimum_ping_payload_octets ||
          parsed_size > profile::maximum_ping_payload_octets)
        return "MINOR: MGMT_CORE #2301: Invalid element value - " +
               std::string{*size_text} + " out of range " +
               std::to_string(profile::minimum_ping_payload_octets) + ".." +
               std::to_string(profile::maximum_ping_payload_octets);
      payload_octets = static_cast<std::uint16_t>(parsed_size);
    }
    const bool dont_fragment = std::any_of(
        command.tokens.begin(), command.tokens.begin() + command.token_count,
        [](std::string_view token) { return token == "do-not-fragment"; });
    const auto destination_value = ipv4_value(destination);
    if (!destination_value)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    return send_ping({static_cast<std::uint8_t>(*destination_value >> 24),
                      static_cast<std::uint8_t>(*destination_value >> 16),
                      static_cast<std::uint8_t>(*destination_value >> 8),
                      static_cast<std::uint8_t>(*destination_value)},
                     count, payload_octets, dont_fragment);
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

bool remove_static(DeviceConfiguration &configuration,
                   std::string_view prefix) {
  // The route list key is destination prefix plus route type. The milestone
  // exposes only unicast, so parsing with a throwaway valid next hop reuses the
  // same strict host-bit and prefix-length validation as route creation.
  const auto parsed = parse_static_route(prefix, "0.0.0.0");
  if (!parsed)
    return false;
  const auto existing = std::find_if(
      configuration.static_routes.begin(), configuration.static_routes.end(),
      [&parsed](const StaticRouteConfiguration &route) {
        return route.valid && route.network == parsed->network &&
               route.prefix_length == parsed->prefix;
      });
  if (existing == configuration.static_routes.end())
    return false;
  *existing = {};
  return true;
}

std::optional<ParsedInterfaceAddress>
parse_interface_address(std::string_view address,
                        std::string_view prefix_length) {
  // Classic supplies one CIDR token, while MD supplies address and
  // prefix-length as separate leaves. Normalizing both syntaxes here keeps
  // engine renderers separate without duplicating IPv4 validation semantics.
  if (prefix_length.empty()) {
    const auto slash = address.find('/');
    if (slash == std::string_view::npos)
      return std::nullopt;
    prefix_length = address.substr(slash + 1U);
    address = address.substr(0, slash);
  }
  const auto value = ipv4_value(address);
  unsigned prefix{};
  const auto parsed = std::from_chars(prefix_length.data(),
                                      prefix_length.data() + prefix_length.size(),
                                      prefix);
  if (!value || parsed.ec != std::errc{} ||
      parsed.ptr != prefix_length.data() + prefix_length.size() ||
      prefix > 32U)
    return std::nullopt;
  const auto mask = routing::prefix_mask(static_cast<std::uint8_t>(prefix));
  const auto host_bits = ~mask;
  const auto first = *value >> 24;
  if (!*value || *value == 0xffffffffU || !first || first == 127U ||
      first >= 224U ||
      (prefix <= 30U &&
       (((*value) & host_bits) == 0U || ((*value) & host_bits) == host_bits)))
    return std::nullopt;
  return ParsedInterfaceAddress{
      .address = {static_cast<std::uint8_t>(*value >> 24),
                  static_cast<std::uint8_t>(*value >> 16),
                  static_cast<std::uint8_t>(*value >> 8),
                  static_cast<std::uint8_t>(*value)},
      .network = *value & mask,
      .prefix = static_cast<std::uint8_t>(prefix)};
}

bool set_interface_address(DeviceConfiguration &configuration,
                           std::size_t interface_index,
                           ParsedInterfaceAddress address) {
  if (interface_index >= configuration.interface_count)
    return false;
  const auto mask = routing::prefix_mask(address.prefix);
  for (std::size_t index = 0; index < configuration.interface_count; ++index) {
    if (index == interface_index || !configuration.interfaces[index].valid)
      continue;
    const auto &existing = configuration.interfaces[index];
    const auto existing_mask = routing::prefix_mask(existing.prefix_length);
    if ((address.network & existing_mask) == existing.network ||
        (existing.network & mask) == address.network)
      return false;
  }
  auto &interface = configuration.interfaces[interface_index];
  interface.ipv4 = address.address;
  interface.network = address.network;
  interface.prefix_length = address.prefix;
  return true;
}

bool set_interface_port(DeviceConfiguration &configuration,
                        std::size_t interface_index, std::size_t port_index) {
  if (interface_index >= configuration.interface_count ||
      port_index >= profile::port_count)
    return false;
  for (std::size_t index = 0; index < configuration.interface_count; ++index) {
    if (index != interface_index && configuration.interfaces[index].valid &&
        configuration.interfaces[index].port_index == port_index)
      return false;
  }
  configuration.interfaces[interface_index].port_index =
      static_cast<std::uint8_t>(port_index);
  return true;
}

// Removes one balanced quote pair after tokenizer validation. Returned storage
// remains borrowed from the parsed command for the duration of execution.
std::string_view unquote(std::string_view value) noexcept {
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
    return value.substr(1, value.size() - 2);
  return value;
}

bool valid_cli_string(std::string_view value) noexcept {
  // SR OS configuration strings accept printable 7-bit ASCII. A value that
  // contains a question mark, hash or dollar sign must be quoted, and embedded
  // quotes are unsupported. The tokenizer has already verified an outer pair.
  const bool quoted =
      value.size() >= 2 && value.front() == '"' && value.back() == '"';
  const auto content = quoted ? value.substr(1, value.size() - 2) : value;
  return std::all_of(content.begin(), content.end(),
                     [quoted](unsigned char ch) {
                       return ch >= 0x20U && ch <= 0x7eU && ch != '"' &&
                              (quoted || (ch != '#' && ch != '?' && ch != '$'));
                     });
}

namespace {

std::string_view session_path(const CliSession &session,
                              CliEngine engine) noexcept {
  // Path storage is always NUL-terminated by set_session_path. A bounded view
  // avoids reading padding bytes restored from a checkpoint.
  const auto &path =
      engine == CliEngine::md ? session.md_path : session.classic_path;
  return {path.data(), std::char_traits<char>::length(path.data())};
}

bool set_session_path(CliSession &session, CliEngine engine,
                      std::string_view value) noexcept {
  auto &path = engine == CliEngine::md ? session.md_path : session.classic_path;
  if (value.size() >= path.size())
    return false;
  path.fill('\0');
  std::copy(value.begin(), value.end(), path.begin());
  return true;
}

std::array<char, 160> &previous_session_path(CliSession &session,
                                             CliEngine engine) noexcept {
  return engine == CliEngine::md ? session.md_previous_path
                                 : session.classic_previous_path;
}

void move_session_path(CliSession &session, std::string_view value) noexcept {
  // A navigation records the origin for exit. back deliberately bypasses this
  // helper because repeatedly walking parents must not bounce between paths.
  auto &previous = previous_session_path(session, session.engine);
  previous.fill('\0');
  const auto current = session_path(session, session.engine);
  std::copy(current.begin(), current.end(), previous.begin());
  set_session_path(session, session.engine, value);
}

void parent_context(CliSession &session) noexcept {
  // The generated tree knows that a list node and its key form one context.
  // This avoids invalid intermediate paths such as "configure card".
  set_session_path(
      session, session.engine,
      parent_command_prefix(session, session_path(session, session.engine)));
}

void previous_context(CliSession &session) noexcept {
  // exit restores the saved origin and makes the old current path the next
  // origin, matching the reversible working-context behavior of MD-CLI.
  auto &previous = previous_session_path(session, session.engine);
  std::array<char, 160> current{};
  const auto path = session_path(session, session.engine);
  std::copy(path.begin(), path.end(), current.begin());
  set_session_path(session, session.engine, std::string_view{previous.data()});
  previous = current;
}

std::string effective_input(const CliSession &session, std::string_view input) {
  // A leading slash selects the operational root. Otherwise a non-global line
  // is resolved below the engine's own saved working context.
  if (input.starts_with('/') ||
      (session.engine == CliEngine::classic && input.starts_with('\\'))) {
    input.remove_prefix(1);
    return std::string{input};
  }
  const auto path = session_path(session, session.engine);
  if (path.empty())
    return std::string{input};
  if (session.engine == CliEngine::md && input.starts_with("delete ") &&
      (path == "configure" || path.starts_with("configure ") ||
       path == "bof" || path.starts_with("bof "))) {
    // MD delete is an operator applied to a path. From /configure card 1,
    // "delete mda 1" denotes the same modeled node as the root form
    // "delete card 1 mda 1". The generated command row remains canonical.
    const bool bof = path == "bof" || path.starts_with("bof ");
    const auto relative_path =
        path == "configure" || path == "bof"
            ? std::string_view{}
            : path.substr(bof ? 4U : 10U);
    return std::string{"delete "} + (bof ? "bof " : "") +
           (relative_path.empty() ? std::string{}
                                  : std::string{relative_path} + ' ') +
           std::string{input.substr(7)};
  }
  return std::string{path} + ' ' + std::string{input};
}

bool md_configuration_command(cli_schema::CommandId id) noexcept {
  using enum cli_schema::CommandId;
  if (router::lab::bof_cli::is_md_command(id))
    return true;
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

bool global_action(cli_schema::CommandId id, CliEngine engine) noexcept {
  // Operational reports are rooted commands in both engines. In particular,
  // MD-CLI requires /show from a configuration context. Only the commands
  // listed by Nokia as global bypass contextual path resolution here.
  using enum cli_schema::CommandId;
  switch (id) {
  case switch_engine:
  case help:
  case help_edit:
  case help_global:
  case help_globals:
  case help_special_characters:
  case navigate_back:
  case navigate_back_levels:
  case navigate_closing_brace:
  case navigate_exit:
  case navigate_exit_all:
  case navigate_root:
  case navigate_classic_root:
  case ping:
  case ping_count:
    return true;
  case navigate_top:
  case md_edit_config_exclusive:
  case md_edit_config_global:
  case md_edit_config_private:
  case md_edit_config_read_only:
  case md_info:
  case md_info_detail:
  case md_compare:
  case md_commit:
  case md_discard:
  case md_delete_card:
  case md_delete_mda:
  case md_delete_port_description:
  case md_delete_static_route:
    return engine == CliEngine::md;
  default:
    return false;
  }
}

std::string classic_help(cli_schema::CommandId id) {
  // These texts are the user-visible contract of the classic CLI help command,
  // sourced from the 26.7 classic `help` reference. The globals list is limited
  // to commands that this release profile actually executes, so help never
  // advertises a successful-looking no-op.
  using enum cli_schema::CommandId;
  if (id == help) {
    return "Help may be requested at any point by hitting a question mark "
           "'?'.\n"
           "In case of an executable node, the syntax for that node will be "
           "displayed with an\nexplanation of all parameters.\n"
           "In case of sub-commands, a brief description is provided.\n"
           "Global Commands:\n"
           "Help on global commands can be observed by issuing \"help "
           "globals\" "
           "at any time.\n"
           "Editing Commands:\n"
           "Help on editing commands can be observed by issuing \"help edit\" "
           "at any time.";
  }
  if (id == help_edit) {
    return "Delete current character.....................Ctrl-d\n"
           "Delete previous character....................Ctrl-h\n"
           "Delete text up to cursor.....................Ctrl-u\n"
           "Delete text after cursor.....................Ctrl-k\n"
           "Move to beginning of line....................Ctrl-a\n"
           "Move to end of line..........................Ctrl-e\n"
           "Get prior command from history...............Ctrl-p\n"
           "Get next command from history................Ctrl-n\n"
           "Search command history in reverse............Ctrl-r\n"
           "Move cursor left.............................Ctrl-b\n"
           "Move cursor right............................Ctrl-f\n"
           "Move back one word...........................Esc-b\n"
           "Move forward one word........................Esc-f\n"
           "Convert rest of word to uppercase............Esc-c\n"
           "Convert rest of word to lowercase............Esc-l\n"
           "Delete remainder of word.....................Esc-d\n"
           "Recall last element of previous command......Esc-.\n"
           "Delete word up to cursor.....................Ctrl-w\n"
           "Transpose current and previous character.....Ctrl-t\n"
           "Enter command and return to root prompt.......Ctrl-z\n"
           "Refresh input line...........................Ctrl-l";
  }
  if (id == help_global || id == help_globals) {
    return "back            - Go back a level in the command tree\n"
           "exit            - Exit to intermediate mode - use option all to "
           "exit to root prompt\n"
           "help            - Display help\n"
           "ping            - Verify the reachability of a remote host";
  }
  return "?\n"
         "Lists all commands in the current context.\n\n"
         "string?\n"
         "Lists all commands available in the current context that start with "
         "the string.\n\n"
         "command ?\n"
         "Displays command syntax and associated keywords.\n\n"
         "string<Tab> or string<Space>\n"
         "Completes a partial command name or lists matching commands.";
}

std::string md_context_marker(const CliSession &session) {
  const auto path = session_path(session, CliEngine::md);
  const auto location =
      path.empty() ? std::string{"/"} : std::string{"/"} + std::string{path};
  const auto changed = session.candidate_dirty ? "*" : "";
  const auto stale = session.candidate_outdated ? "!" : "";
  switch (session.md_workflow) {
  case MdCliWorkflow::operational:
    return "[" + location + "]";
  case MdCliWorkflow::implicit_exclusive:
    return std::string{stale} + changed + "[ex:" + location + "]";
  case MdCliWorkflow::explicit_exclusive:
    return std::string{stale} + changed + "(ex)[" + location + "]";
  case MdCliWorkflow::implicit_global:
    return std::string{stale} + changed + "[gl:" + location + "]";
  case MdCliWorkflow::explicit_global:
    return std::string{stale} + changed + "(gl)[" + location + "]";
  case MdCliWorkflow::implicit_private:
    return std::string{stale} + changed + "[pr:" + location + "]";
  case MdCliWorkflow::explicit_private:
    return std::string{stale} + changed + "(pr)[" + location + "]";
  case MdCliWorkflow::implicit_read_only:
    return std::string{stale} + changed + "[ro:" + location + "]";
  case MdCliWorkflow::explicit_read_only:
    return std::string{stale} + changed + "(ro)[" + location + "]";
  }
  return "[" + location + "]";
}

// Workflow helpers keep prompt, entry and exit semantics synchronized. The
// abbreviations are the documented MD-CLI prompt regions and are not router
// identity or application modes.
bool implicit_workflow(MdCliWorkflow workflow) noexcept {
  return workflow == MdCliWorkflow::implicit_exclusive ||
         workflow == MdCliWorkflow::implicit_global ||
         workflow == MdCliWorkflow::implicit_private ||
         workflow == MdCliWorkflow::implicit_read_only;
}

std::string_view workflow_name(MdCliWorkflow workflow) noexcept {
  switch (workflow) {
  case MdCliWorkflow::implicit_exclusive:
  case MdCliWorkflow::explicit_exclusive:
    return "exclusive";
  case MdCliWorkflow::implicit_global:
  case MdCliWorkflow::explicit_global:
    return "global";
  case MdCliWorkflow::implicit_private:
  case MdCliWorkflow::explicit_private:
    return "private";
  case MdCliWorkflow::implicit_read_only:
  case MdCliWorkflow::explicit_read_only:
    return "read-only";
  case MdCliWorkflow::operational:
    return "operational";
  }
  return "operational";
}

bool private_workflow(MdCliWorkflow workflow) noexcept {
  return workflow == MdCliWorkflow::implicit_private ||
         workflow == MdCliWorkflow::explicit_private;
}

bool exclusive_workflow(MdCliWorkflow workflow) noexcept {
  return workflow == MdCliWorkflow::implicit_exclusive ||
         workflow == MdCliWorkflow::explicit_exclusive;
}

bool global_workflow(MdCliWorkflow workflow) noexcept {
  return workflow == MdCliWorkflow::implicit_global ||
         workflow == MdCliWorkflow::explicit_global;
}

std::string entry_message(MdCliWorkflow workflow) {
  if (global_workflow(workflow))
    return "INFO: CLI #2054: Entering global configuration mode";
  if (private_workflow(workflow))
    return "INFO: CLI #2070: Entering private configuration mode\n"
           "INFO: CLI #2061: Uncommitted changes are discarded on "
           "configuration mode exit";
  if (workflow == MdCliWorkflow::implicit_read_only ||
      workflow == MdCliWorkflow::explicit_read_only)
    return "INFO: CLI #2066: Entering read-only configuration mode";
  return "INFO: CLI #2060: Entering exclusive configuration mode\n"
         "INFO: CLI #2061: Uncommitted changes are discarded on "
         "configuration mode exit";
}

std::string exit_message(MdCliWorkflow workflow, bool dirty) {
  if (global_workflow(workflow)) {
    auto output = std::string{"INFO: CLI #2056: Exiting global configuration mode"};
    if (dirty)
      output += "\nINFO: CLI #2057: Uncommitted changes are kept in the "
                "candidate configuration";
    return output;
  }
  if (private_workflow(workflow))
    return "INFO: CLI #2074: Exiting private configuration mode";
  if (workflow == MdCliWorkflow::implicit_read_only ||
      workflow == MdCliWorkflow::explicit_read_only)
    return "INFO: CLI #2067: Exiting read-only configuration mode";
  return "INFO: CLI #2064: Exiting exclusive configuration mode";
}

std::string discard_prompt(MdCliWorkflow workflow) {
  const auto private_mode = private_workflow(workflow);
  return std::string{"INFO: CLI #"} + (private_mode ? "2071" : "2063") +
         ": Uncommitted changes are present in the candidate configuration.\n"
         "Exiting " + std::string{workflow_name(workflow)} +
         " configuration mode will discard those changes.\n\n"
         "Discard uncommitted changes? [y,n]";
}

std::string discard_canceled(MdCliWorkflow workflow) {
  return private_workflow(workflow)
             ? "INFO: CLI #2072: Exit private configuration mode canceled"
             : "INFO: CLI #2065: Exit exclusive configuration mode canceled";
}

std::string discard_confirmed(MdCliWorkflow workflow) {
  return private_workflow(workflow)
             ? "WARNING: CLI #2073: Exiting private configuration mode - "
               "uncommitted changes are discarded"
             : "WARNING: CLI #2062: Exiting exclusive configuration mode - "
               "uncommitted changes are discarded";
}

std::string classic_context_marker(std::string_view path) {
  // Classic prompts show context node names but omit list keys. The mappings
  // below follow the documented reduced prompt spellings for the implemented
  // tree and do not affect command parsing.
  if (path.empty())
    return {};
  std::istringstream tokens(std::string{path});
  std::string token;
  std::string result;
  bool skip_key = false;
  while (tokens >> token) {
    if (skip_key) {
      skip_key = false;
      continue;
    }
    if (token == "configure")
      token = "config";
    else if (token == "interface") {
      token = "if";
      skip_key = true;
    } else if (token == "card" || token == "mda" || token == "port" ||
               token == "ospf" || token == "ospf3" || token == "area") {
      // Classic prompts name a keyed configuration node but do not append its
      // selected key as another `>` component. OSPF instance and area keys
      // follow the same reduced prompt convention as interface, card and port
      // list keys; command parsing still retains their complete saved path.
      skip_key = true;
    }
    result += '>' + token;
  }
  return result;
}

} // namespace

std::string resolve_session_input(const CliSession &session,
                                  std::string_view input) {
  // effective_input is deliberately kept private because it assumes the
  // fixed-size, NUL-terminated path invariant owned by CliSession. This
  // wrapper exposes only the resulting value and cannot leak path storage.
  return effective_input(session, input);
}

bool enter_classic_context(CliSession &session,
                           std::string_view path) noexcept {
  if (session.engine != CliEngine::classic ||
      path.size() >= session.classic_path.size())
    return false;
  move_session_path(session, path);
  return true;
}

bool enter_md_context(CliSession &session, std::string_view path) noexcept {
  // Keep this mutation next to the private path primitives so every caller
  // preserves exit's reversible-origin invariant. Reimplementing it in the
  // runtime facade would update only md_path and make `exit` jump to stale
  // storage after entering a presence container such as BOF DHCP.
  if (session.engine != CliEngine::md || path.size() >= session.md_path.size())
    return false;
  move_session_path(session, path);
  return true;
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
  if (session.engine == CliEngine::classic) {
    return std::string{"\n"} + (session.classic_unsaved ? "*" : "") +
           "A:" + std::string{name} +
           classic_context_marker(session_path(session, CliEngine::classic)) +
           "# ";
  }
  return "\n" + md_context_marker(session) + "\nA:admin@" + std::string{name} +
         "# ";
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
  const bool absolute_prefix =
      input.front() == '/' ||
      (session.engine == CliEngine::classic && input.front() == '\\');
  if (absolute_prefix && input.size() > 1U &&
      std::string_view{" \r\n\t"}.find(input[1]) != std::string_view::npos) {
    // Both absolute-path spellings require the command immediately after the
    // slash. Nokia documents an intervening space as a syntax error.
    output = session.engine == CliEngine::classic
                 ? "Error: Bad command."
                 : "MINOR: MGMT_CORE #2201: Unknown element";
    return output + cli_detail::prompt(state.configuration.running, session);
  }

  // Exclusive configuration exit is a two-line interaction in SR OS. The
  // pending answer belongs to the router session so switching renderers cannot
  // lose or auto-accept a destructive confirmation.
  if (session.md_exit_confirmation) {
    const auto source = session.md_workflow;
    const auto target = session.md_confirmation_target;
    session.md_exit_confirmation = false;
    session.md_confirmation_target = MdCliWorkflow::operational;
    if (input == "n" || input == "N") {
      output = cli_detail::discard_canceled(source);
    } else if (input == "y" || input == "Y") {
      state.configuration.candidate = state.configuration.running;
      session.candidate_dirty = false;
      session.candidate_outdated = false;
      session.md_workflow = target;
      output = cli_detail::discard_confirmed(source);
      if (target == MdCliWorkflow::operational)
        cli_detail::set_session_path(session, CliEngine::md, {});
      else
        output += '\n' + cli_detail::entry_message(target);
    } else {
      session.md_exit_confirmation = true;
      session.md_confirmation_target = target;
      output = "Discard uncommitted changes? [y,n]";
    }
    return output + cli_detail::prompt(state.configuration.running, session);
  }

  if (input.starts_with("//") && input.size() > 2U) {
    // Nokia executes the remainder as an absolute command in the other engine,
    // then restores both the originating engine and its saved context. The
    // nested call uses the same session owner and therefore preserves candidate
    // state without any cross-router or UI shortcut.
    const auto foreign_input = cli_detail::trim(input.substr(2U));
    if (!foreign_input.empty()) {
      const auto source_engine = session.engine;
      const auto target_engine =
          source_engine == CliEngine::md ? CliEngine::classic : CliEngine::md;
      session.engine = target_engine;
      const auto entering =
          target_engine == CliEngine::md
              ? "INFO: CLI #2052: Switching to the MD-CLI engine"
              : "INFO: CLI #2051: Switching to the classic CLI engine";
      const auto target_prompt =
          cli_detail::prompt(state.configuration.running, session);
      auto foreign_output =
          execute_cli(state, session, "/" + foreign_input, ping);
      const auto returned_prompt =
          cli_detail::prompt(state.configuration.running, session);
      if (foreign_output.ends_with(returned_prompt))
        foreign_output.resize(foreign_output.size() - returned_prompt.size());
      session.engine = source_engine;
      const auto leaving =
          source_engine == CliEngine::md
              ? "INFO: CLI #2052: Switching to the MD-CLI engine"
              : "INFO: CLI #2051: Switching to the classic CLI engine";
      const auto visible_target_prompt = target_prompt.starts_with('\n')
                                             ? target_prompt.substr(1U)
                                             : target_prompt;
      // Operational reports are free to omit a trailing line feed because an
      // ordinary command appends its prompt immediately. Inline engine
      // execution appends a second transcript record first, so normalize that
      // boundary here. Otherwise a table rule such as "====" and CLI #2052
      // become one overlong terminal row.
      if (!foreign_output.empty() && foreign_output.back() != '\n')
        foreign_output.push_back('\n');
      output = std::string{entering} + '\n' + visible_target_prompt + '/' +
               foreign_input + '\n' + foreign_output + leaving;
      return output + cli_detail::prompt(state.configuration.running, session);
    }
  }

  // Global actions are tried before contextual resolution. This permits MD
  // operational commands and configuration workflow actions from any explicit
  // context while classic relative commands still follow its saved tree.
  auto effective = input;
  auto command = cli_detail::parse_command(state, session, effective);
  if (command &&
      !cli_detail::global_action(command->spec->id, session.engine) &&
      !cli_detail::session_path(session, session.engine).empty()) {
    command.reset();
  }
  if (!command) {
    effective = cli_detail::effective_input(session, input);
    command = cli_detail::parse_command(state, session, effective);
  }

  // An exact container prefix navigates without fabricating an executable
  // command. The configuration tree does not exist in the operational
  // workflow: `configure [mode]` must first acquire a candidate datastore.
  // Reject every longer configuration prefix here as well. Previously only
  // the bare `configure` token was guarded, so a line such as
  // `configure router "Base" interface "system"` moved the prompt into a
  // configuration-looking path while the session remained operational. Every
  // following leaf was then rejected and `show router interface` remained
  // empty, which was both misleading and unlike SR OS.
  if (!command &&
      cli_detail::navigable_command_prefix(session, effective)) {
    const auto canonical =
        cli_detail::canonical_command_prefix(session, effective);
    if (!canonical.empty()) {
      if (session.engine == CliEngine::md && canonical == "edit-config") {
        // `edit-config` is a global workflow command whose required child
        // selects the candidate mode. It is not a configuration region.
        // Descendant command rows make it a grammar prefix, but treating every
        // grammar prefix as a navigable model node fabricated the impossible
        // prompt `[/edit-config]`. Keep the PWC unchanged and expose the
        // documented mode choices as the normal incomplete-command response.
        output = cli_detail::incomplete_command_help(state, session, effective);
        return output +
               cli_detail::prompt(state.configuration.running, session);
      }
      if (session.engine == CliEngine::md &&
          session.md_workflow == MdCliWorkflow::operational &&
          (canonical == "configure" ||
           std::string_view{canonical}.starts_with("configure "))) {
        output = "MINOR: CLI #2069: Operation not allowed - currently in "
                 "operational mode";
        return output +
               cli_detail::prompt(state.configuration.running, session);
      }
      if (session.engine == CliEngine::md &&
          cli_detail::implicit_workflow(session.md_workflow) &&
          canonical != "configure" &&
          !std::string_view{canonical}.starts_with("configure ")) {
        // Implicit workflow is confined to the configuration region. An
        // operational leaf may execute through an absolute path, but an
        // incomplete operational container would navigate out and is rejected.
        output = "MINOR: CLI #2069: Operation not allowed - cannot navigate "
                 "out of configuration region";
        return output +
               cli_detail::prompt(state.configuration.running, session);
      }
      cli_detail::move_session_path(session, canonical);
      return cli_detail::prompt(state.configuration.running, session);
    }
  }

  if (!command) {
    std::optional<cli_detail::ParsedCommand> forbidden_configuration;
    if (session.engine == CliEngine::md &&
        session.md_workflow == MdCliWorkflow::operational) {
      // Completion must hide candidate-only commands in operational mode, but
      // execution of a complete configuration statement produces CLI #2069.
      // Parse a copy of the session in configuration mode only to distinguish
      // that case without mutating context or candidate state.
      auto configuring_session = session;
      configuring_session.md_workflow = MdCliWorkflow::explicit_exclusive;
      forbidden_configuration =
          cli_detail::parse_command(state, configuring_session, effective);
    }
    if (forbidden_configuration && cli_detail::md_configuration_command(
                                       forbidden_configuration->spec->id)) {
      output = "MINOR: CLI #2069: Operation not allowed - currently in "
               "operational mode";
    } else if (session.engine == CliEngine::classic) {
      output = "Error: Bad command.";
    } else if (const auto help = cli_detail::incomplete_command_help(
                   state, session, effective);
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
  } else if (command->spec->id == cli_schema::CommandId::navigate_back ||
             command->spec->id == cli_schema::CommandId::navigate_back_levels ||
             command->spec->id ==
                 cli_schema::CommandId::navigate_closing_brace) {
    // A very large back value cannot create unbounded work: traversal stops as
    // soon as the bounded current path reaches the operational root.
    const auto original_path =
        std::string{cli_detail::session_path(session, session.engine)};
    std::uint32_t levels = 1;
    if (command->spec->id == cli_schema::CommandId::navigate_back_levels) {
      const auto text =
          cli_detail::argument(*command, cli_schema::TokenKind::levels);
      const auto parsed =
          text ? std::from_chars(text->data(), text->data() + text->size(),
                                 levels)
               : std::from_chars_result{};
      if (!text || parsed.ec != std::errc{} ||
          parsed.ptr != text->data() + text->size() || levels == 0) {
        output = "MINOR: MGMT_CORE #2301: Invalid element value";
        levels = 0;
      }
    }
    while (levels-- &&
           !cli_detail::session_path(session, session.engine).empty())
      cli_detail::parent_context(session);
    if (session.engine == CliEngine::md &&
        cli_detail::implicit_workflow(session.md_workflow) &&
        cli_detail::session_path(session, CliEngine::md).empty()) {
      if (session.candidate_dirty &&
          !cli_detail::global_workflow(session.md_workflow)) {
        // The navigation is not committed until the destructive confirmation
        // succeeds. Answering 'n' therefore leaves the exact prior context.
        cli_detail::set_session_path(session, CliEngine::md, original_path);
        session.md_exit_confirmation = true;
        session.md_confirmation_target = MdCliWorkflow::operational;
        output = cli_detail::discard_prompt(session.md_workflow);
      } else {
        const auto leaving = session.md_workflow;
        session.md_workflow = MdCliWorkflow::operational;
        output = cli_detail::exit_message(leaving, false);
      }
    }
  } else if (command->spec->id == cli_schema::CommandId::navigate_top) {
    // top retains the top-level branch. In implicit configuration workflow
    // that branch is always /configure; explicit workflow may also use show.
    const auto path = cli_detail::session_path(session, session.engine);
    const auto separator = path.find(' ');
    cli_detail::move_session_path(session, separator == std::string_view::npos
                                               ? path
                                               : path.substr(0, separator));
  } else if (command->spec->id == cli_schema::CommandId::navigate_exit) {
    const bool leave_implicit =
        session.engine == CliEngine::md &&
        cli_detail::implicit_workflow(session.md_workflow) &&
        cli_detail::session_path(session, CliEngine::md) == "configure";
    if (session.engine == CliEngine::classic) {
      // Classic exit and back both move to the next higher command context.
      // MD exit is different and restores the previous working context.
      cli_detail::parent_context(session);
    } else if (!leave_implicit) {
      cli_detail::previous_context(session);
    } else if (session.candidate_dirty &&
               !cli_detail::global_workflow(session.md_workflow)) {
      session.md_exit_confirmation = true;
      session.md_confirmation_target = MdCliWorkflow::operational;
      output = cli_detail::discard_prompt(session.md_workflow);
    } else {
      const auto leaving = session.md_workflow;
      const auto dirty = session.candidate_dirty;
      session.md_workflow = MdCliWorkflow::operational;
      cli_detail::set_session_path(session, CliEngine::md, {});
      output = cli_detail::exit_message(leaving, dirty);
    }
  } else if (command->spec->id == cli_schema::CommandId::navigate_exit_all ||
             command->spec->id == cli_schema::CommandId::navigate_root ||
             command->spec->id ==
                 cli_schema::CommandId::navigate_classic_root) {
    const bool leave_implicit =
        session.engine == CliEngine::md &&
        cli_detail::implicit_workflow(session.md_workflow);
    if (leave_implicit && session.candidate_dirty &&
        !cli_detail::global_workflow(session.md_workflow)) {
      session.md_exit_confirmation = true;
      session.md_confirmation_target = MdCliWorkflow::operational;
      output = cli_detail::discard_prompt(session.md_workflow);
    } else {
      cli_detail::move_session_path(session, {});
      if (leave_implicit) {
        const auto leaving = session.md_workflow;
        const auto dirty = session.candidate_dirty;
        session.md_workflow = MdCliWorkflow::operational;
        output = cli_detail::exit_message(leaving, dirty);
      }
    }
  } else if (command->spec->id == cli_schema::CommandId::md_quit_config) {
    if (session.candidate_dirty &&
        !cli_detail::global_workflow(session.md_workflow)) {
      session.md_exit_confirmation = true;
      session.md_confirmation_target = MdCliWorkflow::operational;
      output = cli_detail::discard_prompt(session.md_workflow);
    } else {
      const auto leaving = session.md_workflow;
      const auto dirty = session.candidate_dirty;
      session.md_workflow = MdCliWorkflow::operational;
      cli_detail::move_session_path(session, {});
      output = cli_detail::exit_message(leaving, dirty);
    }
  } else if (command->spec->id == cli_schema::CommandId::switch_engine) {
    session.engine =
        session.engine == CliEngine::md ? CliEngine::classic : CliEngine::md;
    output = session.engine == CliEngine::md
                 ? "INFO: CLI #2052: Switching to the MD-CLI engine"
                 : "INFO: CLI #2051: Switching to the classic CLI engine";
  } else if ([&] {
               using enum cli_schema::CommandId;
               const auto id = command->spec->id;
               return id == md_configure_exclusive ||
                      id == md_configure_global ||
                      id == md_configure_private ||
                      id == md_configure_read_only ||
                      id == md_edit_config_exclusive ||
                      id == md_edit_config_global ||
                      id == md_edit_config_private ||
                      id == md_edit_config_read_only;
             }()) {
    using enum cli_schema::CommandId;
    const auto id = command->spec->id;
    const bool implicit = id == md_configure_exclusive ||
                          id == md_configure_global ||
                          id == md_configure_private ||
                          id == md_configure_read_only;
    const bool implicit_to_explicit =
        (session.md_workflow == MdCliWorkflow::implicit_exclusive &&
         id == md_edit_config_exclusive) ||
        (session.md_workflow == MdCliWorkflow::implicit_global &&
         id == md_edit_config_global) ||
        (session.md_workflow == MdCliWorkflow::implicit_private &&
         id == md_edit_config_private) ||
        (session.md_workflow == MdCliWorkflow::implicit_read_only &&
         id == md_edit_config_read_only);
    MdCliWorkflow target{};
    if (id == md_configure_exclusive || id == md_edit_config_exclusive)
      target = implicit ? MdCliWorkflow::implicit_exclusive
                        : MdCliWorkflow::explicit_exclusive;
    else if (id == md_configure_global || id == md_edit_config_global)
      target = implicit ? MdCliWorkflow::implicit_global
                        : MdCliWorkflow::explicit_global;
    else if (id == md_configure_private || id == md_edit_config_private)
      target = implicit ? MdCliWorkflow::implicit_private
                        : MdCliWorkflow::explicit_private;
    else
      target = implicit ? MdCliWorkflow::implicit_read_only
                        : MdCliWorkflow::explicit_read_only;
    if (implicit_to_explicit)
      session.md_workflow = target;
    if (implicit_to_explicit)
      return cli_detail::prompt(state.configuration.running, session);
    if (session.md_workflow != MdCliWorkflow::operational) {
      const auto source = session.md_workflow;
      // Nokia permits in-place transitions only among exclusive, global and
      // read-only global-candidate modes. Private candidate identity cannot be
      // converted, and configure is an entry workflow rather than transition.
      if (implicit || cli_detail::private_workflow(source) ||
          cli_detail::private_workflow(target)) {
        output = "MINOR: CLI #2069: Operation not allowed";
      } else if (cli_detail::exclusive_workflow(source) &&
                 session.candidate_dirty) {
        session.md_exit_confirmation = true;
        session.md_confirmation_target = target;
        output = cli_detail::discard_prompt(source);
      } else {
        session.md_workflow = target;
        output = cli_detail::exit_message(source, session.candidate_dirty) +
                 '\n' + cli_detail::entry_message(target);
      }
      return output + cli_detail::prompt(state.configuration.running, session);
    }
    session.md_workflow = target;
    if (implicit)
      cli_detail::set_session_path(session, CliEngine::md, "configure");
    state.configuration.candidate = state.configuration.running;
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    output = cli_detail::entry_message(session.md_workflow);
  } else if (command->spec->id == cli_schema::CommandId::help ||
             command->spec->id == cli_schema::CommandId::help_edit ||
             command->spec->id == cli_schema::CommandId::help_global ||
             command->spec->id == cli_schema::CommandId::help_globals ||
             command->spec->id ==
                 cli_schema::CommandId::help_special_characters) {
    output = cli_detail::classic_help(command->spec->id);
  } else if (session.engine == CliEngine::md &&
             session.md_workflow == MdCliWorkflow::operational &&
             cli_detail::md_configuration_command(command->spec->id)) {
    output = "MINOR: CLI #2069: Operation not allowed - currently in "
             "operational mode";
  } else if (const auto common =
                 cli_detail::operational_command(state, *command, ping)) {
    output = *common;
  } else if (session.engine == CliEngine::md) {
    output = cli_detail::execute_md(state.configuration, session, *command);
  } else {
    output =
        cli_detail::execute_classic(state.configuration, session, *command);
    // In classic CLI, selecting an OSPF instance is both an immediate
    // configuration operation and a context transition. The schema therefore
    // contains an executable row for the exact same token sequence that is
    // also the parent of area and interface commands. Prefix-only navigation
    // cannot handle this overlap because the complete command wins parsing.
    //
    // Move only after successful execution. This preserves the current prompt
    // when instance creation or validation fails and prevents a context that
    // has no corresponding running configuration from being fabricated.
    using enum cli_schema::CommandId;
    if (output.empty() &&
        (command->spec->id == classic_ospf_create ||
         command->spec->id == classic_ospf3_create)) {
      cli_detail::move_session_path(session, effective);
    } else if (output.empty() &&
               (command->spec->id == classic_ospf_create_router_id ||
                command->spec->id == classic_ospf3_create_router_id)) {
      // The optional router ID is a creation argument, not a context key.
      // Strip it from the canonical command before storing the classic PWC.
      const auto separator = effective.find_last_of(' ');
      if (separator != std::string::npos)
        cli_detail::move_session_path(session, effective.substr(0, separator));
    }
  }
  return output + cli_detail::prompt(state.configuration.running, session);
}

std::string complete_cli(const DeviceState &state, const CliSession &session,
                         const std::string &raw, CliCompletionTrigger trigger) {
  // Completion reads schema and device candidates but cannot execute or mutate.
  // Only leading whitespace is irrelevant here. A trailing separator selects
  // the next grammar position and therefore must survive into the parser.
  std::string_view input{raw};
  while (!input.empty() && std::string_view{" \r\n\t"}.find(input.front()) !=
                               std::string_view::npos)
    input.remove_prefix(1);
  const auto effective = cli_detail::effective_input(session, input);
  const auto completed =
      cli_detail::complete_command(state, session, effective, trigger);
  if (completed.empty() ||
      cli_detail::session_path(session, session.engine).empty() ||
      completed.find('\n') != std::string::npos)
    return completed;
  const auto prefix =
      std::string{cli_detail::session_path(session, session.engine)} + ' ';
  return completed.starts_with(prefix) ? completed.substr(prefix.size())
                                       : completed;
}

std::string cli_prompt(const DeviceState &state, const CliSession &session) {
  // Expose prompt rendering without exposing cli_detail to runtime consumers.
  return cli_detail::prompt(state.configuration.running, session);
}

} // namespace router
