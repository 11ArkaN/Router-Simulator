#pragma once

// Generated release grammar. Execution and completion consume the same rows,
// which prevents a handwritten command catalog from drifting from sources.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace router::cli_schema {

enum class CommandId : std::uint16_t {
  switch_engine,
  help,
  help_edit,
  help_global,
  help_globals,
  help_special_characters,
  navigate_back,
  navigate_back_levels,
  navigate_closing_brace,
  navigate_exit,
  navigate_exit_all,
  navigate_top,
  navigate_root,
  navigate_classic_root,
  md_quit_config,
  md_configure_exclusive,
  md_edit_config_exclusive,
  show_system_information,
  show_system_alarms,
  show_card,
  show_mda,
  show_port,
  show_router_interface,
  show_router_route_table,
  show_router_fib,
  show_router_arp,
  ping,
  ping_count,
  ping_size,
  ping_do_not_fragment,
  ping_size_do_not_fragment,
  ping_count_size,
  ping_count_do_not_fragment,
  ping_count_size_do_not_fragment,
  configure_card_type,
  configure_mda_type,
  md_card_enable,
  md_card_disable,
  md_mda_enable,
  md_mda_disable,
  configure_system_name,
  md_port_enable,
  md_port_disable,
  md_port_description,
  md_port_mtu,
  md_interface_enable,
  md_interface_disable,
  md_interface_port,
  md_interface_ipv4_primary,
  md_static_route,
  md_delete_card,
  md_delete_mda,
  md_delete_port_description,
  md_delete_static_route,
  md_compare,
  md_commit,
  md_discard,
  classic_remove_card_type,
  classic_remove_mda_type,
  classic_card_shutdown,
  classic_card_no_shutdown,
  classic_mda_shutdown,
  classic_mda_no_shutdown,
  classic_port_shutdown,
  classic_port_no_shutdown,
  classic_port_description,
  classic_remove_port_description,
  classic_port_mtu,
  classic_interface_shutdown,
  classic_interface_no_shutdown,
  classic_interface_port,
  classic_interface_address,
  classic_static_route,
  classic_remove_static_route
};

enum class TokenKind : std::uint8_t {
  literal,
  card_slot,
  mda_slot,
  card_type,
  mda_type,
  port_id,
  interface_name,
  ipv4,
  ipv4_key,
  ipv4_prefix,
  prefix_length,
  count,
  size,
  mtu,
  levels,
  system_name,
  description
};

struct TokenSpec {
  TokenKind kind{TokenKind::literal};
  std::string_view display{};
  std::string_view description{};
};

inline constexpr std::size_t maximum_tokens = 11;

struct CommandSpec {
  CommandId id{};
  std::uint8_t engine_mask{};
  std::uint8_t token_count{};
  std::array<TokenSpec, maximum_tokens> tokens{};
  std::string_view source_id{};
};

inline constexpr std::array<CommandSpec, 74> commands{{
    {CommandId::switch_engine, 3, 1, {{{TokenKind::literal, "//", "Switch to the other CLI engine"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::help, 2, 1, {{{TokenKind::literal, "help", "Display help for the classic CLI"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.classic_cli.navigation"},
    {CommandId::help_edit, 2, 2, {{{TokenKind::literal, "help", "Display help for the classic CLI"}, {TokenKind::literal, "edit", "Display help for line-editing keys"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.classic_cli.navigation"},
    {CommandId::help_global, 2, 2, {{{TokenKind::literal, "help", "Display help for the classic CLI"}, {TokenKind::literal, "global", "Display help for global commands"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.classic_cli.navigation"},
    {CommandId::help_globals, 2, 2, {{{TokenKind::literal, "help", "Display help for the classic CLI"}, {TokenKind::literal, "globals", "Display help for global commands"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.classic_cli.navigation"},
    {CommandId::help_special_characters, 2, 2, {{{TokenKind::literal, "help", "Display help for the classic CLI"}, {TokenKind::literal, "special-characters", "Display help for special CLI characters"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.classic_cli.navigation"},
    {CommandId::navigate_back, 3, 1, {{{TokenKind::literal, "back", "Navigate to a parent context"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::navigate_back_levels, 1, 2, {{{TokenKind::literal, "back", "Navigate to a parent context"}, {TokenKind::levels, "<number>", "Number of parent levels"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::navigate_closing_brace, 1, 1, {{{TokenKind::literal, "}", "Navigate to the parent MD-CLI context"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::navigate_exit, 3, 1, {{{TokenKind::literal, "exit", "Return to a previous or parent context"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::navigate_exit_all, 3, 2, {{{TokenKind::literal, "exit", "Return to a previous or parent context"}, {TokenKind::literal, "all", "Navigate to the operational root"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::navigate_top, 1, 1, {{{TokenKind::literal, "top", "Navigate to the top context"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::navigate_root, 3, 1, {{{TokenKind::literal, "/", "Navigate to the root context"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::navigate_classic_root, 2, 1, {{{TokenKind::literal, "\\", "Navigate to the classic operational root"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.classic_cli.navigation"},
    {CommandId::md_quit_config, 1, 1, {{{TokenKind::literal, "quit-config", "Exit explicit candidate configuration mode"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.configuration_workflow"},
    {CommandId::md_configure_exclusive, 1, 2, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "exclusive", "Use exclusive candidate configuration mode"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.configuration_workflow"},
    {CommandId::md_edit_config_exclusive, 1, 2, {{{TokenKind::literal, "edit-config", "Enter the explicit configuration workflow"}, {TokenKind::literal, "exclusive", "Use exclusive candidate configuration mode"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.configuration_workflow"},
    {CommandId::show_system_information, 3, 3, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "system", "Configure or display system information"}, {TokenKind::literal, "information", "Display system information"}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.system_information"},
    {CommandId::show_system_alarms, 3, 3, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "system", "Configure or display system information"}, {TokenKind::literal, "alarms", "Display facility alarms"}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.system_alarms"},
    {CommandId::show_card, 3, 2, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "card", "Configure or display card information"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.card"},
    {CommandId::show_mda, 3, 2, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.mda"},
    {CommandId::show_port, 3, 2, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.port"},
    {CommandId::show_router_interface, 3, 3, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.router_interface"},
    {CommandId::show_router_route_table, 3, 3, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "route-table", "Display the route table"}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.route_table"},
    {CommandId::show_router_fib, 3, 4, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "fib", "Display forwarding information base entries"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.fib"},
    {CommandId::show_router_arp, 3, 3, {{{TokenKind::literal, "show", "Display operational information"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "arp", "Display the ARP table"}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.show.arp"},
    {CommandId::ping, 3, 2, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_count, 3, 4, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "count", "Configure the number of echo requests"}, {TokenKind::count, "<number>", "Number of echo requests"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_size, 3, 4, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "size", "Configure the ICMP data field size"}, {TokenKind::size, "<bytes>", "ICMP data field size in bytes"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_do_not_fragment, 3, 3, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "do-not-fragment", "Set the IPv4 Don't Fragment bit"}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_size_do_not_fragment, 3, 5, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "size", "Configure the ICMP data field size"}, {TokenKind::size, "<bytes>", "ICMP data field size in bytes"}, {TokenKind::literal, "do-not-fragment", "Set the IPv4 Don't Fragment bit"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_count_size, 3, 6, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "count", "Configure the number of echo requests"}, {TokenKind::count, "<number>", "Number of echo requests"}, {TokenKind::literal, "size", "Configure the ICMP data field size"}, {TokenKind::size, "<bytes>", "ICMP data field size in bytes"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_count_do_not_fragment, 3, 5, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "count", "Configure the number of echo requests"}, {TokenKind::count, "<number>", "Number of echo requests"}, {TokenKind::literal, "do-not-fragment", "Set the IPv4 Don't Fragment bit"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_count_size_do_not_fragment, 3, 7, {{{TokenKind::literal, "ping", "Verify reachability of a remote host"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "count", "Configure the number of echo requests"}, {TokenKind::count, "<number>", "Number of echo requests"}, {TokenKind::literal, "size", "Configure the ICMP data field size"}, {TokenKind::size, "<bytes>", "ICMP data field size in bytes"}, {TokenKind::literal, "do-not-fragment", "Set the IPv4 Don't Fragment bit"}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::configure_card_type, 3, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "card-type", "Configure the card type"}, {TokenKind::card_type, "<card-type>", "Card type"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::configure_mda_type, 3, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {TokenKind::mda_slot, "<mda-number>", "MDA slot number"}, {TokenKind::literal, "mda-type", "Configure the MDA type"}, {TokenKind::mda_type, "<mda-type>", "MDA type"}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_card_enable, 1, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "enable", "Set the administrative state to enabled"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_card_disable, 1, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "disable", "Set the administrative state to disabled"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_mda_enable, 1, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {TokenKind::mda_slot, "<mda-number>", "MDA slot number"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "enable", "Set the administrative state to enabled"}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_mda_disable, 1, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {TokenKind::mda_slot, "<mda-number>", "MDA slot number"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "disable", "Set the administrative state to disabled"}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::configure_system_name, 3, 4, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "system", "Configure or display system information"}, {TokenKind::literal, "name", "Configure the system name"}, {TokenKind::system_name, "<system-name>", "System name"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.system.name"},
    {CommandId::md_port_enable, 1, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "enable", "Set the administrative state to enabled"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_port_disable, 1, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "disable", "Set the administrative state to disabled"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_port_description, 1, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "description", "Configure descriptive text"}, {TokenKind::description, "<description>", "Description text"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.description"},
    {CommandId::md_port_mtu, 1, 6, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "ethernet", "Configure Ethernet parameters"}, {TokenKind::literal, "mtu", "Configure Ethernet MTU"}, {TokenKind::mtu, "<bytes>", "Ethernet MTU in bytes"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_interface_enable, 1, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "\"Base\"", "Base router instance"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "enable", "Set the administrative state to enabled"}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_interface_disable, 1, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "\"Base\"", "Base router instance"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "admin-state", "Configure administrative state"}, {TokenKind::literal, "disable", "Set the administrative state to disabled"}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_interface_port, 1, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "\"Base\"", "Base router instance"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {}, {}, {}, {}}}, "nokia.sros.26_7.router_interface.configuration"},
    {CommandId::md_interface_ipv4_primary, 1, 11, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "\"Base\"", "Base router instance"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "ipv4", "Configure IPv4 parameters"}, {TokenKind::literal, "primary", "Configure the primary IPv4 address"}, {TokenKind::literal, "address", "Configure an IP address"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {TokenKind::literal, "prefix-length", "Configure the IPv4 prefix length"}, {TokenKind::prefix_length, "<prefix-length>", "IPv4 prefix length"}}}, "nokia.sros.26_7.router_interface.configuration"},
    {CommandId::md_static_route, 1, 10, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "\"Base\"", "Base router instance"}, {TokenKind::literal, "static-routes", "Configure static routes"}, {TokenKind::literal, "route", "Configure a static route entry"}, {TokenKind::ipv4_prefix, "<ip-prefix/prefix-length>", "IPv4 prefix and prefix length"}, {TokenKind::literal, "route-type", "Configure the route type"}, {TokenKind::literal, "unicast", "Select the unicast route type"}, {TokenKind::literal, "next-hop", "Configure a route next hop"}, {TokenKind::ipv4_key, "\"<ip-address>\"", "Quoted IPv4 next-hop key"}, {}}}, "nokia.sros.26_7.static_route.configuration"},
    {CommandId::md_delete_card, 1, 3, {{{TokenKind::literal, "delete", "Delete a candidate configuration element"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_delete_mda, 1, 5, {{{TokenKind::literal, "delete", "Delete a candidate configuration element"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {TokenKind::mda_slot, "<mda-number>", "MDA slot number"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_delete_port_description, 1, 4, {{{TokenKind::literal, "delete", "Delete a candidate configuration element"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "description", "Configure descriptive text"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.description"},
    {CommandId::md_delete_static_route, 1, 8, {{{TokenKind::literal, "delete", "Delete a candidate configuration element"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "\"Base\"", "Base router instance"}, {TokenKind::literal, "static-routes", "Configure static routes"}, {TokenKind::literal, "route", "Configure a static route entry"}, {TokenKind::ipv4_prefix, "<ip-prefix/prefix-length>", "IPv4 prefix and prefix length"}, {TokenKind::literal, "route-type", "Configure the route type"}, {TokenKind::literal, "unicast", "Select the unicast route type"}, {}, {}, {}}}, "nokia.sros.26_7.static_route.configuration"},
    {CommandId::md_compare, 1, 1, {{{TokenKind::literal, "compare", "Display candidate configuration changes"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::md_commit, 1, 1, {{{TokenKind::literal, "commit", "Commit candidate configuration changes"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::md_discard, 1, 1, {{{TokenKind::literal, "discard", "Discard candidate configuration changes"}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::classic_remove_card_type, 2, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "card-type", "Configure the card type"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_remove_mda_type, 2, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {TokenKind::mda_slot, "<mda-number>", "MDA slot number"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "mda-type", "Configure the MDA type"}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_card_shutdown, 2, 4, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_card_no_shutdown, 2, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_mda_shutdown, 2, 6, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {TokenKind::mda_slot, "<mda-number>", "MDA slot number"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_mda_no_shutdown, 2, 7, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "card", "Configure or display card information"}, {TokenKind::card_slot, "<slot-number>", "Card slot number"}, {TokenKind::literal, "mda", "Configure or display MDA information"}, {TokenKind::mda_slot, "<mda-number>", "MDA slot number"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_port_shutdown, 2, 4, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_port_no_shutdown, 2, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_port_description, 2, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "description", "Configure descriptive text"}, {TokenKind::description, "<description>", "Description text"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.description"},
    {CommandId::classic_remove_port_description, 2, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "description", "Configure descriptive text"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.description"},
    {CommandId::classic_port_mtu, 2, 6, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {TokenKind::literal, "ethernet", "Configure Ethernet parameters"}, {TokenKind::literal, "mtu", "Configure Ethernet MTU"}, {TokenKind::mtu, "<bytes>", "Ethernet MTU in bytes"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_interface_shutdown, 2, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_interface_no_shutdown, 2, 6, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "shutdown", "Administratively disable an object"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_interface_port, 2, 6, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "port", "Configure or display physical ports"}, {TokenKind::port_id, "<port-id>", "Physical port identifier"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.router_interface.configuration"},
    {CommandId::classic_interface_address, 2, 6, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "interface", "Configure or display router interfaces"}, {TokenKind::interface_name, "<interface-name>", "Router interface name"}, {TokenKind::literal, "address", "Configure an IP address"}, {TokenKind::ipv4_prefix, "<ip-prefix/prefix-length>", "IPv4 prefix and prefix length"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.router_interface.configuration"},
    {CommandId::classic_static_route, 2, 6, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "static-route-entry", "Configure a classic static route entry"}, {TokenKind::ipv4_prefix, "<ip-prefix/prefix-length>", "IPv4 prefix and prefix length"}, {TokenKind::literal, "next-hop", "Configure a route next hop"}, {TokenKind::ipv4, "<ip-address>", "IPv4 address in dotted-decimal notation"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.static_route.configuration"},
    {CommandId::classic_remove_static_route, 2, 5, {{{TokenKind::literal, "configure", "Enter or address the configuration branch"}, {TokenKind::literal, "router", "Configure or display router information"}, {TokenKind::literal, "no", "Remove configuration or negate a command"}, {TokenKind::literal, "static-route-entry", "Configure a classic static route entry"}, {TokenKind::ipv4_prefix, "<ip-prefix/prefix-length>", "IPv4 prefix and prefix length"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.static_route.configuration"}
}};

}  // namespace router::cli_schema
