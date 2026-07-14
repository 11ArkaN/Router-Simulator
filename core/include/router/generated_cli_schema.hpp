#pragma once

// Generated from the release-pinned CLI grammar. The runtime matches token
// descriptors and never carries a second handwritten list of command lines.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace router::cli_schema {

enum class CommandId : std::uint16_t {
  switch_engine,
  help,
  help_question,
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
  configure_card_type,
  configure_mda_type,
  configure_system_name,
  md_port_enable,
  md_port_disable,
  md_port_description,
  md_port_mtu,
  md_interface_enable,
  md_interface_disable,
  md_static_route,
  md_delete_card,
  md_delete_mda,
  md_compare,
  md_commit,
  md_discard,
  classic_remove_card_type,
  classic_remove_mda_type,
  classic_port_shutdown,
  classic_port_no_shutdown,
  classic_port_description,
  classic_port_mtu,
  classic_interface_shutdown,
  classic_interface_no_shutdown,
  classic_static_route
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
  ipv4_prefix,
  count,
  mtu,
  system_name,
  description
};

struct TokenSpec {
  TokenKind kind{TokenKind::literal};
  std::string_view display{};
};

inline constexpr std::size_t maximum_tokens = 8;

struct CommandSpec {
  CommandId id{};
  std::uint8_t engine_mask{};
  std::uint8_t token_count{};
  std::array<TokenSpec, maximum_tokens> tokens{};
  std::string_view source_id{};
};

inline constexpr std::array<CommandSpec, 38> commands{{
    {CommandId::switch_engine, 3, 1, {{{TokenKind::literal, "//"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::help, 3, 1, {{{TokenKind::literal, "help"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.command_completion"},
    {CommandId::help_question, 3, 1, {{{TokenKind::literal, "?"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.command_completion"},
    {CommandId::show_system_information, 3, 3, {{{TokenKind::literal, "show"}, {TokenKind::literal, "system"}, {TokenKind::literal, "information"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::show_system_alarms, 3, 3, {{{TokenKind::literal, "show"}, {TokenKind::literal, "system"}, {TokenKind::literal, "alarms"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::show_card, 3, 2, {{{TokenKind::literal, "show"}, {TokenKind::literal, "card"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::show_mda, 3, 2, {{{TokenKind::literal, "show"}, {TokenKind::literal, "mda"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::show_port, 3, 2, {{{TokenKind::literal, "show"}, {TokenKind::literal, "port"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::show_router_interface, 3, 3, {{{TokenKind::literal, "show"}, {TokenKind::literal, "router"}, {TokenKind::literal, "interface"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::show_router_route_table, 3, 3, {{{TokenKind::literal, "show"}, {TokenKind::literal, "router"}, {TokenKind::literal, "route-table"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::show_router_fib, 3, 3, {{{TokenKind::literal, "show"}, {TokenKind::literal, "router"}, {TokenKind::literal, "fib"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::show_router_arp, 3, 3, {{{TokenKind::literal, "show"}, {TokenKind::literal, "router"}, {TokenKind::literal, "arp"}, {}, {}, {}, {}, {}}}, "ietf.arp.rfc826"},
    {CommandId::ping, 3, 2, {{{TokenKind::literal, "ping"}, {TokenKind::ipv4, "<ipv4>"}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::ping_count, 3, 4, {{{TokenKind::literal, "ping"}, {TokenKind::ipv4, "<ipv4>"}, {TokenKind::literal, "count"}, {TokenKind::count, "<count>"}, {}, {}, {}, {}}}, "nokia.sros.26_7.ping"},
    {CommandId::configure_card_type, 3, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "card"}, {TokenKind::card_slot, "<card-slot>"}, {TokenKind::literal, "card-type"}, {TokenKind::card_type, "<card-type>"}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::configure_mda_type, 3, 7, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "card"}, {TokenKind::card_slot, "<card-slot>"}, {TokenKind::literal, "mda"}, {TokenKind::mda_slot, "<mda-slot>"}, {TokenKind::literal, "mda-type"}, {TokenKind::mda_type, "<mda-type>"}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::configure_system_name, 3, 4, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "system"}, {TokenKind::literal, "name"}, {TokenKind::system_name, "<system-name>"}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::md_port_enable, 1, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "admin-state"}, {TokenKind::literal, "enable"}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_port_disable, 1, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "admin-state"}, {TokenKind::literal, "disable"}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_port_description, 1, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "description"}, {TokenKind::description, "<description>"}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_port_mtu, 1, 6, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "ethernet"}, {TokenKind::literal, "mtu"}, {TokenKind::mtu, "<mtu>"}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_interface_enable, 1, 7, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "router"}, {TokenKind::literal, "\"Base\""}, {TokenKind::literal, "interface"}, {TokenKind::interface_name, "<interface-name>"}, {TokenKind::literal, "admin-state"}, {TokenKind::literal, "enable"}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_interface_disable, 1, 7, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "router"}, {TokenKind::literal, "\"Base\""}, {TokenKind::literal, "interface"}, {TokenKind::interface_name, "<interface-name>"}, {TokenKind::literal, "admin-state"}, {TokenKind::literal, "disable"}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_static_route, 1, 8, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "router"}, {TokenKind::literal, "\"Base\""}, {TokenKind::literal, "static-routes"}, {TokenKind::literal, "route"}, {TokenKind::ipv4_prefix, "<ipv4-prefix>"}, {TokenKind::literal, "next-hop"}, {TokenKind::ipv4, "<ipv4>"}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::md_delete_card, 1, 3, {{{TokenKind::literal, "delete"}, {TokenKind::literal, "card"}, {TokenKind::card_slot, "<card-slot>"}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_delete_mda, 1, 5, {{{TokenKind::literal, "delete"}, {TokenKind::literal, "card"}, {TokenKind::card_slot, "<card-slot>"}, {TokenKind::literal, "mda"}, {TokenKind::mda_slot, "<mda-slot>"}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::md_compare, 1, 1, {{{TokenKind::literal, "compare"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::md_commit, 1, 1, {{{TokenKind::literal, "commit"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::md_discard, 1, 1, {{{TokenKind::literal, "discard"}, {}, {}, {}, {}, {}, {}, {}}}, "nokia.sros.26_7.md_cli.navigation"},
    {CommandId::classic_remove_card_type, 2, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "card"}, {TokenKind::card_slot, "<card-slot>"}, {TokenKind::literal, "no"}, {TokenKind::literal, "card-type"}, {}, {}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_remove_mda_type, 2, 7, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "card"}, {TokenKind::card_slot, "<card-slot>"}, {TokenKind::literal, "mda"}, {TokenKind::mda_slot, "<mda-slot>"}, {TokenKind::literal, "no"}, {TokenKind::literal, "mda-type"}, {}}}, "nokia.sros.26_7.physical_port.provisioning"},
    {CommandId::classic_port_shutdown, 2, 4, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "shutdown"}, {}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_port_no_shutdown, 2, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "no"}, {TokenKind::literal, "shutdown"}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_port_description, 2, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "description"}, {TokenKind::description, "<description>"}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_port_mtu, 2, 6, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "port"}, {TokenKind::port_id, "<port-id>"}, {TokenKind::literal, "ethernet"}, {TokenKind::literal, "mtu"}, {TokenKind::mtu, "<mtu>"}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_interface_shutdown, 2, 5, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "router"}, {TokenKind::literal, "interface"}, {TokenKind::interface_name, "<interface-name>"}, {TokenKind::literal, "shutdown"}, {}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_interface_no_shutdown, 2, 6, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "router"}, {TokenKind::literal, "interface"}, {TokenKind::interface_name, "<interface-name>"}, {TokenKind::literal, "no"}, {TokenKind::literal, "shutdown"}, {}, {}}}, "nokia.sros.26_7.port.configuration"},
    {CommandId::classic_static_route, 2, 6, {{{TokenKind::literal, "configure"}, {TokenKind::literal, "router"}, {TokenKind::literal, "static-route-entry"}, {TokenKind::ipv4_prefix, "<ipv4-prefix>"}, {TokenKind::literal, "next-hop"}, {TokenKind::ipv4, "<ipv4>"}, {}, {}}}, "nokia.sros.26_7.port.configuration"}
}};

}  // namespace router::cli_schema
