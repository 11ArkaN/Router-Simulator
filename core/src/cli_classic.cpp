// Classic CLI configuration semantics. The release schema selects commands;
// this engine applies changes to running configuration immediately.

#include "cli_internal.hpp"

#include "router/generated_profile.hpp"

#include <algorithm>
#include <charconv>

namespace router::cli_detail {
namespace {

std::optional<unsigned> unsigned_value(std::string_view text) {
  unsigned value{};
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size())
    return std::nullopt;
  return value;
}

std::optional<std::size_t>
exact_interface(const DeviceConfiguration &configuration,
                std::string_view name) {
  name = unquote(name);
  for (std::size_t index = 0; index < configuration.interface_count; ++index) {
    if (configuration.interfaces[index].valid &&
        configuration.interfaces[index].name == name)
      return index;
  }
  return std::nullopt;
}

bool profile_card(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::card_slot);
  const auto type = argument(command, cli_schema::TokenKind::card_type);
  return slot && type && *slot == std::to_string(profile::line_card_slot) &&
         *type == profile::line_card_type;
}

bool profile_card_slot(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::card_slot);
  return slot && *slot == std::to_string(profile::line_card_slot);
}

bool profile_mda_slot(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::mda_slot);
  return profile_card_slot(command) && slot &&
         *slot == std::to_string(profile::mda_slot);
}

bool profile_mda(const ParsedCommand &command) {
  const auto card_slot = argument(command, cli_schema::TokenKind::card_slot);
  const auto mda_slot = argument(command, cli_schema::TokenKind::mda_slot);
  const auto type = argument(command, cli_schema::TokenKind::mda_type);
  if (!card_slot || !mda_slot || !type ||
      *card_slot != std::to_string(profile::line_card_slot) ||
      *mda_slot != std::to_string(profile::mda_slot))
    return false;
  return *type == profile::modeled_mda_type;
}

} // namespace

std::string execute_classic(ConfigurationState &configuration,
                            CliSession &session,
                            const ParsedCommand &command) {
  using enum cli_schema::CommandId;
  auto &running = configuration.running;
  const auto finish = [&](bool changed, const char *message) {
    synchronize_candidate(configuration, session, changed);
    return std::string{message};
  };

  switch (command.spec->id) {
  case help:
  case help_question:
    return "show | configure | //";
  case configure_card_type: {
    if (!profile_card(command))
      return "Error: Bad command.";
    const bool changed = !running.card_provisioned;
    running.card_provisioned = true;
    return finish(changed, "Card 1 provisioned");
  }
  case classic_remove_card_type: {
    if (!profile_card_slot(command))
      return "Error: Bad command.";
    const bool changed = running.card_provisioned || running.mda_provisioned;
    running.card_provisioned = false;
    running.mda_provisioned = false;
    return finish(changed, "Card 1 provisioning removed");
  }
  case configure_mda_type: {
    if (!profile_mda(command) || !running.card_provisioned)
      return "Error: Bad command.";
    const bool changed = !running.mda_provisioned;
    running.mda_provisioned = true;
    return finish(changed, "MDA 1/1 provisioned");
  }
  case classic_remove_mda_type: {
    if (!profile_mda_slot(command))
      return "Error: Bad command.";
    const bool changed = running.mda_provisioned;
    running.mda_provisioned = false;
    return finish(changed, "MDA 1/1 provisioning removed");
  }
  case configure_system_name: {
    const auto before = running.system_name;
    const auto name = unquote(*argument(command, cli_schema::TokenKind::system_name));
    if (name.empty() || !copy_config_text(running.system_name, name))
      return "Error: Bad command.";
    return finish(before != running.system_name, "System name updated");
  }
  case classic_port_shutdown:
  case classic_port_no_shutdown:
  case classic_port_description:
  case classic_port_mtu: {
    if (!running.mda_provisioned)
      return "Error: Bad command.";
    const auto index = port_index(*argument(command, cli_schema::TokenKind::port_id));
    if (!index)
      return "Error: Bad command.";
    const auto before = running.ports[*index];
    auto &port = running.ports[*index];
    if (command.spec->id == classic_port_shutdown ||
        command.spec->id == classic_port_no_shutdown) {
      port.admin_enabled = command.spec->id == classic_port_no_shutdown;
    } else if (command.spec->id == classic_port_description) {
      const auto value = unquote(*argument(command, cli_schema::TokenKind::description));
      if (!copy_config_text(port.description, value))
        return "Error: Bad command.";
    } else {
      const auto mtu = unsigned_value(*argument(command, cli_schema::TokenKind::mtu));
      if (!mtu || *mtu < 576 || *mtu > 1500)
        return "Error: Bad command.";
      port.mtu = static_cast<std::uint16_t>(*mtu);
    }
    return finish(before.admin_enabled != port.admin_enabled ||
                      before.mtu != port.mtu ||
                      before.description != port.description,
                  "Port configuration updated");
  }
  case classic_interface_shutdown:
  case classic_interface_no_shutdown: {
    const auto index = exact_interface(
        running, *argument(command, cli_schema::TokenKind::interface_name));
    if (!index)
      return "Error: Bad command.";
    const bool next = command.spec->id == classic_interface_no_shutdown;
    const bool changed = running.interfaces[*index].admin_enabled != next;
    running.interfaces[*index].admin_enabled = next;
    return finish(changed, "Router interface configuration updated");
  }
  case classic_static_route: {
    const auto route = parse_static_route(
        *argument(command, cli_schema::TokenKind::ipv4_prefix),
        *argument(command, cli_schema::TokenKind::ipv4));
    if (!route)
      return "Error: Bad command.";
    const auto before = running.static_routes;
    if (!install_static(running, *route))
      return "Error: Bad command.";
    return finish(before != running.static_routes, "Static route configured");
  }
  default:
    return "Error: Bad command.";
  }
}

} // namespace router::cli_detail
