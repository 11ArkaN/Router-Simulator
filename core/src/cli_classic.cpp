// Classic CLI configuration semantics. The release schema selects commands;
// this engine applies changes to running configuration immediately.

#include "cli_internal.hpp"

#include "router/generated_profile.hpp"

#include <algorithm>
#include <charconv>

namespace router::cli_detail {
namespace {

// Parses unsigned CLI leaves without accepting signs or trailing characters.
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
  // Classic execution still requires an exact generated interface identity;
  // tokenizer abbreviations apply to literals, not arbitrary variable values.
  name = unquote(name);
  for (std::size_t index = 0; index < configuration.interface_count; ++index) {
    if (configuration.interfaces[index].valid &&
        configuration.interfaces[index].name == name)
      return index;
  }
  return std::nullopt;
}

// Confirms external slot and type against the active generated card capability.
bool profile_card(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::card_slot);
  const auto type = argument(command, cli_schema::TokenKind::card_type);
  return slot && type && *slot == std::to_string(profile::line_card_slot) &&
         *type == profile::line_card_type;
}

// Validates the generated line-card slot for immediate removal operations.
bool profile_card_slot(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::card_slot);
  return slot && *slot == std::to_string(profile::line_card_slot);
}

// Validates the generated parent and child location for MDA removal.
bool profile_mda_slot(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::mda_slot);
  return profile_card_slot(command) && slot &&
         *slot == std::to_string(profile::mda_slot);
}

// Validates the only provisionable MDA type in this release profile.
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
                            CliSession &session, const ParsedCommand &command) {
  // Classic commands update running immediately. finish() synchronizes or
  // invalidates the shared MD candidate after each real state change.
  using enum cli_schema::CommandId;
  auto &running = configuration.running;
  const auto finish = [&](bool changed, const char *message) {
    // Classic CLI applies changes immediately but does not save the boot
    // configuration. SR OS therefore keeps a leading '*' in later classic
    // prompts until an explicit save operation, which is not yet exposed.
    session.classic_unsaved = session.classic_unsaved || changed;
    configuration.running_unsaved = configuration.running_unsaved || changed;
    synchronize_candidate(configuration, session, changed);
    return std::string{message};
  };

  switch (command.spec->id) {
  case configure_card_type: {
    if (!profile_card(command))
      return "Error: Bad command.";
    auto &card = router::profile_card(running);
    const bool changed = !card.type;
    card.type = profile::line_card_type;
    // Classic CLI card provisioning starts shut down. The documented classic
    // configuration explicitly uses no shutdown, unlike the MD-CLI example.
    if (changed)
      card.admin_enabled = false;
    return finish(changed, "");
  }
  case classic_remove_card_type: {
    if (!profile_card_slot(command))
      return "Error: Bad command.";
    // SR OS requires child MDA provisioning to be removed before card-type.
    // Card shutdown alone cannot silently delete the child configuration.
    if (router::profile_card(running).admin_enabled ||
        router::profile_mda(running).type)
      return "Error: Bad command.";
    const bool changed = router::profile_card(running).type;
    router::profile_card(running).type = nullptr;
    return finish(changed, "");
  }
  case configure_mda_type: {
    if (!profile_mda(command) || !router::profile_card(running).type)
      return "Error: Bad command.";
    auto &mda = router::profile_mda(running);
    const bool changed = !mda.type;
    mda.type = profile::modeled_mda_type;
    // The classic MDA context has the same explicit no-shutdown lifecycle as
    // its parent card. Provisioning alone must not make ports operational.
    if (changed)
      mda.admin_enabled = false;
    return finish(changed, "");
  }
  case classic_remove_mda_type: {
    if (!profile_mda_slot(command))
      return "Error: Bad command.";
    if (router::profile_mda(running).admin_enabled)
      return "Error: Bad command.";
    const bool changed = router::profile_mda(running).type;
    router::profile_mda(running).type = nullptr;
    return finish(changed, "");
  }
  case classic_card_shutdown:
  case classic_card_no_shutdown: {
    if (!profile_card_slot(command) || !router::profile_card(running).type)
      return "Error: Bad command.";
    auto &card = router::profile_card(running);
    const bool enabled = command.spec->id == classic_card_no_shutdown;
    const bool changed = card.admin_enabled != enabled;
    card.admin_enabled = enabled;
    return finish(changed, "");
  }
  case classic_mda_shutdown:
  case classic_mda_no_shutdown: {
    if (!profile_mda_slot(command) || !router::profile_mda(running).type)
      return "Error: Bad command.";
    auto &mda = router::profile_mda(running);
    const bool enabled = command.spec->id == classic_mda_no_shutdown;
    // Administrative intent is independent at each hierarchy level. Enabling
    // an MDA below a shutdown card is valid configuration; operational state
    // remains down until the parent is enabled and physically ready.
    const bool changed = mda.admin_enabled != enabled;
    mda.admin_enabled = enabled;
    return finish(changed, "");
  }
  case configure_system_name: {
    const auto before = running.system_name;
    const auto raw_name =
        *argument(command, cli_schema::TokenKind::system_name);
    const auto name = unquote(raw_name);
    if (name.empty() || !valid_cli_string(raw_name) ||
        !copy_config_text(running.system_name, name))
      return "Error: Bad command.";
    return finish(before != running.system_name, "");
  }
  case classic_port_shutdown:
  case classic_port_no_shutdown:
  case classic_port_description:
  case classic_port_mtu: {
    if (!router::profile_mda(running).type)
      return "Error: Bad command.";
    const auto index =
        port_index(*argument(command, cli_schema::TokenKind::port_id));
    if (!index)
      return "Error: Bad command.";
    const auto before = running.ports[*index];
    auto &port = running.ports[*index];
    if (command.spec->id == classic_port_shutdown ||
        command.spec->id == classic_port_no_shutdown) {
      port.admin_enabled = command.spec->id == classic_port_no_shutdown;
    } else if (command.spec->id == classic_port_description) {
      const auto raw_value =
          *argument(command, cli_schema::TokenKind::description);
      const auto value = unquote(raw_value);
      if (value.empty() || !valid_cli_string(raw_value) ||
          !copy_config_text(port.description, value))
        return "Error: Bad command.";
    } else {
      const auto mtu =
          unsigned_value(*argument(command, cli_schema::TokenKind::mtu));
      if (!mtu || *mtu < profile::minimum_port_mtu ||
          *mtu > profile::maximum_port_mtu)
        return "Error: Bad command.";
      port.mtu = static_cast<std::uint16_t>(*mtu);
    }
    return finish(before.admin_enabled != port.admin_enabled ||
                      before.mtu != port.mtu ||
                      before.description != port.description,
                  "");
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
    return finish(changed, "");
  }
  case classic_remove_port_description: {
    if (!router::profile_mda(running).type)
      return "Error: Bad command.";
    const auto index =
        port_index(*argument(command, cli_schema::TokenKind::port_id));
    if (!index)
      return "Error: Bad command.";
    const bool changed = running.ports[*index].description[0] != '\0';
    running.ports[*index].description = {};
    return finish(changed, "");
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
    return finish(before != running.static_routes, "");
  }
  case classic_remove_static_route: {
    const auto before = running.static_routes;
    if (!remove_static(running,
                       *argument(command, cli_schema::TokenKind::ipv4_prefix)))
      return "Error: Bad command.";
    return finish(before != running.static_routes, "");
  }
  default:
    return "Error: Bad command.";
  }
}

} // namespace router::cli_detail
