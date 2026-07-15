// MD-CLI configuration semantics. Grammar comes from the release schema while
// this engine owns transactional candidate behavior and validation effects.

#include "cli_internal.hpp"

#include "router/generated_profile.hpp"

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
  // Interface names are generated stable pointers. Exact matching prevents an
  // abbreviation from being accepted by execution after parser completion.
  name = unquote(name);
  for (std::size_t index = 0; index < configuration.interface_count; ++index) {
    if (configuration.interfaces[index].valid &&
        configuration.interfaces[index].name == name)
      return index;
  }
  return std::nullopt;
}

// Confirms that both the external slot and card type match active capability.
bool profile_card(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::card_slot);
  const auto type = argument(command, cli_schema::TokenKind::card_type);
  return slot && type && *slot == std::to_string(profile::line_card_slot) &&
         *type == profile::line_card_type;
}

// Validates the generated line-card slot for removal and child operations.
bool profile_card_slot(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::card_slot);
  return slot && *slot == std::to_string(profile::line_card_slot);
}

// Validates the generated MDA location without assuming a field named 1/1.
bool profile_mda_slot(const ParsedCommand &command) {
  const auto slot = argument(command, cli_schema::TokenKind::mda_slot);
  return profile_card_slot(command) && slot &&
         *slot == std::to_string(profile::mda_slot);
}

// Validates the complete provisionable MDA identity from generated capability.
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

std::string execute_md(ConfigurationState &configuration, CliSession &session,
                       const ParsedCommand &command) {
  // MD commands mutate only candidate until commit. Every successful mutation
  // passes through changed() so prompt state cannot drift from datastore state.
  using enum cli_schema::CommandId;
  auto &candidate = configuration.candidate;
  const auto changed = [&session]() {
    session.candidate_dirty = true;
    return std::string{"Candidate updated"};
  };

  switch (command.spec->id) {
  case help:
  case help_question:
    // Public dispatch resolves schema-derived help before entering the engine.
    // This branch only keeps the internal switch exhaustive.
    return {};
  case configure_card_type:
    if (!profile_card(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    router::profile_card(candidate).type = profile::line_card_type;
    return changed();
  case configure_mda_type:
    if (!profile_mda(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    router::profile_card(candidate).type = profile::line_card_type;
    router::profile_mda(candidate).type = profile::modeled_mda_type;
    return changed();
  case configure_system_name: {
    const auto name =
        unquote(*argument(command, cli_schema::TokenKind::system_name));
    if (name.empty() || !copy_config_text(candidate.system_name, name))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    return changed();
  }
  case md_port_enable:
  case md_port_disable:
  case md_port_description:
  case md_port_mtu: {
    if (!router::profile_mda(candidate).type)
      return "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    const auto index =
        port_index(*argument(command, cli_schema::TokenKind::port_id));
    if (!index)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    auto &port = candidate.ports[*index];
    if (command.spec->id == md_port_enable ||
        command.spec->id == md_port_disable) {
      port.admin_enabled = command.spec->id == md_port_enable;
    } else if (command.spec->id == md_port_description) {
      const auto value =
          unquote(*argument(command, cli_schema::TokenKind::description));
      if (!copy_config_text(port.description, value))
        return "MINOR: MGMT_CORE #2301: Invalid element value";
    } else {
      const auto mtu =
          unsigned_value(*argument(command, cli_schema::TokenKind::mtu));
      if (!mtu || *mtu < profile::minimum_port_mtu ||
          *mtu > profile::maximum_port_mtu)
        return "MINOR: MGMT_CORE #2301: Invalid element value";
      port.mtu = static_cast<std::uint16_t>(*mtu);
    }
    return changed();
  }
  case md_interface_enable:
  case md_interface_disable: {
    const auto index = exact_interface(
        candidate, *argument(command, cli_schema::TokenKind::interface_name));
    if (!index)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    candidate.interfaces[*index].admin_enabled =
        command.spec->id == md_interface_enable;
    return changed();
  }
  case md_static_route: {
    const auto route = parse_static_route(
        *argument(command, cli_schema::TokenKind::ipv4_prefix),
        *argument(command, cli_schema::TokenKind::ipv4));
    if (!route)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    if (!install_static(candidate, *route))
      return "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    return changed();
  }
  case md_delete_card:
    if (!profile_card_slot(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    router::profile_card(candidate).type = nullptr;
    router::profile_mda(candidate).type = nullptr;
    return changed();
  case md_delete_mda:
    if (!profile_mda_slot(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    router::profile_mda(candidate).type = nullptr;
    return changed();
  case md_compare: {
    if (!session.candidate_dirty)
      return "No differences";
    const auto &running = configuration.running;
    std::string result;
    const auto append = [&result](const std::string &value) {
      if (!result.empty())
        result += '\n';
      result += value;
    };
    if (router::profile_card(candidate).type !=
        router::profile_card(running).type) {
      append(std::string{router::profile_card(candidate).type ? "+ card "
                                                              : "- card "} +
             std::to_string(profile::line_card_slot) + " " +
             profile::line_card_type);
    }
    if (router::profile_mda(candidate).type !=
        router::profile_mda(running).type) {
      append(std::string{router::profile_mda(candidate).type ? "+ mda "
                                                             : "- mda "} +
             std::to_string(profile::mda_slot) + " " +
             profile::modeled_mda_type);
    }
    if (candidate.system_name != running.system_name)
      append(std::string{"~ system name "} + candidate.system_name.data());
    for (std::size_t index = 0; index < candidate.ports.size(); ++index) {
      const auto &left = candidate.ports[index];
      const auto &right = running.ports[index];
      if (left.admin_enabled != right.admin_enabled || left.mtu != right.mtu ||
          left.description != right.description)
        append(std::string{"~ port "} + profile::port_ids[index]);
    }
    if (candidate.static_routes != running.static_routes)
      append("~ static route");
    return result.empty() ? "No differences" : result;
  }
  case md_commit:
    if (session.candidate_outdated)
      return "MINOR: MGMT_CORE #2203: Invalid element - candidate baseline is "
             "out of date";
    if (!router::profile_card(candidate).type)
      router::profile_mda(candidate).type = nullptr;
    configuration.running = candidate;
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    return "Commit complete";
  case md_discard:
    configuration.candidate = configuration.running;
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    return "Candidate discarded";
  default:
    return "MINOR: MGMT_CORE #2201: Unknown element";
  }
}

} // namespace router::cli_detail
