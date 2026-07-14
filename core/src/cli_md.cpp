// MD-CLI configuration semantics. Grammar comes from the release schema while
// this engine owns transactional candidate behavior and validation effects.

#include "cli_internal.hpp"

#include "router/generated_profile.hpp"

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

std::string execute_md(ConfigurationState &configuration, CliSession &session,
                       const ParsedCommand &command) {
  using enum cli_schema::CommandId;
  auto &candidate = configuration.candidate;
  const auto changed = [&session]() {
    session.candidate_dirty = true;
    return std::string{"Candidate updated"};
  };

  switch (command.spec->id) {
  case help:
  case help_question:
    return "show | configure | delete | compare | commit | discard | //";
  case configure_card_type:
    if (!profile_card(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    candidate.card_provisioned = true;
    return changed();
  case configure_mda_type:
    if (!profile_mda(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    candidate.card_provisioned = true;
    candidate.mda_provisioned = true;
    return changed();
  case configure_system_name: {
    const auto name = unquote(*argument(command, cli_schema::TokenKind::system_name));
    if (name.empty() || !copy_config_text(candidate.system_name, name))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    return changed();
  }
  case md_port_enable:
  case md_port_disable:
  case md_port_description:
  case md_port_mtu: {
    if (!candidate.mda_provisioned)
      return "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    const auto index = port_index(*argument(command, cli_schema::TokenKind::port_id));
    if (!index)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    auto &port = candidate.ports[*index];
    if (command.spec->id == md_port_enable || command.spec->id == md_port_disable) {
      port.admin_enabled = command.spec->id == md_port_enable;
    } else if (command.spec->id == md_port_description) {
      const auto value = unquote(*argument(command, cli_schema::TokenKind::description));
      if (!copy_config_text(port.description, value))
        return "MINOR: MGMT_CORE #2301: Invalid element value";
    } else {
      const auto mtu = unsigned_value(*argument(command, cli_schema::TokenKind::mtu));
      if (!mtu || *mtu < 576 || *mtu > 1500)
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
    candidate.card_provisioned = false;
    candidate.mda_provisioned = false;
    return changed();
  case md_delete_mda:
    if (!profile_mda_slot(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    candidate.mda_provisioned = false;
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
    if (candidate.card_provisioned != running.card_provisioned)
      append(candidate.card_provisioned ? "+ card 1 iom4-e"
                                        : "- card 1 iom4-e");
    if (candidate.mda_provisioned != running.mda_provisioned)
      append(candidate.mda_provisioned ? "+ mda 1 me10-10gb-sfp+"
                                       : "- mda 1 me10-10gb-sfp+");
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
      return "MINOR: MGMT_CORE #2203: Invalid element - candidate baseline is out of date";
    if (!candidate.card_provisioned)
      candidate.mda_provisioned = false;
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
