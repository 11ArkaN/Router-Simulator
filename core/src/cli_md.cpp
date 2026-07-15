// MD-CLI configuration semantics. Grammar comes from the release schema while
// this engine owns transactional candidate behavior and validation effects.

#include "cli_internal.hpp"

#include "router/generated_profile.hpp"

#include <charconv>
#include <utility>

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
  const auto changed = [&configuration, &session](bool modified) {
    // The prompt marker describes an actual datastore difference, not merely
    // whether an edit command has ever run. Reverting the last leaf therefore
    // clears '*' without requiring discard.
    if (modified)
      session.candidate_dirty =
          configuration.candidate != configuration.running;
    // SR OS configuration leaves are silent on success. The changed marker is
    // visible in the prompt and is the only normal acknowledgement.
    return std::string{};
  };

  switch (command.spec->id) {
  case md_configure_exclusive:
  case md_edit_config_exclusive:
    // Workflow entry is handled before the configuration engine receives a
    // candidate command. Retaining these IDs keeps the switch exhaustive.
    return {};
  case configure_card_type:
    if (!profile_card(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    {
      const bool modified = !router::profile_card(candidate).type;
      router::profile_card(candidate).type = profile::line_card_type;
      return changed(modified);
    }
  case configure_mda_type:
    if (!profile_mda(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    if (!router::profile_card(candidate).type)
      return "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    {
      const bool modified = !router::profile_mda(candidate).type;
      router::profile_mda(candidate).type = profile::modeled_mda_type;
      return changed(modified);
    }
  case configure_system_name: {
    const auto raw_name =
        *argument(command, cli_schema::TokenKind::system_name);
    const auto name = unquote(raw_name);
    const auto before = candidate.system_name;
    if (name.empty() || !valid_cli_string(raw_name) ||
        !copy_config_text(candidate.system_name, name))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    return changed(before != candidate.system_name);
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
    const auto before = port;
    if (command.spec->id == md_port_enable ||
        command.spec->id == md_port_disable) {
      port.admin_enabled = command.spec->id == md_port_enable;
    } else if (command.spec->id == md_port_description) {
      const auto raw_value =
          *argument(command, cli_schema::TokenKind::description);
      const auto value = unquote(raw_value);
      if (value.empty() || !valid_cli_string(raw_value) ||
          !copy_config_text(port.description, value))
        return "MINOR: MGMT_CORE #2301: Invalid element value";
    } else {
      const auto mtu =
          unsigned_value(*argument(command, cli_schema::TokenKind::mtu));
      if (!mtu || *mtu < profile::minimum_port_mtu ||
          *mtu > profile::maximum_port_mtu) {
        const auto entered = *argument(command, cli_schema::TokenKind::mtu);
        return "MINOR: MGMT_CORE #2301: Invalid element value - " +
               std::string{entered} + " out of range " +
               std::to_string(profile::minimum_port_mtu) + ".." +
               std::to_string(profile::maximum_port_mtu);
      }
      port.mtu = static_cast<std::uint16_t>(*mtu);
    }
    return changed(before != port);
  }
  case md_interface_enable:
  case md_interface_disable: {
    const auto index = exact_interface(
        candidate, *argument(command, cli_schema::TokenKind::interface_name));
    if (!index)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    const bool next = command.spec->id == md_interface_enable;
    const bool modified = candidate.interfaces[*index].admin_enabled != next;
    candidate.interfaces[*index].admin_enabled = next;
    return changed(modified);
  }
  case md_static_route: {
    const auto route = parse_static_route(
        *argument(command, cli_schema::TokenKind::ipv4_prefix),
        unquote(*argument(command, cli_schema::TokenKind::ipv4_key)));
    if (!route)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    const auto before = candidate.static_routes;
    if (!install_static(candidate, *route))
      return "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    return changed(before != candidate.static_routes);
  }
  case md_delete_card:
    if (!profile_card_slot(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    {
      const bool modified = router::profile_card(candidate).type ||
                            router::profile_mda(candidate).type;
      router::profile_card(candidate).type = nullptr;
      router::profile_mda(candidate).type = nullptr;
      return changed(modified);
    }
  case md_delete_mda:
    if (!profile_mda_slot(command))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    {
      const bool modified = router::profile_mda(candidate).type;
      router::profile_mda(candidate).type = nullptr;
      return changed(modified);
    }
  case md_delete_port_description: {
    if (!router::profile_mda(candidate).type)
      return "MINOR: MGMT_CORE #2203: Invalid element - currently not allowed";
    const auto index =
        port_index(*argument(command, cli_schema::TokenKind::port_id));
    if (!index)
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    const bool modified = candidate.ports[*index].description[0] != '\0';
    candidate.ports[*index].description = {};
    return changed(modified);
  }
  case md_delete_static_route: {
    const auto before = candidate.static_routes;
    if (!remove_static(candidate,
                       *argument(command, cli_schema::TokenKind::ipv4_prefix)))
      return "MINOR: MGMT_CORE #2301: Invalid element value";
    return changed(before != candidate.static_routes);
  }
  case md_compare: {
    if (!session.candidate_dirty)
      return {};
    const auto &running = configuration.running;
    std::string result;
    const auto append = [&result](std::string_view value) {
      if (!result.empty())
        result += '\n';
      result += value;
    };
    // compare output is valid hierarchical MD-CLI input. Signs occupy the
    // first column and unchanged ancestor braces remain unsigned, matching the
    // format accepted by copy and paste on SR OS.
    const auto &candidate_card = router::profile_card(candidate);
    const auto &running_card = router::profile_card(running);
    if (candidate_card.type != running_card.type ||
        router::profile_mda(candidate).type !=
            router::profile_mda(running).type) {
      append("    card " + std::to_string(profile::line_card_slot) + " {");
      if (candidate_card.type != running_card.type) {
        if (running_card.type)
          append(std::string{"-       card-type "} + running_card.type);
        if (candidate_card.type)
          append(std::string{"+       card-type "} + candidate_card.type);
      }
      const auto &candidate_mda = router::profile_mda(candidate);
      const auto &running_mda = router::profile_mda(running);
      if (candidate_mda.type != running_mda.type) {
        append("        mda " + std::to_string(profile::mda_slot) + " {");
        if (running_mda.type)
          append(std::string{"-           mda-type "} + running_mda.type);
        if (candidate_mda.type)
          append(std::string{"+           mda-type "} + candidate_mda.type);
        append("        }");
      }
      append("    }");
    }
    if (candidate.system_name != running.system_name) {
      append("    system {");
      append(std::string{"-       name \""} + running.system_name.data() + '"');
      append(std::string{"+       name \""} + candidate.system_name.data() +
             '"');
      append("    }");
    }
    for (std::size_t index = 0; index < candidate.ports.size(); ++index) {
      const auto &left = candidate.ports[index];
      const auto &right = running.ports[index];
      if (left.admin_enabled == right.admin_enabled && left.mtu == right.mtu &&
          left.description == right.description)
        continue;
      append(std::string{"    port "} + profile::port_ids[index] + " {");
      if (left.admin_enabled != right.admin_enabled) {
        append(std::string{"-       admin-state "} +
               (right.admin_enabled ? "enable" : "disable"));
        append(std::string{"+       admin-state "} +
               (left.admin_enabled ? "enable" : "disable"));
      }
      if (left.description != right.description) {
        if (right.description[0])
          append(std::string{"-       description \""} +
                 right.description.data() + '"');
        if (left.description[0])
          append(std::string{"+       description \""} +
                 left.description.data() + '"');
      }
      if (left.mtu != right.mtu) {
        append("        ethernet {");
        append("-           mtu " + std::to_string(right.mtu));
        append("+           mtu " + std::to_string(left.mtu));
        append("        }");
      }
      append("    }");
    }
    if (candidate.static_routes != running.static_routes) {
      append("    router \"Base\" {");
      append("        static-routes {");
      for (std::size_t index = 0; index < candidate.static_routes.size();
           ++index) {
        const auto &left = candidate.static_routes[index];
        const auto &right = running.static_routes[index];
        if (left == right)
          continue;
        const auto route_values = [](const StaticRouteConfiguration &route) {
          const auto ip = [](std::uint32_t value) {
            return std::to_string((value >> 24) & 255U) + '.' +
                   std::to_string((value >> 16) & 255U) + '.' +
                   std::to_string((value >> 8) & 255U) + '.' +
                   std::to_string(value & 255U);
          };
          return std::pair{ip(route.network) + '/' +
                               std::to_string(route.prefix_length),
                           ip(route.next_hop)};
        };
        const auto append_route =
            [&append, &route_values](char sign,
                                     const StaticRouteConfiguration &route) {
              // A list instance added or removed by compare carries the sign on
              // every line. The hierarchy matches `info` and is valid MD-CLI
              // input when copied back, including the route-type and quoted
              // next-hop list keys required by the Nokia YANG model.
              const auto [prefix, next_hop] = route_values(route);
              const std::string marker{sign};
              append(marker + "           route " + prefix +
                     " route-type unicast {");
              append(marker + "               next-hop \"" + next_hop + "\" {");
              append(marker + "               }");
              append(marker + "           }");
            };
        if (right.valid)
          append_route('-', right);
        if (left.valid)
          append_route('+', left);
      }
      append("        }");
      append("    }");
    }
    return result;
  }
  case md_commit: {
    if (session.candidate_outdated)
      return "MINOR: MGMT_CORE #2203: Invalid element - candidate baseline is "
             "out of date";
    const bool running_changed = candidate != configuration.running;
    configuration.running_unsaved =
        configuration.running_unsaved || running_changed;
    session.classic_unsaved = session.classic_unsaved || running_changed;
    configuration.running = candidate;
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    // A successful immediate commit produces no informational banner.
    return {};
  }
  case md_discard:
    configuration.candidate = configuration.running;
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    return {};
  default:
    return "MINOR: MGMT_CORE #2201: Unknown element";
  }
}

} // namespace router::cli_detail
