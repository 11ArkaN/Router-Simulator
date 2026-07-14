// MD-CLI configuration semantics. This engine mutates candidate only and uses
// one bounded datastore copy for commit or discard on the control shard.

#include "cli_internal.hpp"

#include "router/generated_profile.hpp"

#include <charconv>

namespace router::cli_detail {

std::string execute_md(ConfigurationState &configuration, CliSession &session,
                       const std::string &input) {
  auto &candidate = configuration.candidate;
  const auto changed = [&session]() {
    session.candidate_dirty = true;
    return "Candidate updated";
  };
  if (input == "?" || input == "help") {
    return "show | configure | delete | compare | commit | discard | //";
  }
  if (input == "configure card 1 card-type iom4-e") {
    candidate.card_provisioned = true;
    return changed();
  }
  if (input == "configure card 1 mda 1 mda-type me10-10gb-sfp+") {
    candidate.card_provisioned = true;
    candidate.mda_provisioned = true;
    return changed();
  }
  if (starts_with(input, "configure system name ")) {
    const auto name = std::string_view(input).substr(22);
    if (name.empty() || !copy_config_text(candidate.system_name, name)) {
      return "MINOR: system name must contain 1 to 64 characters";
    }
    return changed();
  }
  if (const auto parsed = port_tail(input, "configure port ")) {
    const auto [index, tail] = *parsed;
    auto &port = candidate.ports[index];
    if (tail == "admin-state enable" || tail == "admin-state disable") {
      port.admin_enabled = tail.ends_with("enable");
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
      const auto parsed_mtu =
          std::from_chars(text.data(), text.data() + text.size(), mtu);
      if (parsed_mtu.ec != std::errc{} ||
          parsed_mtu.ptr != text.data() + text.size() || mtu < 576 ||
          mtu > 1500) {
        return "MINOR: MTU must be between 576 and 1500 in this profile";
      }
      port.mtu = static_cast<std::uint16_t>(mtu);
    } else {
      return std::string{"MINOR: unsupported MD-CLI port command in the "} +
             profile::release + " milestone profile";
    }
    return changed();
  }
  if (starts_with(input, "configure router \"Base\" interface ") &&
      input.find(" admin-state ") != std::string::npos) {
    const auto index = interface_index(candidate, input);
    if (!index ||
        (!input.ends_with(" enable") && !input.ends_with(" disable"))) {
      return "MINOR: invalid router interface admin-state";
    }
    candidate.interfaces[*index].admin_enabled = input.ends_with(" enable");
    return changed();
  }
  constexpr std::string_view prefix =
      "configure router \"Base\" static-routes route ";
  if (starts_with(input, prefix)) {
    const auto route =
        parse_static_route(std::string_view(input).substr(prefix.size()));
    if (!route)
      return "MINOR: invalid static route prefix or next hop";
    if (!install_static(candidate, *route))
      return "MINOR: static route capacity reached";
    return changed();
  }
  if (input == "delete card 1") {
    candidate.card_provisioned = false;
    candidate.mda_provisioned = false;
    return changed();
  }
  if (input == "delete card 1 mda 1") {
    candidate.mda_provisioned = false;
    return changed();
  }
  if (input == "compare") {
    if (!session.candidate_dirty)
      return "No differences";
    const auto &running = configuration.running;
    std::string result;
    const auto append = [&result](const std::string &value) {
      if (!result.empty())
        result += '\n';
      result += value;
    };
    if (candidate.card_provisioned != running.card_provisioned) {
      append(candidate.card_provisioned ? "+ card 1 iom4-e"
                                        : "- card 1 iom4-e");
    }
    if (candidate.mda_provisioned != running.mda_provisioned) {
      append(candidate.mda_provisioned ? "+ mda 1 me10-10gb-sfp+"
                                       : "- mda 1 me10-10gb-sfp+");
    }
    if (candidate.system_name != running.system_name) {
      append(std::string{"~ system name "} + candidate.system_name.data());
    }
    for (std::size_t index = 0; index < candidate.ports.size(); ++index) {
      const auto &left = candidate.ports[index];
      const auto &right = running.ports[index];
      if (left.admin_enabled != right.admin_enabled || left.mtu != right.mtu ||
          left.description != right.description) {
        append(std::string{"~ port "} + profile::port_ids[index]);
      }
    }
    if (candidate.static_routes != running.static_routes)
      append("~ static route");
    return result.empty() ? "No differences" : result;
  }
  if (input == "commit") {
    if (session.candidate_outdated) {
      return "MINOR: candidate baseline is out of date; discard or update is "
             "required";
    }
    if (!candidate.card_provisioned)
      candidate.mda_provisioned = false;
    configuration.running = candidate;
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    return "Commit complete";
  }
  if (input == "discard") {
    configuration.candidate = configuration.running;
    session.candidate_dirty = false;
    session.candidate_outdated = false;
    return "Candidate discarded";
  }
  return std::string{"MINOR: unsupported MD-CLI command in the "} +
         profile::release + " milestone profile";
}

} // namespace router::cli_detail
