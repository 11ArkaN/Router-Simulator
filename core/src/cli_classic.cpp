// Classic CLI configuration semantics. This engine mutates running immediately
// and uses one shared rebase rule for the MD candidate in the same session.

#include "cli_internal.hpp"

#include "router/generated_profile.hpp"

#include <charconv>

namespace router::cli_detail {

std::string execute_classic(ConfigurationState &configuration,
                            CliSession &session, const std::string &input) {
  auto &running = configuration.running;
  const auto finish = [&](bool changed, const char *message) {
    synchronize_candidate(configuration, session, changed);
    return std::string{message};
  };
  if (input == "?" || input == "help")
    return "show | configure | //";
  if (input == "configure card 1 card-type iom4-e") {
    const bool changed = !running.card_provisioned;
    running.card_provisioned = true;
    return finish(changed, "Card 1 provisioned");
  }
  if (input == "configure card 1 no card-type") {
    const bool changed = running.card_provisioned || running.mda_provisioned;
    running.card_provisioned = false;
    running.mda_provisioned = false;
    return finish(changed, "Card 1 provisioning removed");
  }
  if (input == "configure card 1 mda 1 mda-type me10-10gb-sfp+") {
    if (!running.card_provisioned)
      return "MINOR: card 1 is not provisioned";
    const bool changed = !running.mda_provisioned;
    running.mda_provisioned = true;
    return finish(changed, "MDA 1/1 provisioned");
  }
  if (input == "configure card 1 mda 1 no mda-type") {
    const bool changed = running.mda_provisioned;
    running.mda_provisioned = false;
    return finish(changed, "MDA 1/1 provisioning removed");
  }
  if (starts_with(input, "configure system name ")) {
    const auto before = running.system_name;
    const auto name = std::string_view(input).substr(22);
    if (name.empty() || !copy_config_text(running.system_name, name)) {
      return "MINOR: system name must contain 1 to 64 characters";
    }
    return finish(before != running.system_name, "System name updated");
  }
  if (const auto parsed = port_tail(input, "configure port ")) {
    const auto [index, tail] = *parsed;
    const auto before = running.ports[index];
    auto &port = running.ports[index];
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
      const auto result =
          std::from_chars(text.data(), text.data() + text.size(), mtu);
      if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
          mtu < 576 || mtu > 1500) {
        return "MINOR: MTU must be between 576 and 1500 in this profile";
      }
      port.mtu = static_cast<std::uint16_t>(mtu);
    } else {
      return std::string{
                 "MINOR: unsupported classic CLI port command in the "} +
             profile::release + " milestone profile";
    }
    return finish(before.admin_enabled != port.admin_enabled ||
                      before.mtu != port.mtu ||
                      before.description != port.description,
                  "Port configuration updated");
  }
  if (starts_with(input, "configure router interface ") &&
      (input.ends_with(" shutdown") || input.ends_with(" no shutdown"))) {
    const auto index = interface_index(running, input);
    if (!index)
      return "MINOR: unsupported router interface";
    const bool next = input.ends_with(" no shutdown");
    const bool changed = running.interfaces[*index].admin_enabled != next;
    running.interfaces[*index].admin_enabled = next;
    return finish(changed, "Router interface configuration updated");
  }
  constexpr std::string_view prefix = "configure router static-route-entry ";
  if (starts_with(input, prefix)) {
    const auto route =
        parse_static_route(std::string_view(input).substr(prefix.size()));
    if (!route)
      return "MINOR: invalid static route prefix or next hop";
    const auto before = running.static_routes;
    if (!install_static(running, *route))
      return "MINOR: static route capacity reached";
    return finish(before != running.static_routes, "Static route configured");
  }
  return std::string{"MINOR: unsupported classic CLI command in the "} +
         profile::release + " milestone profile";
}

} // namespace router::cli_detail
