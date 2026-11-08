// Shared IS-IS configuration transaction for MD and classic CLI. Source-bound
// generated paths select intent fields; only the caller can publish a generation.
#include "isis_cli_configuration.hpp"
#include "cli_internal.hpp"
#include <algorithm>
#include <charconv>
#include <type_traits>

namespace router::lab::isis_cli {
namespace {
using cli_schema::TokenKind;
std::string_view argument_text(const cli_detail::ParsedCommand &command, TokenKind kind) {
  const auto value = cli_detail::argument(command, kind);
  return value ? cli_detail::unquote(*value) : std::string_view{};
}
template<class T> bool number(std::string_view text, T &value) {
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
  return !text.empty() && result.ec == std::errc{} && result.ptr == text.data() + text.size();
}
template<class T> bool scalar(std::optional<T> &field, std::string_view value, bool remove) {
  if (remove) { field.reset(); return true; }
  T parsed{};
  if constexpr (std::is_same_v<T, bool>) {
    if (value != "true" && value != "false") return false;
    parsed = value == "true";
  } else if (!number(value, parsed)) return false;
  field = parsed;
  return true;
}
std::optional<isis::ConfiguredLevels> levels(std::string_view value) {
  if (value == "1") return isis::ConfiguredLevels::level1;
  if (value == "2") return isis::ConfiguredLevels::level2;
  if (value == "1/2") return isis::ConfiguredLevels::both;
  return {};
}
}
bool is_md_command(cli_schema::CommandId id) noexcept {
  return std::any_of(cli_schema::commands.begin(), cli_schema::commands.end(), [id](const auto &spec) {
    return spec.id == id && (spec.engine_mask & 1U) && spec.source_id == "nokia.sros.26_7.isis.basic_cli";
  });
}
bool is_classic_command(cli_schema::CommandId id) noexcept {
  return std::any_of(cli_schema::commands.begin(), cli_schema::commands.end(), [id](const auto &spec) {
    return spec.id == id && (spec.engine_mask & 2U) && spec.source_id == "nokia.sros.26_7.isis.basic_cli";
  });
}
EditResult edit(isis::RouterConfiguration &configuration,
                const cli_detail::ParsedCommand &command, CliEngine engine) {
  constexpr std::string_view root = "/configure/router/isis";
  if (!command.spec || !(command.spec->yang_path == root ||
      command.spec->yang_path.starts_with("/configure/router/isis/"))) return {};
  EditResult result{true, false, false, 0U};
  if (!(command.spec->engine_mask & (engine == CliEngine::md ? 1U : 2U))) return result;
  const auto instance_text = argument_text(command, TokenKind::isis_instance);
  if (!instance_text.empty() && !number(instance_text, result.instance)) return result;
  if (instance_text.empty() && engine != CliEngine::classic) return result;
  auto next = configuration;
  const bool remove = cli_detail::removal_command(*command.spec);
  const auto path = command.spec->yang_path.substr(root.size());
  // Classic scalar commands traverse creating configuration contexts before
  // applying an inverse or default-restoration leaf. Whole-node removals and
  // MD delete never create absent ancestors.
  const bool whole_node = path.empty() || path == "/interface" || path == "/level" || path == "/interface/level";
  const bool creates_parents = !remove || (engine == CliEngine::classic && !whole_node);
  auto instance = std::find_if(next.instances.begin(), next.instances.end(),
      [&](const auto &item) { return item.instance == result.instance; });
  // Whole-node and MD removals of absent subtrees never create parents.
  if (instance == next.instances.end()) {
    if (!creates_parents) return {true, true, false, result.instance};
    next.instances.push_back({}); instance = std::prev(next.instances.end());
    instance->instance = result.instance;
  }
  if (path.empty()) {
    if (remove) next.instances.erase(instance);
  } else {
    isis::InterfaceIntent *interface = nullptr;
    const bool interface_path = path.starts_with("/interface");
    if (interface_path) {
      const auto name = argument_text(command, TokenKind::interface_name);
      auto found = std::find_if(instance->interfaces.begin(), instance->interfaces.end(),
          [&](const auto &item) { return item.name == name; });
      if (found == instance->interfaces.end()) {
        if (!creates_parents) return {true, true, false, result.instance};
        instance->interfaces.push_back({}); found = std::prev(instance->interfaces.end());
        found->name = name;
      }
      if (path == "/interface" && remove) instance->interfaces.erase(found);
      else interface = &*found;
    }
    const auto leaf = path.substr(path.rfind('/') + 1U);
    const auto level_text = argument_text(command, TokenKind::isis_level);
    std::uint8_t level{};
    if (!level_text.empty() && (!number(level_text, level) || level < 1U || level > 2U)) return result;
    isis::InterfaceLevelIntent *il = interface && level ? &interface->level[level - 1U] : nullptr;
    isis::InstanceLevelIntent *rl = !interface_path && level ? &instance->level[level - 1U] : nullptr;
    if (il && creates_parents) il->present = true;
    if (rl && creates_parents) rl->present = true;
    bool accepted = path == "/interface";
    if (leaf == "level") {
      if (il) { if (remove) *il = {}; else il->present = true; accepted = true; }
      if (rl) { if (remove) *rl = {}; else rl->present = true; accepted = true; }
    }
    std::string_view value;
    for (std::size_t index{}; index < command.spec->token_count; ++index)
      if (command.spec->tokens[index].kind != TokenKind::literal)
        value = cli_detail::unquote(command.tokens[index]);
    // Classic booleans use positive/no or shutdown/no shutdown forms instead
    // of a YANG boolean argument. Removal remains leaf-specific below.
    const auto id = command.spec->handler_id;
    const bool admin = leaf == "admin-state";
    if (admin) {
      const bool enabled = id == cli_schema::CommandId::md_isis_admin_state_enable ||
          id == cli_schema::CommandId::md_isis_interface_admin_state_enable ||
          id == cli_schema::CommandId::classic_isis_admin_state_enable ||
          id == cli_schema::CommandId::classic_isis_interface_admin_state_enable;
      auto &field = interface ? interface->admin_enabled : instance->admin_enabled;
      if (engine == CliEngine::md && remove) field.reset(); else field = enabled;
      accepted = true;
    } else if (leaf == "level-capability") {
      auto &field = interface ? interface->levels : instance->levels;
      if (remove) { field.reset(); accepted = true; }
      else if (const auto parsed = levels(value)) { field = *parsed; accepted = true; }
    } else if (leaf == "interface-type" && interface) {
      if (remove) { interface->type.reset(); accepted = true; }
      else if (value == "broadcast" || value == "point-to-point") {
        interface->type = value == "broadcast" ? isis::ConfiguredInterfaceType::broadcast : isis::ConfiguredInterfaceType::point_to_point;
        accepted = true;
      }
    } else if (leaf == "system-id") {
      if (remove) { instance->system_id.reset(); accepted = true; }
      else if (const auto parsed = isis::parse_configured_system_id(value)) { instance->system_id = *parsed; accepted = true; }
    } else if (leaf == "router-id") {
      if (remove) { instance->router_id.reset(); accepted = true; }
      else {
        std::uint32_t address{}; std::size_t offset{}; accepted = true;
        for (unsigned part{}; part < 4U; ++part) {
          const auto end = part == 3U ? value.size() : value.find('.', offset);
          unsigned octet{};
          if (end == std::string_view::npos || !number(value.substr(offset, end - offset), octet) || octet > 255U) { accepted = false; break; }
          address = (address << 8U) | octet; offset = end + 1U;
        }
        if (accepted) instance->router_id = address;
      }
    } else if (leaf == "ipv6-routing") {
      if (remove) { instance->ipv6_routing.reset(); accepted = true; }
      else if (id == cli_schema::CommandId::md_isis_ipv6_routing_false) {
        instance->ipv6_routing = isis::ConfiguredIpv6Routing::disabled; accepted = true;
      } else if (id == cli_schema::CommandId::md_isis_ipv6_routing_native ||
                 id == cli_schema::CommandId::classic_isis_ipv6_routing_native) {
        instance->ipv6_routing = isis::ConfiguredIpv6Routing::native; accepted = true;
      }
    } else if (leaf == "area-address") {
      accepted = true;
      for (std::size_t index{}; index < command.spec->token_count; ++index) {
        if (command.spec->tokens[index].display == "*") { instance->areas.clear(); continue; }
        if (command.spec->tokens[index].kind != TokenKind::isis_area_address) continue;
        const auto area = isis::parse_configured_area(cli_detail::unquote(command.tokens[index]));
        if (!area) { accepted = false; break; }
        const auto found = std::find(instance->areas.begin(), instance->areas.end(), *area);
        if (remove) { if (found != instance->areas.end()) instance->areas.erase(found); }
        else if (found == instance->areas.end()) instance->areas.push_back(*area);
      }
      std::sort(instance->areas.begin(), instance->areas.end(), [](const auto &a, const auto &b) {
        return std::lexicographical_compare(a.view().begin(), a.view().end(), b.view().begin(), b.view().end());
      });
    } else if (leaf == "ipv4-routing" || leaf == "passive" || leaf == "wide-metrics-only") {
      const auto boolean = engine == CliEngine::classic ? (remove ? "false" : "true") : value;
      const bool reset = engine == CliEngine::md && remove;
      if (leaf == "ipv4-routing") accepted = scalar(instance->ipv4_routing, boolean, reset);
      else if (leaf == "wide-metrics-only" && rl) accepted = scalar(rl->wide_metrics_only, boolean, reset);
      else if (il) accepted = scalar(il->passive, boolean, reset);
      else if (interface) accepted = scalar(interface->passive, boolean, reset);
    } else if (leaf == "lsp-lifetime") accepted = scalar(instance->lsp_lifetime_seconds, value, remove);
    else if (leaf == "lsp-mtu-size") accepted = scalar(rl ? rl->lsp_mtu_octets : instance->lsp_mtu_octets, value, remove);
    else if (interface && leaf == "csnp-interval") accepted = scalar(interface->csnp_interval_seconds, value, remove);
    else if (interface && leaf == "lsp-pacing-interval") accepted = scalar(interface->lsp_pacing_interval_milliseconds, value, remove);
    else if (interface && leaf == "retransmit-interval") accepted = scalar(interface->retransmit_interval_seconds, value, remove);
    else if (il && leaf == "metric") accepted = scalar(il->metric, value, remove);
    else if (il && leaf == "hello-interval") accepted = scalar(il->hello_interval_seconds, value, remove);
    else if (il && leaf == "hello-multiplier") accepted = scalar(il->hello_multiplier, value, remove);
    else if (il && leaf == "priority") accepted = scalar(il->priority, value, remove);
    else if (rl && leaf == "default-metric") accepted = scalar(rl->default_metric, value, remove);
    else if (rl && leaf == "preference") accepted = scalar(rl->preference, value, remove);
    else if (rl && leaf == "external-preference") accepted = scalar(rl->external_preference, value, remove);
    if (!accepted) return result;
  }
  if (isis::validate_configuration(next) != isis::ConfigurationError::none) return result;
  result.valid = true; result.changed = next != configuration;
  if (result.changed) configuration = std::move(next);
  return result;
}
}
