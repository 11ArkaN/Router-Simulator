// IS-IS info output preserves typed list presence and explicit default leaves.
// Formatting depends on immutable release facts, never live adjacency state.
#include "isis_cli_info.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
namespace router::lab::isis_cli {
namespace {
using namespace isis;
namespace defaults = configuration_profile;
struct Node {
  std::string key, text;
  bool block{};
  std::vector<Node> children;
};
class Writer {
public:
  Node root{{}, {}, true, {}};
  Writer() = default;
  Writer(const Writer &) = delete;
  Writer &operator=(const Writer &) = delete;
  template<class T> void leaf(std::string_view name, T value) {
    const auto text = std::to_string(+value); leaf(name, std::string_view{text});
  }
  void leaf(std::string_view name, std::string_view value) {
    auto text = std::string{name} + ' ' + std::string{value};
    // Area Addresses are individual system-ordered leaf-list values. Matching
    // their complete value reports additions/removals without pairing aliases.
    auto key = name == "area-address" ? text : std::string{name};
    current_->children.push_back({std::move(key), std::move(text), false, {}});
  }
  void boolean(std::string_view name, bool value) { leaf(name, std::string_view{value ? "true" : "false"}); }
  template<class T> void optional(std::string_view name, const std::optional<T> &value, T fallback, bool detail) {
    if (value || detail) leaf(name, value.value_or(fallback));
  }
  void boolean(std::string_view name, const std::optional<bool> &value, bool fallback, bool detail) {
    if (value || detail) boolean(name, value.value_or(fallback));
  }
  void admin(const std::optional<bool> &value, bool fallback, bool detail) {
    if (value || detail) leaf("admin-state", std::string_view{value.value_or(fallback) ? "enable" : "disable"});
  }
  void levels(const std::optional<ConfiguredLevels> &value, bool detail) {
    if (value || detail) {
      const auto selected = value.value_or(static_cast<ConfiguredLevels>(defaults::level_capability_default));
      leaf("level-capability", std::string_view{selected == ConfiguredLevels::both ? "1/2" : selected == ConfiguredLevels::level1 ? "1" : "2"});
    }
  }
  template<class Function> void block(std::string_view name, Function write) {
    // Only the current node's descendants grow while its pointer is borrowed.
    // Ancestor child vectors cannot reallocate until this synchronous block
    // returns; no pointer survives a sibling insertion or escapes the writer.
    auto *parent = current_;
    current_ = &parent->children.emplace_back(Node{std::string{name}, std::string{name}, true, {}});
    write(); current_ = parent;
  }
private:
  Node *current_{&root};
};
void render(std::ostream &out, const Node &node, std::size_t depth, char sign = '\0') {
  if (sign) out << sign;
  out << std::string(depth * 4U, ' ') << node.text << (node.block ? " {\n" : "\n");
  if (!node.block) return;
  for (const auto &child : node.children) render(out, child, depth + 1U, sign);
  if (sign) out << sign;
  out << std::string(depth * 4U, ' ') << "}\n";
}
const Node *find(const Node &parent, const Node &key) {
  const auto match = std::find_if(parent.children.begin(), parent.children.end(),
      [&](const auto &node) { return node.key == key.key && node.block == key.block; });
  return match == parent.children.end() ? nullptr : &*match;
}
void difference(std::ostream &out, const Node &before, const Node &after, std::size_t depth) {
  for (const auto &old : before.children) {
    const auto *current = find(after, old);
    if (!current) { render(out, old, depth, '-'); continue; }
    if (!old.block) {
      if (old.text != current->text) { render(out, old, depth, '-'); render(out, *current, depth, '+'); }
      continue;
    }
    std::ostringstream children;
    difference(children, old, *current, depth + 1U);
    if (const auto body = children.str(); !body.empty())
      out << std::string(depth * 4U, ' ') << old.text << " {\n" << body
          << std::string(depth * 4U, ' ') << "}\n";
  }
  for (const auto &node : after.children) if (!find(before, node)) render(out, node, depth, '+');
}

void interface_level(Writer &writer, const InterfaceLevelIntent &level, bool detail) {
  // An absent metric has no YANG leaf default; its runtime fallback is owned
  // by default-metric/reference-bandwidth resolution, not inserted as intent.
  if (level.metric) writer.leaf("metric", *level.metric);
  writer.optional("hello-interval", level.hello_interval_seconds, static_cast<std::uint16_t>(defaults::hello_interval_seconds_default), detail);
  writer.optional("hello-multiplier", level.hello_multiplier, static_cast<std::uint8_t>(defaults::hello_multiplier_default), detail);
  writer.optional("priority", level.priority, static_cast<std::uint8_t>(defaults::priority_default), detail);
  writer.boolean("passive", level.passive, defaults::interface_level_passive_default, detail);
}
void interface(Writer &writer, const InterfaceIntent &value, bool detail) {
  writer.admin(value.admin_enabled, defaults::interface_admin_enabled_default, detail);
  writer.levels(value.levels, detail);
  if (value.type) writer.leaf("interface-type", std::string_view{*value.type == ConfiguredInterfaceType::broadcast ? "broadcast" : "point-to-point"});
  writer.boolean("passive", value.passive, defaults::interface_passive_default, detail);
  writer.optional("csnp-interval", value.csnp_interval_seconds, static_cast<std::uint16_t>(defaults::csnp_interval_seconds_default), detail);
  writer.optional("retransmit-interval", value.retransmit_interval_seconds, static_cast<std::uint16_t>(defaults::retransmit_interval_seconds_default), detail);
  writer.optional("lsp-pacing-interval", value.lsp_pacing_interval_milliseconds, static_cast<std::uint16_t>(defaults::lsp_pacing_interval_milliseconds_default), detail);
  for (std::size_t index{}; index < value.level.size(); ++index) if (value.level[index].present)
    writer.block("level " + std::to_string(index + 1U), [&] { interface_level(writer, value.level[index], detail); });
}
void instance(Writer &writer, const InstanceIntent &value, bool detail) {
  writer.admin(value.admin_enabled, defaults::instance_admin_enabled_default, detail);
  writer.levels(value.levels, detail);
  writer.boolean("ipv4-routing", value.ipv4_routing, defaults::ipv4_routing_default, detail);
  if (value.ipv6_routing || detail) {
    const auto ipv6 = value.ipv6_routing.value_or(ConfiguredIpv6Routing::disabled);
    writer.leaf("ipv6-routing", std::string_view{ipv6 == ConfiguredIpv6Routing::disabled ? "false" : ipv6 == ConfiguredIpv6Routing::native ? "native" : "mt"});
  }
  if (value.system_id || detail) writer.leaf("system-id", std::string_view{format_configured_system_id(value.system_id.value_or(packet::isis::SystemId{}))});
  if (value.router_id) {
    const auto id = *value.router_id;
    const auto text = std::to_string(id >> 24U) + '.' + std::to_string((id >> 16U) & 255U) + '.' +
        std::to_string((id >> 8U) & 255U) + '.' + std::to_string(id & 255U);
    writer.leaf("router-id", std::string_view{text});
  }
  writer.optional("lsp-lifetime", value.lsp_lifetime_seconds, static_cast<std::uint16_t>(defaults::lsp_lifetime_seconds_default), detail);
  writer.optional("lsp-mtu-size", value.lsp_mtu_octets, static_cast<std::uint16_t>(defaults::lsp_mtu_octets_default), detail);
  for (const auto &area : value.areas) writer.leaf("area-address", std::string_view{format_configured_area(area)});
  for (std::size_t index{}; index < value.level.size(); ++index) if (value.level[index].present) {
    const auto &level = value.level[index];
    writer.block("level " + std::to_string(index + 1U), [&] {
      writer.optional("default-metric", level.default_metric, defaults::default_metric_default, detail);
      writer.optional("lsp-mtu-size", level.lsp_mtu_octets, static_cast<std::uint16_t>(defaults::level_lsp_mtu_octets_default), detail);
      // Preference defaults are context-dependent classic reference facts,
      // not defaults declared on the YANG scalar typedefs.
      writer.optional("preference", level.preference, static_cast<std::uint8_t>(index ? 18U : 15U), detail);
      writer.optional("external-preference", level.external_preference, static_cast<std::uint8_t>(index ? 165U : 160U), detail);
      writer.boolean("wide-metrics-only", level.wide_metrics_only, defaults::wide_metrics_only_default, detail);
    });
  }
  for (const auto &attached : value.interfaces) {
    std::ostringstream header; header << "interface " << std::quoted(attached.name);
    writer.block(header.str(), [&] { interface(writer, attached, detail); });
  }
}
Node tree(const isis::RouterConfiguration &configuration, bool detail) {
  Writer writer;
  for (const auto &value : configuration.instances)
    writer.block("isis " + std::to_string(value.instance), [&] { instance(writer, value, detail); });
  return std::move(writer.root);
}
}
std::string md_tree(const isis::RouterConfiguration &configuration, bool detail) {
  const auto nodes = tree(configuration, detail);
  std::ostringstream out;
  for (const auto &node : nodes.children) render(out, node, 0U);
  return out.str();
}
std::string md_compare(const isis::RouterConfiguration &running, const isis::RouterConfiguration &candidate) {
  const auto before = tree(running, false), after = tree(candidate, false);
  std::ostringstream out;
  difference(out, before, after, 1U);
  const auto body = out.str();
  return body.empty() ? body : "router \"Base\" {\n" + body + "}\n";
}
std::string classic_leaf(std::string_view value) {
  if (value.starts_with("area-address ")) return "area-id " + std::string{value.substr(13U)};
  if (value.starts_with("level-capability ")) {
    const auto levels = value.substr(17U);
    return "level-capability level-" + std::string{levels};
  }
  if (value == "ipv4-routing true") return "ipv4-routing";
  if (value == "ipv4-routing false") return "no ipv4-routing";
  if (value == "ipv6-routing false") return "no ipv6-routing";
  if (value == "wide-metrics-only true") return "wide-metrics-only";
  if (value == "wide-metrics-only false") return "no wide-metrics-only";
  return std::string{value};
}
}
