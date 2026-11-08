// IS-IS browser projection preserves explicit configuration and list presence.
// Only the serialized control owner calls this module; dependencies are values.
#include "isis_configuration_projection.hpp"
#include <type_traits>
namespace router::lab::isis_projection {
namespace {
void quoted(std::ostream &out, std::string_view text) {
  constexpr std::string_view hex = "0123456789abcdef";
  out << '"';
  for (const auto character : text) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte == '"' || byte == '\\') out << '\\' << character;
    else if (byte < 32U) out << "\\u00" << hex[byte >> 4U] << hex[byte & 15U];
    else out << character;
  }
  out << '"';
}
class Object {
public:
  explicit Object(std::ostream &out) : out_(out) { out_ << '{'; }
  template<class T> void field(std::string_view name, const T &value) {
    key(name); scalar(value);
  }
  template<class Function> void nested(std::string_view name, Function write) { key(name); write(); }
  void finish() { out_ << '}'; }
private:
  void key(std::string_view name) { if (!first_) out_ << ','; first_ = false; quoted(out_, name); out_ << ':'; }
  template<class T> void scalar(const T &value) {
    if constexpr (std::is_same_v<T, bool>) out_ << (value ? "true" : "false");
    else if constexpr (std::is_integral_v<T>) out_ << +value;
    else if constexpr (std::is_same_v<T, isis::ConfiguredLevels>) quoted(out_, value == isis::ConfiguredLevels::both ? "1/2" : value == isis::ConfiguredLevels::level1 ? "1" : "2");
    else if constexpr (std::is_same_v<T, isis::ConfiguredInterfaceType>) quoted(out_, value == isis::ConfiguredInterfaceType::point_to_point ? "point-to-point" : "broadcast");
    else if constexpr (std::is_same_v<T, isis::ConfiguredIpv6Routing>) quoted(out_, value == isis::ConfiguredIpv6Routing::disabled ? "false" : value == isis::ConfiguredIpv6Routing::native ? "native" : "mt");
    else if constexpr (std::is_convertible_v<T, std::string_view>) quoted(out_, value);
    else { if (value) scalar(*value); else out_ << "null"; }
  }
  std::ostream &out_; bool first_{true};
};
template<class Range, class Function> void array(std::ostream &out, const Range &values, Function write) {
  out << '['; bool first = true;
  for (const auto &value : values) { if (!first) out << ','; first = false; write(value); }
  out << ']';
}
void level(std::ostream &out, const isis::InterfaceLevelIntent &value) {
  Object object{out}; object.field("present", value.present); object.field("metric", value.metric);
  object.field("helloIntervalSeconds", value.hello_interval_seconds); object.field("helloMultiplier", value.hello_multiplier);
  object.field("priority", value.priority); object.field("passive", value.passive); object.finish();
}
void level(std::ostream &out, const isis::InstanceLevelIntent &value) {
  Object object{out}; object.field("present", value.present); object.field("defaultMetric", value.default_metric);
  object.field("lspMtuOctets", value.lsp_mtu_octets); object.field("preference", value.preference);
  object.field("externalPreference", value.external_preference); object.field("wideMetricsOnly", value.wide_metrics_only); object.finish();
}
void interface(std::ostream &out, const isis::InterfaceIntent &value) {
  Object object{out}; object.field("name", value.name); object.field("type", value.type);
  object.field("levelCapability", value.levels); object.field("adminEnabled", value.admin_enabled);
  object.field("passive", value.passive); object.field("csnpIntervalSeconds", value.csnp_interval_seconds);
  object.field("retransmitIntervalSeconds", value.retransmit_interval_seconds);
  object.field("lspPacingIntervalMilliseconds", value.lsp_pacing_interval_milliseconds);
  object.nested("levels", [&] { array(out, value.level, [&](const auto &entry) { level(out, entry); }); }); object.finish();
}
void wait_timer(std::ostream &out, const isis::WaitTimerIntent &value) {
  Object object{out}; object.field("maximumMilliseconds", value.maximum);
  object.field("initialMilliseconds", value.initial); object.field("secondMilliseconds", value.second); object.finish();
}
void instance(std::ostream &out, const isis::InstanceIntent &value) {
  Object object{out}; object.field("instance", value.instance); object.field("adminEnabled", value.admin_enabled);
  object.field("advertisePassiveOnly", value.advertise_passive_only);
  object.field("ipv4Routing", value.ipv4_routing); object.field("ipv6Routing", value.ipv6_routing);
  object.field("levelCapability", value.levels);
  object.field("systemId", value.system_id ? std::optional{isis::format_configured_system_id(*value.system_id)} : std::nullopt);
  std::optional<std::string> router_id;
  if (value.router_id) {
    const auto id = *value.router_id;
    router_id = std::to_string(id >> 24U) + '.' + std::to_string((id >> 16U) & 255U) + '.' +
        std::to_string((id >> 8U) & 255U) + '.' + std::to_string(id & 255U);
  }
  object.field("routerId", router_id); object.field("lspLifetimeSeconds", value.lsp_lifetime_seconds);
  object.field("lspMtuOctets", value.lsp_mtu_octets);
  object.nested("spfWait", [&] { wait_timer(out, value.spf_wait); });
  object.nested("lspWait", [&] { wait_timer(out, value.lsp_wait); });
  object.nested("levels", [&] { array(out, value.level, [&](const auto &entry) { level(out, entry); }); });
  object.nested("areas", [&] { array(out, value.areas, [&](const auto &entry) { quoted(out, isis::format_configured_area(entry)); }); });
  object.nested("interfaces", [&] { array(out, value.interfaces, [&](const auto &entry) { interface(out, entry); }); }); object.finish();
}
}
void write_json(std::ostream &out, const isis::RouterConfiguration &value) {
  Object object{out}; object.nested("instances", [&] { array(out, value.instances, [&](const auto &entry) { instance(out, entry); }); }); object.finish();
}
}
