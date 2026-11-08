// The control datastore owns IS-IS intent. This module validates and projects
// immutable values without reading protocol owners, hardware or another router.
#include "router/isis_configuration.hpp"

#include <algorithm>

namespace router::isis {
namespace {
constexpr int hex(char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}
template <typename Value> bool range(const std::optional<Value> &value,
    std::uint32_t minimum, std::uint32_t maximum) noexcept {
  return !value || (*value >= minimum && *value <= maximum);
}
bool levels(const std::optional<ConfiguredLevels> &value) noexcept {
  return !value || (*value >= ConfiguredLevels::level1 && *value <= ConfiguredLevels::both);
}
// YANG string lengths count Unicode scalar values, not UTF-8 bytes. Reject
// overlong sequences, surrogates, invalid continuation bytes and embedded NUL.
std::optional<std::size_t> characters(std::string_view text) noexcept {
  std::size_t count{};
  for (std::size_t offset{}; offset < text.size(); ++count) {
    const auto first = static_cast<std::uint8_t>(text[offset++]);
    if (!first) return std::nullopt;
    if (first < 0x80U) continue;
    const auto width = first >= 0xc2U && first <= 0xdfU ? 2U :
        first >= 0xe0U && first <= 0xefU ? 3U : first >= 0xf0U && first <= 0xf4U ? 4U : 0U;
    if (!width || width - 1U > text.size() - offset) return std::nullopt;
    std::uint32_t point = first & (0x7fU >> width);
    for (unsigned index{1U}; index < width; ++index) {
      const auto byte = static_cast<std::uint8_t>(text[offset++]);
      if ((byte & 0xc0U) != 0x80U) return std::nullopt;
      point = point << 6U | (byte & 0x3fU);
    }
    if ((width == 2U && point < 0x80U) || (width == 3U && point < 0x800U) ||
        (width == 4U && point < 0x10000U) || point > 0x10ffffU ||
        (point >= 0xd800U && point <= 0xdfffU)) return std::nullopt;
  }
  return count;
}
bool area(const NeighborArea &value) noexcept {
  return value.length && value.length <= value.bytes.size() &&
      std::all_of(value.bytes.begin() + value.length, value.bytes.end(), [](auto byte) { return !byte; });
}
void append_hex(std::string &text, std::uint8_t value) {
  constexpr std::string_view digits{"0123456789abcdef"};
  text += digits[value >> 4U]; text += digits[value & 15U];
}
}
std::optional<packet::isis::SystemId> parse_configured_system_id(std::string_view text) noexcept {
  if (text.size() != 14U || text[4U] != '.' || text[9U] != '.') return std::nullopt;
  packet::isis::SystemId value{};
  std::size_t offset{};
  for (auto &byte : value) {
    if (offset == 4U || offset == 9U) ++offset;
    const auto upper = hex(text[offset++]), lower = hex(text[offset++]);
    if (upper < 0 || lower < 0) return std::nullopt;
    byte = static_cast<std::uint8_t>(upper * 16 + lower);
  }
  return value;
}
std::optional<NeighborArea> parse_configured_area(std::string_view text) noexcept {
  if (text.size() < 2U || text.size() > 38U) return std::nullopt;
  NeighborArea value;
  std::size_t offset{};
  while (offset < text.size()) {
    const auto separator = text.find('.', offset);
    const auto end = separator == std::string_view::npos ? text.size() : separator;
    const auto width = end - offset;
    if ((offset ? width != 2U && width != 4U : width != 2U) ||
        width / 2U > value.bytes.size() - value.length) return std::nullopt;
    while (offset < end) {
      const auto upper = hex(text[offset++]), lower = hex(text[offset++]);
      if (upper < 0 || lower < 0) return std::nullopt;
      value.bytes[value.length++] = static_cast<std::uint8_t>(upper * 16 + lower);
    }
    if (separator == std::string_view::npos) break;
    offset = separator + 1U;
    if (offset == text.size()) return std::nullopt;
  }
  return value;
}
std::string format_configured_system_id(const packet::isis::SystemId &value) {
  std::string text;
  text.reserve(14U);
  for (std::size_t index{}; index < value.size(); ++index) {
    if (index && !(index % 2U)) text += '.';
    append_hex(text, value[index]);
  }
  return text;
}
std::string format_configured_area(const NeighborArea &value) {
  if (!area(value)) return {};
  std::string text;
  text.reserve(value.length * 3U);
  for (std::size_t index{}; index < value.length; ++index) {
    if (index % 2U) text += '.';
    append_hex(text, value.bytes[index]);
  }
  return text;
}
std::optional<packet::isis::SystemId> resolve_configured_system_id(
    const InstanceIntent &intent, const IdentityContext &context) noexcept {
  if (intent.system_id && std::any_of(intent.system_id->begin(), intent.system_id->end(), [](auto value) { return value; }))
    return intent.system_id;
  std::uint32_t address = context.fallback_router_id;
  for (const auto candidate : {intent.router_id, context.base_router_id, context.system_ipv4})
    if (candidate && *candidate) { address = *candidate; break; }
  if (!address) return std::nullopt;
  packet::isis::SystemId result{};
  std::array<std::uint8_t, 12U> digits{};
  for (unsigned index{}; index < 4U; ++index) {
    const auto octet = (address >> (24U - index * 8U)) & 255U;
    digits[index * 3U] = static_cast<std::uint8_t>(octet / 100U);
    digits[index * 3U + 1U] = static_cast<std::uint8_t>(octet / 10U % 10U);
    digits[index * 3U + 2U] = static_cast<std::uint8_t>(octet % 10U);
  }
  for (std::size_t index{}; index < result.size(); ++index)
    result[index] = static_cast<std::uint8_t>(digits[index * 2U] * 16U + digits[index * 2U + 1U]);
  return result;
}
std::uint8_t configured_level_mask(const InstanceIntent &instance, const InterfaceIntent &interface) noexcept {
  const auto fallback = static_cast<ConfiguredLevels>(configuration_profile::level_capability_default);
  return static_cast<std::uint8_t>(static_cast<std::uint8_t>(instance.levels.value_or(fallback)) &
      static_cast<std::uint8_t>(interface.levels.value_or(fallback)));
}
ConfigurationError validate_configuration(const RouterConfiguration &configuration) noexcept {
  using namespace configuration_profile;
  using Error = ConfigurationError;
  for (auto instance = configuration.instances.begin(); instance != configuration.instances.end(); ++instance) {
    if (instance->instance > instance_maximum) return Error::instance_id;
    if (std::any_of(configuration.instances.begin(), instance, [&](const auto &other) { return other.instance == instance->instance; })) return Error::duplicate_instance;
    if (!levels(instance->levels)) return Error::levels;
    if (instance->ipv6_routing && *instance->ipv6_routing > ConfiguredIpv6Routing::multi_topology) return Error::ipv6_routing;
    if (!range(instance->lsp_lifetime_seconds, lsp_lifetime_seconds_minimum, lsp_lifetime_seconds_maximum)) return Error::lsp_lifetime;
    if (!range(instance->lsp_mtu_octets, lsp_mtu_octets_minimum, lsp_mtu_octets_maximum)) return Error::lsp_mtu;
    if (!range(instance->spf_wait.maximum, spf_max_wait_milliseconds_minimum, spf_max_wait_milliseconds_maximum) ||
        !range(instance->spf_wait.initial, spf_initial_wait_milliseconds_minimum, spf_initial_wait_milliseconds_maximum) ||
        !range(instance->spf_wait.second, spf_second_wait_milliseconds_minimum, spf_second_wait_milliseconds_maximum) ||
        !range(instance->lsp_wait.maximum, lsp_max_wait_milliseconds_minimum, lsp_max_wait_milliseconds_maximum) ||
        !range(instance->lsp_wait.initial, lsp_initial_wait_milliseconds_minimum, lsp_initial_wait_milliseconds_maximum) ||
        !range(instance->lsp_wait.second, lsp_second_wait_milliseconds_minimum, lsp_second_wait_milliseconds_maximum)) return Error::wait_timer;
    for (const auto &level : instance->level) {
      if (!level.present && (level.default_metric || level.lsp_mtu_octets || level.preference ||
          level.external_preference || level.wide_metrics_only)) return Error::context_presence;
      if (!range(level.default_metric, default_metric_minimum, default_metric_maximum)) return Error::metric;
      if (!range(level.lsp_mtu_octets, level_lsp_mtu_octets_minimum, level_lsp_mtu_octets_maximum)) return Error::lsp_mtu;
      if (!range(level.preference, preference_minimum, preference_maximum)) return Error::preference;
      if (!range(level.external_preference, external_preference_minimum, external_preference_maximum)) return Error::external_preference;
    }
    if (instance->areas.size() > area_addresses_maximum) return Error::system_area;
    for (auto current = instance->areas.begin(); current != instance->areas.end(); ++current) {
      if (!area(*current)) return Error::system_area;
      if (std::find(instance->areas.begin(), current, *current) != current) return Error::duplicate_area;
    }
    for (auto interface = instance->interfaces.begin(); interface != instance->interfaces.end(); ++interface) {
      const auto length = characters(interface->name);
      if (!length || *length < interface_name_minimum || *length > interface_name_maximum) return Error::interface_name;
      if (std::any_of(instance->interfaces.begin(), interface, [&](const auto &other) { return other.name == interface->name; })) return Error::duplicate_interface;
      if (!levels(interface->levels)) return Error::levels;
      if (interface->type && *interface->type > ConfiguredInterfaceType::broadcast) return Error::interface_type;
      if (!range(interface->csnp_interval_seconds, csnp_interval_seconds_minimum, csnp_interval_seconds_maximum)) return Error::csnp_interval;
      if (!range(interface->retransmit_interval_seconds, retransmit_interval_seconds_minimum, retransmit_interval_seconds_maximum)) return Error::retransmit_interval;
      if (!range(interface->lsp_pacing_interval_milliseconds, lsp_pacing_interval_milliseconds_minimum, lsp_pacing_interval_milliseconds_maximum)) return Error::lsp_pacing_interval;
      for (const auto &level : interface->level) {
        if (!level.present && (level.metric || level.hello_interval_seconds || level.hello_multiplier ||
            level.priority || level.passive)) return Error::context_presence;
        if (!range(level.metric, metric_minimum, metric_maximum)) return Error::metric;
        if (!range(level.hello_interval_seconds, hello_interval_seconds_minimum, hello_interval_seconds_maximum)) return Error::hello_interval;
        if (!range(level.hello_multiplier, hello_multiplier_minimum, hello_multiplier_maximum)) return Error::hello_multiplier;
        if (!range(level.priority, priority_minimum, priority_maximum)) return Error::priority;
      }
    }
  }
  return Error::none;
}
} // namespace router::isis
