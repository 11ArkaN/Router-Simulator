// Portable intent round trips preserve explicit defaults and absent leaves.
// Hostile lengths, enum values and noncanonical bools reject before publication.
#include "router/isis_configuration_codec.hpp"
#include <stdexcept>
namespace {
void require(bool value) { if (!value) throw std::runtime_error("IS-IS intent codec invariant"); }
}
void isis_configuration_codec_tests() {
  using namespace router::isis;
  constexpr std::size_t budget = 65536U;
  RouterConfiguration value;
  require(configuration_codec::encode(value, 5U) == std::optional{std::vector<std::uint8_t>{3U, 0U, 0U, 0U, 0U}});
  require(!configuration_codec::encode(value, 4U));
  value.instances.emplace_back();
  auto &instance = value.instances.back();
  std::vector<std::uint8_t> empty_instance(34U); empty_instance[0U] = empty_instance[1U] = 1U;
  const auto legacy_empty = configuration_codec::decode(empty_instance, budget);
  require(legacy_empty && *legacy_empty == value);
  empty_instance.resize(40U); empty_instance[0U] = 2U;
  require(*configuration_codec::decode(empty_instance, budget) == value);
  empty_instance.resize(41U); empty_instance[0U] = 3U;
  require(configuration_codec::encode(value, budget) == std::optional{empty_instance});
  instance.instance = 127U; instance.admin_enabled = true;
  instance.ipv4_routing = false; instance.ipv6_routing = ConfiguredIpv6Routing::native;
  instance.system_id = *parse_configured_system_id("0102.0304.0506");
  instance.areas.push_back(*parse_configured_area("49.0001"));
  instance.level[0U].present = true;
  instance.level[0U].default_metric = 10U;
  instance.level[0U].preference = std::uint8_t{255U};
  instance.interfaces.emplace_back();
  auto &interface = instance.interfaces.back();
  interface.name = "edge"; interface.admin_enabled = true;
  interface.level[1U].present = true;
  interface.level[1U].metric = 16777215U;
  interface.level[1U].hello_interval_seconds = std::uint16_t{20000U};
  interface.level[1U].hello_multiplier = std::uint8_t{100U};
  auto legacy = *configuration_codec::encode(value, budget);
  legacy.resize(legacy.size() - 7U); legacy[0U] = 1U;
  require(*configuration_codec::decode(legacy, budget) == value);
  instance.spf_wait = {550U, 10U, 100000U};
  instance.lsp_wait = {120000U, 99U, 1000U};
  instance.advertise_passive_only = true;
  const auto encoded = configuration_codec::encode(value, budget);
  require(encoded.has_value());
  auto previous = *encoded; previous.resize(previous.size() - 2U); previous[0U] = 2U;
  auto prior_intent = value; prior_intent.instances.front().advertise_passive_only.reset();
  require(*configuration_codec::decode(previous, budget) == prior_intent);
  auto invalid_boolean = *encoded; invalid_boolean.back() = 2U;
  require(!configuration_codec::decode(invalid_boolean, budget));
  instance.advertise_passive_only = false;
  const auto explicit_false = configuration_codec::encode(value, budget);
  require(explicit_false && *configuration_codec::decode(*explicit_false, budget) == value && *explicit_false != *encoded);
  instance.advertise_passive_only = true;
  const auto decoded = configuration_codec::decode(*encoded, budget);
  require(decoded && *decoded == value && decoded->instances[0U].level[0U].default_metric == 10U &&
      !decoded->instances[0U].level[1U].default_metric);
  require(!configuration_codec::decode(*encoded, 1U));
  require(!configuration_codec::encode(value, encoded->size() - 1U));
  for (std::size_t size{}; size < encoded->size(); ++size)
    require(!configuration_codec::decode(std::span{*encoded}.first(size), budget));
  for (const auto index : {0U, 7U, 11U}) {
    auto invalid = *encoded;
    invalid[index] = 255U;
    require(!configuration_codec::decode(invalid, budget));
  }
  auto invalid = *encoded; invalid.push_back(0U);
  require(!configuration_codec::decode(invalid, budget));
  invalid = *encoded;
  std::fill_n(invalid.begin() + 1U, 4U, std::uint8_t{255U});
  require(!configuration_codec::decode(invalid, budget));
  instance.areas.push_back(instance.areas.front());
  require(!configuration_codec::encode(value, budget));
  instance.areas.pop_back();
  interface.name.clear();
  for (unsigned index{}; index < 32U; ++index) interface.name += "\xc5\xbc";
  const auto unicode = configuration_codec::encode(value, budget);
  require(unicode && *configuration_codec::decode(*unicode, budget) == value);
}
