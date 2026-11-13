// Configuration contract tests own detached control intent. They exercise
// sourced lexical forms, identity precedence and default-presence semantics;
// no protocol owner, network shortcut or mutable global state is involved.
#include "router/isis_configuration.hpp"

#include <source_location>
#include <stdexcept>

void isis_configuration_tests() {
  using namespace router::isis;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS configuration invariant at " + std::to_string(where.line()));
  };
  const auto id = parse_configured_system_id("AbCD.0123.eF45");
  require(id && format_configured_system_id(*id) == "abcd.0123.ef45");
  for (const auto text : {"abcd0123ef45", "abcd:0123:ef45", "abcd.0123.ef4", "abcd.0123.ef450", "abcd.0123.ef4g"})
    require(!parse_configured_system_id(text));
  const auto short_area = parse_configured_area("49.0001"), equivalent_area = parse_configured_area("49.00.01");
  require(short_area && short_area->length == 3U && short_area == equivalent_area &&
      format_configured_area(*short_area) == "49.0001");
  const auto afi = parse_configured_area("49"), maximum_area = parse_configured_area("49.0001.0002.0003.0004.0005.0006");
  require(afi && afi->length == 1U && maximum_area && maximum_area->length == 13U &&
      parse_configured_area(format_configured_area(*maximum_area)) == maximum_area);
  for (const auto text : {"", "4", "4900", ".49", "49.", "49..01", "49.001", "49.000001", "49.0001.0002.0003.0004.0005.0006.01"})
    require(!parse_configured_area(text));

  RouterConfiguration configuration;
  configuration.instances.emplace_back();
  auto &instance = configuration.instances.front();
  instance.admin_enabled = true;
  require(validate_configuration(configuration) == ConfigurationError::none);
  instance.interfaces.emplace_back();
  auto &interface = instance.interfaces.front();
  interface.name = "to-peer";
  require(configured_level_mask(instance, interface) == 3U);
  instance.levels = ConfiguredLevels::level2;
  interface.levels = ConfiguredLevels::level1;
  require(configured_level_mask(instance, interface) == 0U &&
      validate_configuration(configuration) == ConfigurationError::none);
  const auto absent = configuration;
  interface.admin_enabled = configuration_profile::interface_admin_enabled_default;
  require(configuration != absent);
  interface.admin_enabled.reset();
  require(configuration == absent);
  instance.areas = {*short_area, *equivalent_area};
  require(validate_configuration(configuration) == ConfigurationError::duplicate_area);
  instance.areas = {*short_area};
  instance.areas[0U].bytes.back() = 1U;
  require(validate_configuration(configuration) == ConfigurationError::system_area);
  instance.areas = {*short_area};
  interface.level[0U].present = true;
  interface.level[0U].metric = 0U;
  require(validate_configuration(configuration) == ConfigurationError::metric);
  interface.level[0U].metric = 16777215U;
  interface.level[0U].hello_interval_seconds = std::uint16_t{20000U};
  interface.level[0U].hello_multiplier = std::uint8_t{100U};
  interface.level[0U].priority = std::uint8_t{127U};
  interface.lsp_pacing_interval_milliseconds = std::uint16_t{0U};
  require(validate_configuration(configuration) == ConfigurationError::none);
  interface.csnp_interval_seconds = std::uint16_t{0U};
  require(validate_configuration(configuration) == ConfigurationError::csnp_interval);
  interface.csnp_interval_seconds.reset();
  interface.name.clear();
  // Thirty-two Polish two-byte characters fit a 32-character YANG name even
  // though their encoding already occupies the old byte-oriented bound.
  for (unsigned index{}; index < 32U; ++index) interface.name += "\xc5\x82";
  require(validate_configuration(configuration) == ConfigurationError::none);
  interface.name += 'a';
  require(validate_configuration(configuration) == ConfigurationError::interface_name);
  interface.name = "\xc0\x80";
  require(validate_configuration(configuration) == ConfigurationError::interface_name);
  interface.name = "\xed\xa0\x80";
  require(validate_configuration(configuration) == ConfigurationError::interface_name);
  interface.name = "to-peer";
  instance.instance = 127U;
  require(validate_configuration(configuration) == ConfigurationError::none);
  instance.instance = 128U;
  require(validate_configuration(configuration) == ConfigurationError::instance_id);
  RouterConfiguration all_ids;
  for (unsigned index{}; index < 128U; ++index) {
    all_ids.instances.emplace_back();
    all_ids.instances.back().instance = static_cast<std::uint8_t>(index);
  }
  require(validate_configuration(all_ids) == ConfigurationError::none);
  all_ids.instances.push_back(all_ids.instances.front());
  require(validate_configuration(all_ids) == ConfigurationError::duplicate_instance);

  InstanceIntent identity;
  IdentityContext context{0x0a000001U, 0x0a000002U, 0xff000000U};
  require(format_configured_system_id(*resolve_configured_system_id(identity, context)) == "0100.0000.0001");
  context.base_router_id.reset();
  require(format_configured_system_id(*resolve_configured_system_id(identity, context)) == "0100.0000.0002");
  context.system_ipv4.reset();
  require(format_configured_system_id(*resolve_configured_system_id(identity, context)) == "2550.0000.0000");
  identity.router_id = 0xda700e05U;
  require(format_configured_system_id(*resolve_configured_system_id(identity, context)) == "2181.1201.4005");
  identity.system_id = *id;
  require(resolve_configured_system_id(identity, context) == id);
  identity.system_id = router::packet::isis::SystemId{};
  require(format_configured_system_id(*resolve_configured_system_id(identity, context)) == "2181.1201.4005");
  identity.router_id = 0U;
  context.fallback_router_id = 0U;
  require(!resolve_configured_system_id(identity, context));
}
