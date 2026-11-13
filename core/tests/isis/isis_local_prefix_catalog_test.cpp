// Local interface gates select owned prefix units without remote state. Tests
// compose actual semantic LSP fragments and check shared-prefix withdrawal,
// logical interfaces, cold capacity and hostile restored catalog encodings.
#include "router/isis_local_prefix_catalog_program.hpp"
#include "router/interface_identity.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS local prefix catalog invariant at " + std::to_string(at.line()));
}
bool contains(const LocalLspSet &local, std::size_t level, const packet::isis::SystemId &system,
    const ip::IpPrefix &prefix) {
  packet::isis::LspId id{}; std::copy(system.begin(), system.end(), id.begin());
  for (std::uint8_t fragment{}; fragment < 2U; ++fragment) {
    id[7U] = fragment;
    const auto content = local.fragment(level, id);
    if (!content) continue;
    packet::isis::TlvCursor options(content->options);
    while (const auto option = options.next()) if (option->code == 135U || option->code == 236U) {
      packet::isis::ExtendedPrefixCursor values(*option);
      while (const auto value = values.next()) if (value->prefix == prefix) return true;
      require(values.valid());
    }
    require(options.valid());
  }
  return false;
}
}
void isis_local_prefix_catalog_tests() {
  using Status = LocalPrefixCatalogStatus;
  InstanceIntent intent; intent.admin_enabled = true; intent.ipv6_routing = ConfiguredIpv6Routing::native;
  intent.level[0U].present = intent.level[1U].present = true;
  intent.level[0U].wide_metrics_only = intent.level[1U].wide_metrics_only = true;
  for (const auto name : {"first", "second", "system"}) {
    InterfaceIntent attached; attached.name = name; intent.interfaces.push_back(attached);
  }
  const auto shared = *ip::parse_ip_prefix("192.0.2.0/24");
  const auto loopback = *ip::parse_ip_prefix("192.0.2.1/32");
  const auto ipv6 = *ip::parse_ip_prefix("2001:db8:12::/64");
  std::array<std::uint8_t, 3U> attributes{4U, 1U, 0U};
  std::array first{RootPrefix{shared, 20U, {}, attributes}, RootPrefix{ipv6, 30U, {}}};
  std::array second{first[0U]};
  const std::array system{RootPrefix{loopback, 0U, {}}};
  std::array sources{LocalPrefixSource{"first", {first, first}, true, false},
      LocalPrefixSource{"second", {second, second}, false, false},
      LocalPrefixSource{"system", {system, system}, true, true}};
  const std::array bindings{LocalPrefixInterface{0x100000001ULL, std::uint16_t{0U}, true}, LocalPrefixInterface{0x100000002ULL, std::uint16_t{1U}, false},
      LocalPrefixInterface{lab::system_interface_id, {}, true}};
  auto prepared = prepare_local_prefix_catalog(intent, sources, bindings, {3U, 3U});
  require(prepared.status == Status::prepared && prepared.program && valid_local_prefix_catalog(*prepared.program));
  auto &catalog = *prepared.program;
  require(catalog.units.size() == 6U && catalog.units[0U].owners == std::vector<std::uint64_t>({0x100000001ULL, 0x100000002ULL}));
  const auto retained = catalog;
  attributes[2U] = 0x80U;
  require(catalog == retained);
  attributes[2U] = 0U;

  const packet::isis::SystemId local_system{1U, 2U, 3U, 4U, 5U, 6U};
  packet::isis::LanId root{}; std::copy(local_system.begin(), local_system.end(), root.begin());
  const auto now = RuntimeClock::time_point{100s};
  LocalLspProgram content; content.random = 1U;
  for (std::uint8_t level{}; level < 2U; ++level) {
    content.levels[level] = LocalLspLevelProgram{1200U, 256U, 1s, 600s};
    for (std::uint8_t fragment{}; fragment < 2U; ++fragment) {
      packet::isis::LspId id{}; std::copy(local_system.begin(), local_system.end(), id.begin()); id[7U] = fragment;
      content.records.push_back({level, id, 3U, {}, fragment == 0U});
    }
  }
  LocalLspSet local(local_system, 3U, {packet::isis::InstanceFormat::standard, 0U}, content, now);
  OriginFragmentWorkspace workspace(8U, 2U, 229U);
  const auto compose = [&](bool all_possible = false) {
    for (std::size_t level{}; level < 2U; ++level) {
      workspace.reset();
      require(append_local_prefix_catalog(workspace, catalog, level, all_possible));
      const auto result = workspace.compose(local, level, root, 3U, 2U, 229U, now);
      require(result == LocalContentResult::changed || result == LocalContentResult::unchanged);
    }
  };
  compose();
  require(contains(local, 1U, local_system, shared) && contains(local, 1U, local_system, ipv6));
  require(set_local_prefix_carrier(catalog, 0U, false) && !set_local_prefix_carrier(catalog, 0U, false));
  compose();
  require(!contains(local, 1U, local_system, shared) && !contains(local, 1U, local_system, ipv6) &&
      contains(local, 1U, local_system, loopback));
  require(set_local_prefix_carrier(catalog, 1U, true));
  compose();
  require(contains(local, 0U, local_system, shared) && !contains(local, 0U, local_system, ipv6));
  require(!set_local_prefix_carrier(catalog, 65535U, false) && catalog.interfaces.back().available);
  require(set_local_prefix_carrier(catalog, 0U, true));
  require(set_local_prefix_carrier(catalog, 1U, false));
  compose();
  require(contains(local, 1U, local_system, shared) && contains(local, 1U, local_system, ipv6));
  require(set_local_prefix_carrier(catalog, 0U, false));
  compose(true);
  require(contains(local, 1U, local_system, shared) && contains(local, 1U, local_system, ipv6));
  compose();
  require(!contains(local, 1U, local_system, shared));

  require(prepare_local_prefix_catalog(intent, sources, bindings, {2U, 2U}).status == Status::capacity);
  second[0U].metric = 21U;
  require(prepare_local_prefix_catalog(intent, sources, bindings, {3U, 3U}).status == Status::conflicting_prefix);
  second[0U].metric = 20U;
  intent.advertise_passive_only = true;
  auto passive = prepare_local_prefix_catalog(intent, sources, bindings, {1U, 1U});
  require(passive.status == Status::prepared && passive.program->units.size() == 2U &&
      passive.program->units.front().prefix == loopback);
  intent.interfaces[0U].level[0U].present = true; intent.interfaces[0U].level[0U].passive = true;
  passive = prepare_local_prefix_catalog(intent, sources, bindings, {3U, 1U});
  require(passive.status == Status::prepared && passive.program->units.size() == 4U);
  intent.advertise_passive_only = false;
  intent.level[0U].wide_metrics_only = false;
  require(prepare_local_prefix_catalog(intent, sources, bindings, {3U, 3U}).status == Status::prepared);
  first[0U].metric = second[0U].metric = 1000U;
  require(prepare_local_prefix_catalog(intent, sources, bindings, {3U, 3U}).status == Status::unresolved_narrow_metric);
  first[0U].metric = second[0U].metric = 20U;

  auto invalid = retained; invalid.version = 2U; require(!valid_local_prefix_catalog(invalid));
  invalid = retained; invalid.units.front().owners.push_back(0x100000001ULL); require(!valid_local_prefix_catalog(invalid));
  invalid = retained; invalid.units.front().owners = {999U}; require(!valid_local_prefix_catalog(invalid));
  invalid = retained; invalid.units.front().options.push_back(0U); require(!valid_local_prefix_catalog(invalid));
  invalid = retained; invalid.units.front().prefix = loopback; require(!valid_local_prefix_catalog(invalid));
  invalid = retained; invalid.interfaces[1U].interface_id = 0x100000001ULL; require(!valid_local_prefix_catalog(invalid));
  invalid = retained; invalid.units.insert(invalid.units.begin(), invalid.units.front()); require(!valid_local_prefix_catalog(invalid));
  auto wrong_binding = bindings; wrong_binding[0U].available = false;
  require(prepare_local_prefix_catalog(intent, sources, wrong_binding, {3U, 3U}).status == Status::invalid_context);

  std::array<std::uint8_t, 20U> limited{}; limited.fill(0xaaU);
  packet::isis::TlvWriter writer(limited); require(writer.append(99U, {}));
  const auto before = limited;
  RootPrefix transitional{shared, 20U, std::uint8_t{20U}};
  require(!encode_root_prefix(writer, transitional) && limited == before && writer.bytes().size() == 2U);
  InstanceIntent ipv4_intent; ipv4_intent.admin_enabled = true; ipv4_intent.levels = ConfiguredLevels::level2;
  ipv4_intent.level[1U].present = true; ipv4_intent.level[1U].wide_metrics_only = true;
  InterfaceIntent physical; physical.name = "edge"; physical.level[1U].present = true;
  physical.level[1U].metric = 17U; ipv4_intent.interfaces.push_back(physical);
  std::vector<LocalIpv4PrefixSource> ipv4_sources{{"edge", {lab::physical_interface_id(0U), std::uint16_t{0U}, true},
      0xc000027fU, 24U, true, false}};
  auto projected = prepare_local_ipv4_prefix_catalog(ipv4_intent, ipv4_sources, {4U, 4U});
  require(projected.status == Status::prepared && projected.program->units.size() == 1U &&
      projected.program->units.front().prefix == shared && projected.addresses.front() == packet::Ipv4({192U, 0U, 2U, 127U}));
  const auto metric = [&] {
    packet::isis::TlvCursor options(projected.program->units.front().options);
    const auto option = options.next(); require(option.has_value());
    packet::isis::ExtendedPrefixCursor values(*option);
    const auto value = values.next(); require(value.has_value()); return value->metric;
  };
  require(metric() == 17U);
  ipv4_intent.interfaces.front().level[1U].metric.reset();
  ipv4_intent.level[1U].default_metric = 30U;
  projected = prepare_local_ipv4_prefix_catalog(ipv4_intent, ipv4_sources, {4U, 4U});
  require(projected.status == Status::prepared && metric() == 30U);
  ipv4_intent.level[1U].default_metric.reset();
  projected = prepare_local_ipv4_prefix_catalog(ipv4_intent, ipv4_sources, {4U, 4U});
  require(projected.status == Status::prepared && metric() == 10U);
  InterfaceIntent logical; logical.name = "system"; ipv4_intent.interfaces.push_back(logical);
  ipv4_sources.push_back({"system", {lab::system_interface_id, {}, true}, 0xc0000201U, 32U, true, true});
  projected = prepare_local_ipv4_prefix_catalog(ipv4_intent, ipv4_sources, {4U, 4U});
  require(projected.status == Status::prepared && projected.program->units.size() == 2U && projected.addresses.size() == 2U);
  ipv4_intent.level[1U].default_metric = 30U;
  require(prepare_local_ipv4_prefix_catalog(ipv4_intent, ipv4_sources, {4U, 4U}).status == Status::unresolved_system_metric);
  ipv4_intent.level[1U].default_metric.reset();
  ipv4_sources.back().prefix_length = 31U;
  require(prepare_local_ipv4_prefix_catalog(ipv4_intent, ipv4_sources, {4U, 4U}).status == Status::invalid_context);

}
