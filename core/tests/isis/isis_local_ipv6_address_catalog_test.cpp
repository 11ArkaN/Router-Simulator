// Actual root fragment composition exercises independent IPv6 assignment,
// shared subnet owners and deduplicated address metadata. All peer-independent
// inputs and availability edits stay on one local control owner.
#include "router/isis_local_ipv6_address_catalog.hpp"
#include "router/isis_local_prefix_catalog_program.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS IPv6 address catalog invariant at " + std::to_string(at.line()));
}
}
void isis_local_ipv6_address_catalog_tests() {
  const auto a = *ip::parse_ipv6("2001:db8:12::1");
  const auto b = *ip::parse_ipv6("2001:db8:12::2");
  const auto ll = *ip::parse_ipv6("fe80::1");
  const auto subnet = *ip::parse_ip_prefix("2001:db8:12::/64");
  const auto v4 = *ip::parse_ip_prefix("192.0.2.0/24");
  InstanceIntent intent; intent.admin_enabled = true; intent.ipv6_routing = ConfiguredIpv6Routing::native;
  intent.levels = ConfiguredLevels::level2; intent.level[1U].wide_metrics_only = true;
  InterfaceIntent attached; attached.name = "edge"; intent.interfaces.push_back(attached);
  std::array roots{RootPrefix{v4, 10U, {}}, RootPrefix{subnet, 20U, {}}};
  const std::array sources{LocalPrefixSource{"edge", {std::span<const RootPrefix>{}, roots}, true, false}};
  const std::array bindings{LocalPrefixInterface{70001U, std::uint16_t{0U}, true}};
  auto prepared = prepare_local_prefix_catalog(intent, sources, bindings, {2U, 2U});
  require(prepared.status == LocalPrefixCatalogStatus::prepared && prepared.program.has_value());
  auto &prefixes = *prepared.program;
  const std::array candidates{LocalIpv6Address{70001U, std::uint16_t{0U}, b, 64U, false},
      LocalIpv6Address{70001U, std::uint16_t{0U}, a, 64U, true},
      LocalIpv6Address{70001U, std::uint16_t{0U}, ll, 64U, false}};
  auto address_program = prepare_local_ipv6_address_catalog(candidates, 3U);
  require(address_program && valid_local_ipv6_address_catalog(*address_program, prefixes));
  auto &addresses = *address_program;
  require(local_ipv6_prefix_available(addresses, 70001U, subnet) &&
      !local_ipv6_prefix_available(addresses, 70002U, subnet) &&
      !local_ipv6_prefix_available(addresses, 70001U, v4) &&
      !local_ipv6_link_local_available(addresses, 70001U));
  const packet::isis::SystemId system{1U, 2U, 3U, 4U, 5U, 6U};
  packet::isis::LanId root{}; std::copy(system.begin(), system.end(), root.begin());
  const auto now = RuntimeClock::time_point{100s};
  LocalLspProgram program; program.random = 1U;
  program.levels[1U] = LocalLspLevelProgram{1200U, 256U, 1s, 600s};
  packet::isis::LspId id{}; std::copy(system.begin(), system.end(), id.begin());
  program.records.push_back({1U, id, 3U, {}, true});
  LocalLspSet local(system, 3U, {packet::isis::InstanceFormat::standard, 0U}, program, now);
  OriginFragmentWorkspace workspace(8U, 1U, 229U);
  const auto compose = [&](bool all_possible = false) {
    workspace.reset();
    require(append_local_af_prefixes(workspace, prefixes, addresses, 1U, all_possible));
    require(append_local_ipv6_addresses(workspace, addresses, prefixes, all_possible));
    const auto outcome = workspace.compose(local, 1U, root, 3U, 1U, 229U, now);
    require(outcome == LocalContentResult::changed || outcome == LocalContentResult::unchanged);
    const auto content = local.fragment(1U, id); require(content.has_value());
    std::array<std::size_t, 3U> counts{};
    packet::isis::TlvCursor options(content->options);
    while (const auto option = options.next()) {
      if (option->code == 135U) ++counts[0U];
      if (option->code == 236U) ++counts[1U];
      if (option->code == 232U) {
        packet::isis::FixedAddressCursor<16U> values(*option, 232U);
        while (const auto value = values.next()) { require(!ip::is_link_local(*value)); ++counts[2U]; }
        require(values.valid());
      }
    }
    require(options.valid()); return counts;
  };
  require(compose() == std::array<std::size_t, 3U>{1U, 1U, 1U});
  require(!set_local_ipv6_address_ready(addresses, 70001U, 1U, a, false));
  require(set_local_ipv6_address_ready(addresses, 70001U, 0U, b, true));
  require(set_local_ipv6_address_ready(addresses, 70001U, 0U, a, false));
  require(compose() == std::array<std::size_t, 3U>{1U, 1U, 1U});
  require(set_local_ipv6_address_ready(addresses, 70001U, 0U, ll, true) &&
      local_ipv6_link_local_available(addresses, 70001U));
  const std::array<packet::Ipv6, 1U> hello_candidates{ll};
  require(local_ipv6_hello_available(addresses, 70001U, hello_candidates));
  const std::array incomplete_hello{ll, *ip::parse_ipv6("fe80::2")};
  require(!local_ipv6_hello_available(addresses, 70001U, incomplete_hello) &&
      !local_ipv6_hello_available(addresses, 70001U, {}));
  require(compose() == std::array<std::size_t, 3U>{1U, 1U, 1U});
  require(clear_local_ipv6_port(addresses, 0U) && !clear_local_ipv6_port(addresses, 0U));
  require(!local_ipv6_link_local_available(addresses, 70001U));
  require(compose() == std::array<std::size_t, 3U>{1U, 0U, 0U});
  require(compose(true) == std::array<std::size_t, 3U>{1U, 1U, 2U});
  require(set_local_prefix_carrier(prefixes, 0U, false));
  require(set_local_ipv6_address_ready(addresses, 70001U, 0U, a, true));
  require(compose() == std::array<std::size_t, 3U>{0U, 0U, 0U});
  // Equal address values on independent local interfaces share one metadata
  // unit while their corresponding prefix can retain either assigned owner.
  prefixes.interfaces.push_back({70002U, std::uint16_t{1U}, true});
  for (auto &unit : prefixes.units) if (unit.prefix == subnet) unit.owners.push_back(70002U);
  std::vector<LocalIpv6Address> repeated;
  for (const auto &unit : addresses.units) repeated.push_back(unit.source);
  repeated.push_back({70002U, std::uint16_t{1U}, a, 64U, true});
  auto shared_addresses = prepare_local_ipv6_address_catalog(repeated, 4U);
  require(shared_addresses && valid_local_ipv6_address_catalog(*shared_addresses, prefixes));
  addresses = std::move(*shared_addresses);
  require(compose() == std::array<std::size_t, 3U>{0U, 1U, 1U});
  require(set_local_prefix_carrier(prefixes, 0U, true));
  require(compose() == std::array<std::size_t, 3U>{1U, 1U, 1U});
  require(clear_local_ipv6_port(addresses, 0U));
  require(compose() == std::array<std::size_t, 3U>{1U, 1U, 1U});
  require(clear_local_ipv6_port(addresses, 1U));
  require(compose() == std::array<std::size_t, 3U>{1U, 0U, 0U});
  auto invalid = addresses; invalid.units.front().metadata[0U] = 0U;
  require(!valid_local_ipv6_address_catalog(invalid));
  invalid = addresses; invalid.units.front().source.physical_port = std::uint16_t{2U};
  require(!valid_local_ipv6_address_catalog(invalid, prefixes));
  require(!prepare_local_ipv6_address_catalog(candidates, 2U));
  auto bad = candidates; bad[0U] = bad[1U];
  require(!prepare_local_ipv6_address_catalog(bad, 3U));
  bad = candidates; bad[0U].address = *ip::parse_ipv6("ff02::1");
  require(!prepare_local_ipv6_address_catalog(bad, 3U));
  bad = candidates; bad[0U].prefix_length = 129U;
  require(!prepare_local_ipv6_address_catalog(bad, 3U));
  invalid = addresses; invalid.units.clear();
  require(!valid_local_ipv6_address_catalog(invalid, prefixes));
}
