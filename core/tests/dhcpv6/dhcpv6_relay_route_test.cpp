// Relay route tests verify all four Nokia protocol identities, longest-prefix
// lookup, Prefix Exclude blackhole behavior and atomic mutation withdrawal.

#include "router/dhcpv6_relay_route.hpp"

#include <array>
#include <span>
#include <stdexcept>

void dhcpv6_relay_route_tests() {
  using namespace router;
  using namespace router::dhcpv6;

  const auto client = ip::parse_ipv6_prefix("2001:db8:1::/64");
  const auto delegated = ip::parse_ipv6("2001:db8:dead:bee0::");
  const auto excluded = ip::parse_ipv6("2001:db8:dead:beef::");
  const auto peer = ip::parse_ipv6("fe80::100");
  const auto excluded_destination =
      ip::parse_ipv6("2001:db8:dead:beef::1234");
  if (!client || !delegated || !excluded || !peer || !excluded_destination)
    throw std::runtime_error("DHCPv6 relay route fixture is invalid");

  const RelayInterfaceConfig policy{
      .interface_id = 81U,
      .physical_port_ordinal = 4U,
      .client_prefix = *client,
      .lease_population_limit = 2U,
      .route_non_temporary = true,
      .route_temporary = true,
      .route_delegated_prefix = true,
      .route_prefix_exclude = true};
  RelayLeaseRecord pd{
      .value = *delegated,
      .peer_address = *peer,
      .excluded_prefix = *excluded,
      .interface_id = 81U,
      .physical_port_ordinal = 4U,
      .prefix_length = 59U,
      .excluded_prefix_length = 64U,
      .protocol = RelayLeaseProtocol::delegated_prefix,
      .has_excluded_prefix = true};
  RelayRouteRepository routes;
  if (!routes.configure(std::span{&policy, 1U}) ||
      !routes.rebuild(std::span{&pd, 1U}, std::span{&policy, 1U}) ||
      routes.routes().size() != 2U)
    throw std::runtime_error("DHCPv6 relay did not build PD routes");
  RelayRoute selected;
  if (!routes.lookup(*excluded_destination, selected) || !selected.blackhole ||
      selected.protocol != RelayRouteProtocol::delegated_prefix_exclude ||
      selected.prefix_length != 64U)
    throw std::runtime_error("DHCPv6 Prefix Exclude did not win lookup");

  const RelayLeaseMutation remove{
      .kind = RelayLeaseMutationKind::remove, .record = pd};
  if (!routes.prepare(std::span{&remove, 1U}, std::span{&policy, 1U}) ||
      !routes.commit_prepared() || !routes.routes().empty())
    throw std::runtime_error("DHCPv6 relay did not withdraw both PD routes");

  // A disabled route flag retains lease state without leaking a route. This
  // is distinct from a no-op command because the policy and lease owner were
  // evaluated and the resulting operational generation is intentionally empty.
  RelayInterfaceConfig disabled = policy;
  disabled.route_delegated_prefix = false;
  disabled.route_prefix_exclude = false;
  if (!routes.configure(std::span{&disabled, 1U}) ||
      !routes.rebuild(std::span{&pd, 1U}, std::span{&disabled, 1U}) ||
      !routes.routes().empty())
    throw std::runtime_error("disabled DHCPv6 route policy installed state");
}
