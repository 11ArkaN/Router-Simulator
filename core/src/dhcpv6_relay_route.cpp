// DHCPv6 relay route implementation. Route protocol names and Prefix Exclude
// blackhole behavior follow Nokia SR OS DHCP relay documentation; option and
// lifetime validity is already proved by the lease-state owner.

#include "router/dhcpv6_relay_route.hpp"

#include <algorithm>
#include <limits>
#include <new>

namespace router::dhcpv6 {

const RelayInterfaceConfig *RelayRouteRepository::policy(
    std::span<const RelayInterfaceConfig> interfaces,
    std::uint64_t interface_id) noexcept {
  const auto found = std::find_if(
      interfaces.begin(), interfaces.end(), [&](const auto &candidate) {
        return candidate.interface_id == interface_id;
      });
  return found == interfaces.end() ? nullptr : &*found;
}

bool RelayRouteRepository::same_route_key(const RelayRoute &left,
                                          const RelayRoute &right) noexcept {
  return left.interface_id == right.interface_id &&
         left.network == right.network &&
         left.prefix_length == right.prefix_length &&
         left.protocol == right.protocol;
}

bool RelayRouteRepository::append_lease_routes(
    std::vector<RelayRoute> &output, const RelayLeaseRecord &lease,
    const RelayInterfaceConfig &interface) noexcept {
  bool main_enabled{};
  RelayRouteProtocol main_protocol{};
  switch (lease.protocol) {
  case RelayLeaseProtocol::non_temporary:
    main_enabled = interface.route_non_temporary;
    main_protocol = RelayRouteProtocol::non_temporary;
    break;
  case RelayLeaseProtocol::temporary:
    main_enabled = interface.route_temporary;
    main_protocol = RelayRouteProtocol::temporary;
    break;
  case RelayLeaseProtocol::delegated_prefix:
    main_enabled = interface.route_delegated_prefix;
    main_protocol = RelayRouteProtocol::delegated_prefix;
    break;
  }

  const auto append = [&](RelayRoute route) noexcept {
    if (std::any_of(output.begin(), output.end(), [&](const auto &existing) {
          return same_route_key(existing, route);
        }) ||
        output.size() == output.capacity())
      return false;
    output.push_back(route);
    return true;
  };
  if (main_enabled &&
      !append({.network = lease.value,
               // The Relay-forward peer address identifies the requesting
               // client or downstream relay on the service interface. It is
               // an encoded on-link next hop, never a pointer to that device.
               .next_hop = lease.peer_address,
               .interface_id = lease.interface_id,
               .physical_port_ordinal = lease.physical_port_ordinal,
               .prefix_length = lease.prefix_length,
               .protocol = main_protocol,
               .blackhole = false}))
    return false;
  if (lease.has_excluded_prefix && interface.route_prefix_exclude &&
      !append({.network = lease.excluded_prefix,
               .interface_id = lease.interface_id,
               .physical_port_ordinal = lease.physical_port_ordinal,
               .prefix_length = lease.excluded_prefix_length,
               .protocol = RelayRouteProtocol::delegated_prefix_exclude,
               .blackhole = true}))
    return false;
  return true;
}

bool RelayRouteRepository::configure(
    std::span<const RelayInterfaceConfig> interfaces) noexcept {
  std::size_t lease_capacity{};
  for (std::size_t index = 0; index < interfaces.size(); ++index) {
    const auto &candidate = interfaces[index];
    if (candidate.interface_id == 0U ||
        candidate.client_prefix.length > ip::ipv6_address_bits ||
        ip::mask(candidate.client_prefix.network,
                 candidate.client_prefix.length) !=
            candidate.client_prefix.network ||
        (candidate.route_prefix_exclude &&
         !candidate.route_delegated_prefix) ||
        std::any_of(interfaces.begin(), interfaces.begin() + index,
                    [&](const auto &previous) {
                      return previous.interface_id == candidate.interface_id;
                    }) ||
        lease_capacity > std::numeric_limits<std::size_t>::max() -
                             candidate.lease_population_limit)
      return false;
    lease_capacity += candidate.lease_population_limit;
  }
  if (lease_capacity > std::numeric_limits<std::size_t>::max() / 2U)
    return false;
  if (std::any_of(routes_.begin(), routes_.end(), [&](const auto &route) {
        return !policy(interfaces, route.interface_id);
      }))
    return false;
  try {
    std::vector<RelayRoute> live;
    std::vector<RelayRoute> staged;
    live.reserve(lease_capacity * 2U);
    staged.reserve(lease_capacity * 2U);
    live.insert(live.end(), routes_.begin(), routes_.end());
    routes_.swap(live);
    staged_.swap(staged);
    prepared_ = false;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RelayRouteRepository::rebuild(
    std::span<const RelayLeaseRecord> leases,
    std::span<const RelayInterfaceConfig> interfaces) noexcept {
  discard_prepared();
  staged_.clear();
  for (const auto &lease : leases) {
    const auto *interface = policy(interfaces, lease.interface_id);
    if (!interface || !append_lease_routes(staged_, lease, *interface)) {
      staged_.clear();
      return false;
    }
  }
  prepared_ = true;
  return commit_prepared();
}

bool RelayRouteRepository::prepare(
    std::span<const RelayLeaseMutation> mutations,
    std::span<const RelayInterfaceConfig> interfaces) noexcept {
  discard_prepared();
  if (routes_.size() > staged_.capacity())
    return false;
  staged_.assign(routes_.begin(), routes_.end());
  for (const auto &mutation : mutations) {
    const auto *interface = policy(interfaces, mutation.record.interface_id);
    if (!interface) {
      staged_.clear();
      return false;
    }
    const auto erase_protocol = [&](RelayRouteProtocol protocol,
                                    const ip::Ipv6 &network,
                                    std::uint8_t prefix_length) {
      staged_.erase(
          std::remove_if(staged_.begin(), staged_.end(),
                         [&](const auto &route) {
                           return route.interface_id ==
                                      mutation.record.interface_id &&
                                  route.protocol == protocol &&
                                  route.network == network &&
                                  route.prefix_length == prefix_length;
                         }),
          staged_.end());
    };
    const auto protocol =
        mutation.record.protocol == RelayLeaseProtocol::non_temporary
            ? RelayRouteProtocol::non_temporary
        : mutation.record.protocol == RelayLeaseProtocol::temporary
            ? RelayRouteProtocol::temporary
            : RelayRouteProtocol::delegated_prefix;
    erase_protocol(protocol, mutation.record.value,
                   mutation.record.prefix_length);
    if (mutation.record.has_excluded_prefix)
      erase_protocol(RelayRouteProtocol::delegated_prefix_exclude,
                     mutation.record.excluded_prefix,
                     mutation.record.excluded_prefix_length);
    if (mutation.kind == RelayLeaseMutationKind::install &&
        !append_lease_routes(staged_, mutation.record, *interface)) {
      staged_.clear();
      return false;
    }
  }
  prepared_ = true;
  return true;
}

bool RelayRouteRepository::commit_prepared() noexcept {
  if (!prepared_)
    return false;
  routes_.swap(staged_);
  staged_.clear();
  prepared_ = false;
  return true;
}

void RelayRouteRepository::discard_prepared() noexcept {
  staged_.clear();
  prepared_ = false;
}

bool RelayRouteRepository::lookup(const ip::Ipv6 &destination,
                                  RelayRoute &selected) const noexcept {
  const RelayRoute *best{};
  for (const auto &candidate : routes_) {
    if (!ip::contains({.network = candidate.network,
                       .length = candidate.prefix_length},
                      destination))
      continue;
    if (!best || candidate.prefix_length > best->prefix_length)
      best = &candidate;
  }
  if (!best)
    return false;
  selected = *best;
  return true;
}

std::vector<RelayRouteCheckpoint> RelayRouteRepository::checkpoint() const {
  return routes_;
}

bool RelayRouteRepository::restore(
    std::span<const RelayInterfaceConfig> interfaces,
    std::span<const RelayLeaseRecord> leases,
    std::span<const RelayRouteCheckpoint> state) noexcept {
  RelayRouteRepository replacement;
  if (!replacement.configure(interfaces) ||
      !replacement.rebuild(leases, interfaces) ||
      replacement.routes_.size() != state.size() ||
      !std::equal(replacement.routes_.begin(), replacement.routes_.end(),
                  state.begin()))
    return false;
  *this = std::move(replacement);
  return true;
}

} // namespace router::dhcpv6
