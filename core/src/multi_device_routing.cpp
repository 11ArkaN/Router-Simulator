// Multi-device connected and static route selection. Each router runs this
// independently from its local configuration and never inspects the lab graph.

#include "router/multi_device_routing.hpp"

#include <algorithm>

namespace router::lab::routing {

bool RouteTable::rebuild(std::span<const ConnectedInput> connected,
                         std::span<const StaticInput> statics) noexcept {
  std::array<Route, device_catalog::maximum_fib_routes_per_router> next{};
  std::size_t next_count{};

  // Validate every configured prefix before selecting anything. A malformed
  // transaction cannot withdraw the old FIB partially and then fail halfway.
  for (const auto &entry : connected)
    if (entry.configured &&
        (entry.prefix_length > 32U ||
         (entry.local_system && entry.prefix_length != 32U) ||
         (!entry.local_system &&
          entry.port_ordinal >= device_catalog::maximum_ports_per_router))) {
      last_rebuild_valid_ = false;
      return false;
    }
  for (const auto &entry : statics)
    if (entry.configured && entry.prefix_length > 32U) {
      last_rebuild_valid_ = false;
      return false;
    }

  for (const auto &entry : connected) {
    // Connected reachability appears only after every local operational gate.
    // Network is canonicalized so host bits cannot create duplicate keys.
    if (!entry.configured || !entry.operational)
      continue;
    if (next_count == next.size()) {
      last_rebuild_valid_ = false;
      return false;
    }
    next[next_count++] = {
        .network = entry.network & prefix_mask(entry.prefix_length),
        .next_hop = 0,
        .port_ordinal = entry.port_ordinal,
        .prefix_length = entry.prefix_length,
        .local_system = entry.local_system};
  }

  for (const auto &entry : statics) {
    if (!entry.configured)
      continue;
    const ConnectedInput *resolution{};
    for (const auto &candidate : connected) {
      if (!candidate.configured || !candidate.operational ||
          candidate.local_system)
        continue;
      const auto mask = prefix_mask(candidate.prefix_length);
      if ((entry.next_hop & mask) != (candidate.network & mask))
        continue;
      // Overlapping connected interfaces resolve through the longest prefix,
      // matching the same specificity rule used for destination lookup.
      if (!resolution ||
          candidate.prefix_length > resolution->prefix_length)
        resolution = &candidate;
    }
    // An unresolved static route remains configured but inactive. It is not
    // programmed with a guessed port or resolved through another router's RIB.
    if (!resolution)
      continue;
    if (next_count == next.size()) {
      last_rebuild_valid_ = false;
      return false;
    }
    next[next_count++] = {
        .network = entry.network & prefix_mask(entry.prefix_length),
        .next_hop = entry.next_hop,
        .port_ordinal = resolution->port_ordinal,
        .prefix_length = entry.prefix_length,
        .local_system = false};
  }

  const bool changed =
      next_count != count_ ||
      !std::equal(next.begin(), next.begin() + next_count, routes_.begin(),
                  [](const Route &left, const Route &right) {
                    return left.network == right.network &&
                           left.next_hop == right.next_hop &&
                           left.port_ordinal == right.port_ordinal &&
                           left.prefix_length == right.prefix_length &&
                           left.local_system == right.local_system;
                  });
  if (changed) {
    // Publish the complete selected value only after all capacity and semantic
    // checks succeeded. Trailing entries are cleared for deterministic dumps.
    routes_ = next;
    count_ = static_cast<std::uint16_t>(next_count);
  }
  last_rebuild_valid_ = true;
  return changed;
}

FibProgram RouteTable::compile(std::uint64_t generation) const noexcept {
  FibProgram result{.generation = generation, .count = count_};
  // A full value copy is the versioned control-to-forwarding boundary. It
  // cannot retain RIB references that control mutates on the next transaction.
  std::copy_n(routes_.begin(), count_, result.routes.begin());
  return result;
}

bool lookup(const FibProgram &fib, std::uint32_t destination,
            Route &selected) noexcept {
  const Route *best{};
  for (std::size_t index = 0; index < fib.count; ++index) {
    const auto &candidate = fib.routes[index];
    if ((destination & prefix_mask(candidate.prefix_length)) !=
        candidate.network)
      continue;
    if (!best || candidate.prefix_length > best->prefix_length)
      best = &candidate;
  }
  if (!best)
    return false;
  selected = *best;
  return true;
}

bool Ipv6RouteTable::rebuild(
    std::span<const Ipv6ConnectedInput> connected,
    std::span<const Ipv6StaticInput> statics,
    std::span<const Ipv6ConnectedInput> additional_connected) noexcept {
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router> next{};
  std::size_t next_count{};

  // Reject non-canonical networks and invalid lengths before considering route
  // activity. Silent normalization would make CLI info differ from the key
  // actually installed in the forwarding table.
  const auto connected_valid = [](const auto &entries) noexcept {
    return std::all_of(entries.begin(), entries.end(), [](const auto &entry) {
      return !entry.configured ||
             (entry.interface_id != 0U &&
              entry.physical_port_ordinal <
                  device_catalog::maximum_ports_per_router &&
              entry.prefix_length <= ip::ipv6_address_bits &&
              ip::mask(entry.network, entry.prefix_length) == entry.network);
    });
  };
  if (!connected_valid(connected) ||
      !connected_valid(additional_connected)) {
    last_rebuild_valid_ = false;
    return false;
  }
  for (const auto &entry : statics) {
    if (entry.configured &&
        (entry.prefix_length > ip::ipv6_address_bits ||
         ip::is_unspecified(entry.next_hop) ||
         ip::mask(entry.network, entry.prefix_length) != entry.network ||
         (ip::is_link_local(entry.next_hop) &&
          (!entry.outgoing_interface_set ||
           entry.outgoing_interface_id == 0U)))) {
      last_rebuild_valid_ = false;
      return false;
    }
  }

  const auto append_connected = [&](const auto &entries) noexcept {
    for (const auto &entry : entries) {
      if (!entry.configured || !entry.operational)
        continue;
      if (next_count == next.size())
        return false;
      next[next_count++] = Ipv6Route{.network = entry.network,
                                     .interface_id = entry.interface_id,
                                     .physical_port_ordinal =
                                         entry.physical_port_ordinal,
                                     .prefix_length = entry.prefix_length};
    }
    return true;
  };
  if (!append_connected(connected) ||
      !append_connected(additional_connected)) {
    last_rebuild_valid_ = false;
    return false;
  }

  for (const auto &entry : statics) {
    if (!entry.configured)
      continue;
    const Ipv6ConnectedInput *resolution{};
    const auto consider_resolution = [&](const auto &entries) noexcept {
      for (const auto &candidate : entries) {
        if (!candidate.configured || !candidate.operational)
          continue;
        if (ip::is_link_local(entry.next_hop)) {
          // A scoped next hop is reachable only through its configured zone.
          // Search both native and service lists but never cross the explicit
          // interface identity supplied by configuration.
          if (candidate.interface_id == entry.outgoing_interface_id) {
            resolution = &candidate;
            return true;
          }
          continue;
        }
        const ip::Ipv6Prefix candidate_prefix{
            .network = candidate.network, .length = candidate.prefix_length};
        if (ip::contains(candidate_prefix, entry.next_hop) &&
            (!resolution ||
             candidate.prefix_length > resolution->prefix_length))
          resolution = &candidate;
      }
      return false;
    };
    const bool exact_scope = consider_resolution(connected);
    if (!exact_scope)
      static_cast<void>(consider_resolution(additional_connected));
    // Configured but unresolved routes remain absent from the FIB. No global
    // topology lookup is allowed to invent reachability from another router.
    if (!resolution)
      continue;
    if (next_count == next.size()) {
      last_rebuild_valid_ = false;
      return false;
    }
    next[next_count++] = Ipv6Route{
        .network = entry.network,
        .next_hop = entry.next_hop,
        .interface_id = resolution->interface_id,
        .physical_port_ordinal = resolution->physical_port_ordinal,
        .prefix_length = entry.prefix_length};
  }

  const bool changed =
      next_count != count_ ||
      !std::equal(next.begin(), next.begin() + next_count, routes_.begin(),
                  [](const Ipv6Route &left, const Ipv6Route &right) {
                    return left.network == right.network &&
                           left.next_hop == right.next_hop &&
                           left.interface_id == right.interface_id &&
                           left.physical_port_ordinal ==
                               right.physical_port_ordinal &&
                           left.prefix_length == right.prefix_length;
                  });
  if (changed) {
    routes_ = next;
    count_ = static_cast<std::uint16_t>(next_count);
  }
  last_rebuild_valid_ = true;
  return changed;
}

Ipv6FibProgram Ipv6RouteTable::compile(std::uint64_t generation) const noexcept {
  Ipv6FibProgram result{.generation = generation, .count = count_};
  std::copy_n(routes_.begin(), count_, result.routes.begin());
  return result;
}

bool lookup(const Ipv6FibProgram &fib, const ip::Ipv6 &destination,
            Ipv6Route &selected) noexcept {
  const Ipv6Route *best{};
  for (std::size_t index = 0; index < fib.count; ++index) {
    const auto &candidate = fib.routes[index];
    const ip::Ipv6Prefix prefix{.network = candidate.network,
                                .length = candidate.prefix_length};
    if (!ip::contains(prefix, destination))
      continue;
    if (!best || candidate.prefix_length > best->prefix_length)
      best = &candidate;
  }
  if (!best)
    return false;
  selected = *best;
  return true;
}

} // namespace router::lab::routing
