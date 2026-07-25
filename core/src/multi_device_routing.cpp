// Multi-device connected and static route selection. Each router runs this
// independently from its local configuration and never inspects the lab graph.

#include "router/multi_device_routing.hpp"

#include <algorithm>
#include <tuple>

namespace router::lab::routing {
namespace {

[[nodiscard]] constexpr bool is_ospf(RouteSource source) noexcept {
  return source == RouteSource::ospf || source == RouteSource::ospf3;
}

[[nodiscard]] constexpr bool valid_dynamic(RouteSource source,
                                           OspfPathType path_type) noexcept {
  // This boundary currently admits only implemented OSPF publishers. A future
  // protocol must receive its own source identity and selection rules instead
  // of reusing an ambiguous dynamic marker.
  return is_ospf(source) && path_type != OspfPathType::none;
}

[[nodiscard]] constexpr std::uint8_t
path_rank(OspfPathType path_type) noexcept {
  switch (path_type) {
  case OspfPathType::none:
    return 0U;
  case OspfPathType::intra_area:
    return 1U;
  case OspfPathType::inter_area:
    return 2U;
  case OspfPathType::external_type_1:
  case OspfPathType::nssa_type_1:
    return 3U;
  case OspfPathType::external_type_2:
  case OspfPathType::nssa_type_2:
    return 4U;
  }
  return 0xffU;
}

template <typename RouteValue>
[[nodiscard]] constexpr bool selection_less(const RouteValue &left,
                                            const RouteValue &right) noexcept {
  if (left.preference != right.preference)
    return left.preference < right.preference;
  if (left.source != right.source)
    return left.source < right.source;
  if (path_rank(left.ospf_path_type) != path_rank(right.ospf_path_type))
    return path_rank(left.ospf_path_type) < path_rank(right.ospf_path_type);
  if (left.metric != right.metric)
    return left.metric < right.metric;
  // RFC 2328 section 16.4 uses internal cost as the tie-break among otherwise
  // equal Type 2 routes. It is harmlessly zero for non-OSPF and non-Type-2
  // candidates, whose complete cost is already stored in metric.
  if constexpr (requires { left.internal_metric; }) {
    const bool type_two =
        left.ospf_path_type == OspfPathType::external_type_2 ||
        left.ospf_path_type == OspfPathType::nssa_type_2;
    if (type_two && left.internal_metric != right.internal_metric)
      return left.internal_metric < right.internal_metric;
  }
  if (left.protocol_instance != right.protocol_instance)
    return left.protocol_instance < right.protocol_instance;
  return false;
}

template <typename RouteValue>
[[nodiscard]] constexpr bool same_selection_class(
    const RouteValue &left, const RouteValue &right) noexcept {
  return !selection_less(left, right) && !selection_less(right, left);
}

} // namespace

bool RouteTable::rebuild(std::span<const ConnectedInput> connected,
                         std::span<const StaticInput> statics,
                         std::span<const DynamicInput> dynamic,
                         std::uint16_t maximum_ecmp_paths) noexcept {
  std::array<Route, device_catalog::maximum_fib_routes_per_router> next{};
  std::array<Route, device_catalog::maximum_fib_routes_per_router>
      next_alternates{};
  std::size_t next_count{};
  std::size_t next_alternate_count{};

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
  if (maximum_ecmp_paths == 0U ||
      maximum_ecmp_paths > device_catalog::maximum_ecmp_paths) {
    last_rebuild_valid_ = false;
    return false;
  }
  for (const auto &entry : dynamic)
    if (entry.configured &&
        (entry.prefix_length > 32U ||
         entry.port_ordinal >= device_catalog::maximum_ports_per_router ||
         !valid_dynamic(entry.source, entry.ospf_path_type))) {
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
        .preference = 0U,
        .metric = 0U,
        .source = RouteSource::connected,
        .local_system = entry.local_system};
  }

  // Dynamic candidates are already resolved to a physical adjacency by their
  // protocol owner. Keeping that publication separate from static intent is
  // what lets indirect resolution exclude static-to-static recursion.
  for (const auto &entry : dynamic) {
    if (!entry.configured || !entry.operational ||
        entry.loop_free_alternate)
      continue;
    // Type 2 external routes first compare the external metric, then the cost
    // to the ASBR. The FIB does not need that second control-plane quantity,
    // so discard only dominated Type 2 candidates before creating compact FIB
    // rows. Equal internal costs remain available for ECMP.
    const bool type_two =
        entry.ospf_path_type == OspfPathType::external_type_2 ||
        entry.ospf_path_type == OspfPathType::nssa_type_2;
    const bool dominated =
        type_two &&
        std::any_of(dynamic.begin(), dynamic.end(), [&](const auto &other) {
          return other.configured && other.operational &&
                 !other.loop_free_alternate &&
                 other.network == entry.network &&
                 other.prefix_length == entry.prefix_length &&
                 other.preference == entry.preference &&
                 other.source == entry.source &&
                 other.ospf_path_type == entry.ospf_path_type &&
                 other.protocol_instance == entry.protocol_instance &&
                 other.metric == entry.metric &&
                 other.internal_metric < entry.internal_metric;
        });
    if (dominated)
      continue;
    if (next_count == next.size()) {
      last_rebuild_valid_ = false;
      return false;
    }
    next[next_count++] = {
        .network = entry.network & prefix_mask(entry.prefix_length),
        .next_hop = entry.next_hop,
        .port_ordinal = entry.port_ordinal,
        .prefix_length = entry.prefix_length,
        .preference = entry.preference,
        .metric = entry.metric,
        .source = entry.source,
        .local_system = false,
        .ospf_path_type = entry.ospf_path_type,
        .protocol_instance = entry.protocol_instance};
  }

  // Backup candidates never participate in primary RIB selection or indirect
  // static recursion. They are copied only for prefixes whose selected route
  // belongs to the same OSPF source, instance and path class. That check also
  // withdraws a stale repair path atomically when another protocol wins.
  for (const auto &entry : dynamic) {
    if (!entry.configured || !entry.operational ||
        !entry.loop_free_alternate)
      continue;
    const auto network = entry.network & prefix_mask(entry.prefix_length);
    const auto primary = std::find_if(
        next.begin(), next.begin() + next_count,
        [&](const auto &candidate) {
          return candidate.network == network &&
                 candidate.prefix_length == entry.prefix_length &&
                 candidate.source == entry.source &&
                 candidate.ospf_path_type == entry.ospf_path_type &&
                 candidate.protocol_instance == entry.protocol_instance;
        });
    if (primary == next.begin() + next_count)
      continue;
    if (next_alternate_count == next_alternates.size()) {
      last_rebuild_valid_ = false;
      return false;
    }
    next_alternates[next_alternate_count++] = {
        .network = network,
        .next_hop = entry.next_hop,
        .port_ordinal = entry.port_ordinal,
        .prefix_length = entry.prefix_length,
        .preference = entry.preference,
        .metric = entry.metric,
        .source = entry.source,
        .local_system = false,
        .ospf_path_type = entry.ospf_path_type,
        .protocol_instance = entry.protocol_instance};
  }
  std::sort(
      next_alternates.begin(),
      next_alternates.begin() + next_alternate_count,
      [](const Route &left, const Route &right) {
        return std::tie(left.network, left.prefix_length, left.next_hop,
                        left.port_ordinal) <
               std::tie(right.network, right.prefix_length, right.next_hop,
                        right.port_ordinal);
      });
  next_alternate_count = static_cast<std::size_t>(std::distance(
      next_alternates.begin(),
      std::unique(next_alternates.begin(),
                  next_alternates.begin() + next_alternate_count,
                  [](const Route &left, const Route &right) {
                    return left.network == right.network &&
                           left.prefix_length == right.prefix_length &&
                           left.next_hop == right.next_hop &&
                           left.port_ordinal == right.port_ordinal;
                  })));

  for (const auto &entry : statics) {
    if (!entry.configured)
      continue;
    if (!entry.indirect) {
      const ConnectedInput *resolution{};
      for (const auto &candidate : connected) {
        if (!candidate.configured || !candidate.operational ||
            candidate.local_system)
          continue;
        const auto mask = prefix_mask(candidate.prefix_length);
        if ((entry.next_hop & mask) != (candidate.network & mask))
          continue;
        // Direct static resolution follows the longest matching operational
        // connected interface. A system /32 cannot manufacture an adjacency.
        if (!resolution ||
            candidate.prefix_length > resolution->prefix_length)
          resolution = &candidate;
      }
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
          .preference = 5U,
          .metric = 1U,
          .source = RouteSource::static_route,
          .local_system = false};
      continue;
    }

    // Find the best dynamic route covering the indirect address. Prefix
    // length wins first, then protocol preference and metric. Every equal
    // resolved path is expanded into the static route's own ECMP candidates.
    const DynamicInput *best{};
    for (const auto &candidate : dynamic) {
      if (!candidate.configured || !candidate.operational)
        continue;
      if (candidate.loop_free_alternate)
        continue;
      const auto mask = prefix_mask(candidate.prefix_length);
      if ((entry.next_hop & mask) != (candidate.network & mask))
        continue;
      if (!best || candidate.prefix_length > best->prefix_length ||
          (candidate.prefix_length == best->prefix_length &&
           (candidate.preference < best->preference ||
            (candidate.preference == best->preference &&
             candidate.metric < best->metric))))
        best = &candidate;
    }
    if (!best)
      continue;
    for (const auto &candidate : dynamic) {
      if (!candidate.configured || !candidate.operational ||
          candidate.loop_free_alternate ||
          candidate.prefix_length != best->prefix_length ||
          candidate.preference != best->preference ||
          candidate.metric != best->metric)
        continue;
      const auto mask = prefix_mask(candidate.prefix_length);
      if ((entry.next_hop & mask) != (candidate.network & mask))
        continue;
      if (next_count == next.size()) {
        last_rebuild_valid_ = false;
        return false;
      }
      next[next_count++] = {
          .network = entry.network & prefix_mask(entry.prefix_length),
          .next_hop = candidate.next_hop,
          .port_ordinal = candidate.port_ordinal,
          .prefix_length = entry.prefix_length,
          .preference = 5U,
          .metric = 1U,
          .source = RouteSource::static_route,
          .local_system = false};
    }
  }

  // Sorting implements the documented lowest-next-hop fallback when ECMP is
  // disabled. It also makes flow-to-path mapping independent of CLI insertion
  // order. Only candidates with the winning protocol, preference and metric
  // survive for each prefix, capped by the router-wide ECMP setting.
  std::sort(next.begin(), next.begin() + next_count,
            [](const Route &left, const Route &right) {
              if (left.network != right.network)
                return left.network < right.network;
              if (left.prefix_length != right.prefix_length)
                return left.prefix_length > right.prefix_length;
              if (!same_selection_class(left, right))
                return selection_less(left, right);
              if (left.next_hop != right.next_hop)
                return left.next_hop < right.next_hop;
              return left.port_ordinal < right.port_ordinal;
            });
  // Compact the sorted candidate array in place. A second maximum-sized array
  // would double the control-shard stack cost for no ownership benefit. The
  // write cursor never overtakes the read cursor, so unread candidates remain
  // intact while losing paths are discarded.
  std::size_t selected_count{};
  for (std::size_t begin{}; begin < next_count;) {
    std::size_t end = begin + 1U;
    while (end < next_count && next[end].network == next[begin].network &&
           next[end].prefix_length == next[begin].prefix_length)
      ++end;
    const auto &winner = next[begin];
    std::uint16_t paths{};
    for (std::size_t index = begin;
         index < end && paths < maximum_ecmp_paths; ++index) {
      const auto &candidate = next[index];
      if (!same_selection_class(candidate, winner))
        break;
      next[selected_count++] = candidate;
      ++paths;
    }
    begin = end;
  }
  next_count = selected_count;

  // Primary selection may have chosen connected or static after the backup
  // candidates were staged. Compact again against the final winner so an LFA
  // can never repair a prefix now owned by another protocol.
  std::size_t retained_alternates{};
  for (std::size_t index{}; index < next_alternate_count; ++index) {
    const auto &alternate = next_alternates[index];
    const auto primary = std::find_if(
        next.begin(), next.begin() + next_count,
        [&](const auto &candidate) {
          return candidate.network == alternate.network &&
                 candidate.prefix_length == alternate.prefix_length &&
                 candidate.source == alternate.source &&
                 candidate.ospf_path_type == alternate.ospf_path_type &&
                 candidate.protocol_instance ==
                     alternate.protocol_instance;
        });
    if (primary != next.begin() + next_count)
      next_alternates[retained_alternates++] = alternate;
  }
  next_alternate_count = retained_alternates;
  if (next_count + next_alternate_count > next.size()) {
    // Primary and repair entries share the generated forwarding resource.
    // Rejecting the whole generation preserves the previous atomic FIB rather
    // than silently dropping protection for an arbitrary suffix of prefixes.
    last_rebuild_valid_ = false;
    return false;
  }

  const bool changed =
      next_count != count_ ||
      next_alternate_count != loop_free_alternate_count_ ||
      !std::equal(next.begin(), next.begin() + next_count, routes_.begin(),
                  [](const Route &left, const Route &right) {
                    return left.network == right.network &&
                           left.next_hop == right.next_hop &&
                           left.port_ordinal == right.port_ordinal &&
                           left.prefix_length == right.prefix_length &&
                           left.preference == right.preference &&
                           left.metric == right.metric &&
                           left.source == right.source &&
                           left.local_system == right.local_system &&
                           left.ospf_path_type == right.ospf_path_type &&
                           left.protocol_instance == right.protocol_instance;
                  }) ||
      !std::equal(
          next_alternates.begin(),
          next_alternates.begin() + next_alternate_count,
          loop_free_alternates_.begin(),
          [](const Route &left, const Route &right) {
            return left.network == right.network &&
                   left.next_hop == right.next_hop &&
                   left.port_ordinal == right.port_ordinal &&
                   left.prefix_length == right.prefix_length &&
                   left.preference == right.preference &&
                   left.metric == right.metric &&
                   left.source == right.source &&
                   left.ospf_path_type == right.ospf_path_type &&
                   left.protocol_instance == right.protocol_instance;
          });
  if (changed) {
    // Publish the complete selected value only after all capacity and semantic
    // checks succeeded. Trailing entries are cleared for deterministic dumps.
    routes_ = next;
    loop_free_alternates_ = next_alternates;
    count_ = static_cast<std::uint16_t>(next_count);
    loop_free_alternate_count_ =
        static_cast<std::uint16_t>(next_alternate_count);
  }
  last_rebuild_valid_ = true;
  return changed;
}

FibProgram RouteTable::compile(std::uint64_t generation) const noexcept {
  FibProgram result{.generation = generation,
                    .count = count_,
                    .loop_free_alternate_count =
                        loop_free_alternate_count_};
  // A full value copy is the versioned control-to-forwarding boundary. It
  // cannot retain RIB references that control mutates on the next transaction.
  std::copy_n(routes_.begin(), count_, result.routes.begin());
  std::copy_n(loop_free_alternates_.begin(), loop_free_alternate_count_,
              result.routes.begin() + count_);
  return result;
}

bool lookup(const FibProgram &fib, std::uint32_t destination, Route &selected,
            std::uint64_t flow_hash) noexcept {
  const Route *best{};
  std::array<const Route *, device_catalog::maximum_ecmp_paths> equal{};
  std::size_t equal_count{};
  for (std::size_t index = 0; index < fib.count; ++index) {
    const auto &candidate = fib.routes[index];
    if ((destination & prefix_mask(candidate.prefix_length)) !=
        candidate.network)
      continue;
    if (!best || candidate.prefix_length > best->prefix_length) {
      best = &candidate;
      equal[0] = best;
      equal_count = 1U;
    } else if (candidate.prefix_length == best->prefix_length &&
               candidate.network == best->network &&
               same_selection_class(candidate, *best) &&
               equal_count < equal.size()) {
      equal[equal_count++] = &candidate;
    }
  }
  if (!best)
    return false;
  selected = *equal[flow_hash % equal_count];
  return true;
}

bool lookup_loop_free_alternate(const FibProgram &fib,
                                std::uint32_t destination,
                                Route &selected,
                                std::uint64_t flow_hash) noexcept {
  // Alternates for one prefix are already validated against its primary route
  // generation. Longest prefix remains necessary because one FIB can retain
  // repairs for overlapping destinations.
  const Route *best{};
  std::array<const Route *, device_catalog::maximum_ecmp_paths> equal{};
  std::size_t equal_count{};
  for (std::size_t index{}; index < fib.loop_free_alternate_count; ++index) {
    const auto &candidate = fib.routes[fib.count + index];
    if ((destination & prefix_mask(candidate.prefix_length)) !=
        candidate.network)
      continue;
    if (!best || candidate.prefix_length > best->prefix_length) {
      best = &candidate;
      equal[0U] = best;
      equal_count = 1U;
    } else if (candidate.prefix_length == best->prefix_length &&
               candidate.network == best->network &&
               equal_count < equal.size()) {
      equal[equal_count++] = &candidate;
    }
  }
  if (!best)
    return false;
  selected = *equal[flow_hash % equal_count];
  return true;
}

bool Ipv6RouteTable::rebuild(
    std::span<const Ipv6ConnectedInput> connected,
    std::span<const Ipv6StaticInput> statics,
    std::span<const Ipv6ConnectedInput> additional_connected,
    std::span<const Ipv6DynamicInput> dynamic,
    std::uint16_t maximum_ecmp_paths) noexcept {
  // One bounded primary generation remains automatic storage. Repairs are
  // staged later in their existing owner array only after every fallible
  // primary calculation has succeeded. This avoids both the former second
  // stack array and a heap allocation that could fail at the configured Wasm
  // memory ceiling during a large laboratory.
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router> next{};
  std::size_t next_count{};
  std::size_t next_alternate_count{};

  // Reject non-canonical networks and invalid lengths before considering route
  // activity. Silent normalization would make CLI info differ from the key
  // actually installed in the forwarding table.
  const auto connected_valid = [](const auto &entries) noexcept {
    return std::all_of(entries.begin(), entries.end(), [](const auto &entry) {
      const bool system = entry.interface_id == lab::system_interface_id;
      return !entry.configured ||
             (entry.interface_id != 0U &&
              (system
                   ? entry.physical_port_ordinal ==
                             lab::system_interface_port_ordinal &&
                         entry.prefix_length == ip::ipv6_address_bits
                   : entry.physical_port_ordinal <
                         device_catalog::maximum_ports_per_router) &&
              entry.prefix_length <= ip::ipv6_address_bits &&
              ip::mask(entry.network, entry.prefix_length) == entry.network);
    });
  };
  if (!connected_valid(connected) || !connected_valid(additional_connected) ||
      maximum_ecmp_paths == 0U ||
      maximum_ecmp_paths > device_catalog::maximum_ecmp_paths) {
    last_rebuild_valid_ = false;
    return false;
  }
  for (const auto &entry : statics) {
    if (entry.configured &&
        (entry.prefix_length > ip::ipv6_address_bits ||
         ip::is_unspecified(entry.next_hop) ||
         ip::mask(entry.network, entry.prefix_length) != entry.network ||
         (entry.indirect &&
          (ip::is_link_local(entry.next_hop) ||
           entry.outgoing_interface_set)) ||
         (!entry.indirect && ip::is_link_local(entry.next_hop) &&
          (!entry.outgoing_interface_set ||
           entry.outgoing_interface_id == 0U)))) {
      last_rebuild_valid_ = false;
      return false;
    }
  }
  const auto eligible_alternates =
      static_cast<std::size_t>(std::count_if(
          dynamic.begin(), dynamic.end(), [](const auto &entry) {
            return entry.configured && entry.operational &&
                   entry.loop_free_alternate;
          }));
  if (eligible_alternates >
      device_catalog::maximum_fib_routes_per_router) {
    last_rebuild_valid_ = false;
    return false;
  }
  for (const auto &entry : dynamic) {
    if (entry.configured &&
        (entry.interface_id == 0U ||
         entry.physical_port_ordinal >=
             device_catalog::maximum_ports_per_router ||
         entry.prefix_length > ip::ipv6_address_bits ||
         ip::mask(entry.network, entry.prefix_length) != entry.network ||
         ip::is_unspecified(entry.next_hop) ||
         ip::is_multicast(entry.next_hop) ||
         !valid_dynamic(entry.source, entry.ospf_path_type))) {
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
                                     .prefix_length = entry.prefix_length,
                                     .preference = 0U,
                                     .metric = 0U,
                                     .source = RouteSource::connected};
    }
    return true;
  };
  if (!append_connected(connected) ||
      !append_connected(additional_connected)) {
    last_rebuild_valid_ = false;
    return false;
  }

  for (const auto &entry : dynamic) {
    if (!entry.configured || !entry.operational ||
        entry.loop_free_alternate)
      continue;
    const bool type_two =
        entry.ospf_path_type == OspfPathType::external_type_2 ||
        entry.ospf_path_type == OspfPathType::nssa_type_2;
    const bool dominated =
        type_two &&
        std::any_of(dynamic.begin(), dynamic.end(), [&](const auto &other) {
          return other.configured && other.operational &&
                 !other.loop_free_alternate &&
                 other.network == entry.network &&
                 other.prefix_length == entry.prefix_length &&
                 other.preference == entry.preference &&
                 other.source == entry.source &&
                 other.ospf_path_type == entry.ospf_path_type &&
                 other.protocol_instance == entry.protocol_instance &&
                 other.metric == entry.metric &&
                 other.internal_metric < entry.internal_metric;
        });
    if (dominated)
      continue;
    if (next_count == next.size()) {
      last_rebuild_valid_ = false;
      return false;
    }
    next[next_count++] = Ipv6Route{
        .network = entry.network,
        .next_hop = entry.next_hop,
        .interface_id = entry.interface_id,
        .physical_port_ordinal = entry.physical_port_ordinal,
        .prefix_length = entry.prefix_length,
        .preference = entry.preference,
        .metric = entry.metric,
        .source = entry.source,
        .ospf_path_type = entry.ospf_path_type,
        .protocol_instance = entry.protocol_instance};
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
    if (!entry.indirect) {
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
          .prefix_length = entry.prefix_length,
          .preference = 5U,
          .metric = 1U,
          .source = RouteSource::static_route};
      continue;
    }

    // Link-local indirect addresses are not meaningful without a scoped
    // protocol resolver. The configured zone is used to constrain dynamic
    // candidates exactly as it constrains direct Neighbor Discovery.
    const Ipv6DynamicInput *best{};
    for (const auto &candidate : dynamic) {
      if (!candidate.configured || !candidate.operational)
        continue;
      if (candidate.loop_free_alternate)
        continue;
      if (ip::is_link_local(entry.next_hop) &&
          candidate.interface_id != entry.outgoing_interface_id)
        continue;
      const ip::Ipv6Prefix candidate_prefix{candidate.network,
                                             candidate.prefix_length};
      if (!ip::contains(candidate_prefix, entry.next_hop))
        continue;
      if (!best || candidate.prefix_length > best->prefix_length ||
          (candidate.prefix_length == best->prefix_length &&
           (candidate.preference < best->preference ||
            (candidate.preference == best->preference &&
             candidate.metric < best->metric))))
        best = &candidate;
    }
    if (!best)
      continue;
    for (const auto &candidate : dynamic) {
      if (!candidate.configured || !candidate.operational ||
          candidate.loop_free_alternate ||
          candidate.prefix_length != best->prefix_length ||
          candidate.preference != best->preference ||
          candidate.metric != best->metric ||
          (ip::is_link_local(entry.next_hop) &&
           candidate.interface_id != entry.outgoing_interface_id))
        continue;
      const ip::Ipv6Prefix candidate_prefix{candidate.network,
                                             candidate.prefix_length};
      if (!ip::contains(candidate_prefix, entry.next_hop))
        continue;
      if (next_count == next.size()) {
        last_rebuild_valid_ = false;
        return false;
      }
      next[next_count++] = Ipv6Route{
          .network = entry.network,
          .next_hop = candidate.next_hop,
          .interface_id = candidate.interface_id,
          .physical_port_ordinal = candidate.physical_port_ordinal,
          .prefix_length = entry.prefix_length,
          .preference = 5U,
          .metric = 1U,
          .source = RouteSource::static_route};
    }
  }

  const auto address_less = [](const ip::Ipv6 &left,
                               const ip::Ipv6 &right) noexcept {
    return std::lexicographical_compare(left.begin(), left.end(), right.begin(),
                                        right.end());
  };
  std::sort(next.begin(), next.begin() + next_count,
            [&](const Ipv6Route &left, const Ipv6Route &right) {
              if (left.network != right.network)
                return address_less(left.network, right.network);
              if (left.prefix_length != right.prefix_length)
                return left.prefix_length > right.prefix_length;
              if (!same_selection_class(left, right))
                return selection_less(left, right);
              if (left.next_hop != right.next_hop)
                return address_less(left.next_hop, right.next_hop);
              return left.interface_id < right.interface_id;
            });
  // IPv6 routes are larger values than IPv4 routes. In-place compaction keeps
  // a rebuild bounded to one scratch array and avoids stack growth as hardware
  // profiles expose more physical ports.
  std::size_t selected_count{};
  for (std::size_t begin{}; begin < next_count;) {
    std::size_t end = begin + 1U;
    while (end < next_count && next[end].network == next[begin].network &&
           next[end].prefix_length == next[begin].prefix_length)
      ++end;
    const auto &winner = next[begin];
    std::uint16_t paths{};
    for (std::size_t index = begin;
         index < end && paths < maximum_ecmp_paths; ++index) {
      const auto &candidate = next[index];
      if (!same_selection_class(candidate, winner))
        break;
      next[selected_count++] = candidate;
      ++paths;
    }
    begin = end;
  }
  next_count = selected_count;

  // All validation and primary resolution has completed. Reusing the table's
  // repair owner is now non-fallible: every accepted dynamic row was validated
  // above, and the fixed capacity is checked before each write. Identical
  // non-empty repair generations are conservatively republished because their
  // previous bytes are intentionally overwritten instead of copied.
  auto &next_alternates = loop_free_alternates_;
  const auto previous_alternate_count = loop_free_alternate_count_;
  for (const auto &entry : dynamic) {
    if (!entry.configured || !entry.operational ||
        !entry.loop_free_alternate)
      continue;
    next_alternates[next_alternate_count++] = Ipv6Route{
        .network = entry.network,
        .next_hop = entry.next_hop,
        .interface_id = entry.interface_id,
        .physical_port_ordinal = entry.physical_port_ordinal,
        .prefix_length = entry.prefix_length,
        .preference = entry.preference,
        .metric = entry.metric,
        .source = entry.source,
        .ospf_path_type = entry.ospf_path_type,
        .protocol_instance = entry.protocol_instance};
  }
  std::sort(
      next_alternates.begin(),
      next_alternates.begin() + next_alternate_count,
      [](const Ipv6Route &left, const Ipv6Route &right) {
        return std::tie(left.network, left.prefix_length, left.next_hop,
                        left.interface_id) <
               std::tie(right.network, right.prefix_length, right.next_hop,
                        right.interface_id);
      });
  next_alternate_count = static_cast<std::size_t>(std::distance(
      next_alternates.begin(),
      std::unique(
          next_alternates.begin(),
          next_alternates.begin() + next_alternate_count,
          [](const Ipv6Route &left, const Ipv6Route &right) {
            return left.network == right.network &&
                   left.prefix_length == right.prefix_length &&
                   left.next_hop == right.next_hop &&
                   left.interface_id == right.interface_id;
          })));
  std::size_t retained_ipv6_alternates{};
  for (std::size_t index{}; index < next_alternate_count; ++index) {
    const auto &alternate = next_alternates[index];
    const auto primary = std::find_if(
        next.begin(), next.begin() + next_count,
        [&](const auto &candidate) {
          return candidate.network == alternate.network &&
                 candidate.prefix_length == alternate.prefix_length &&
                 candidate.source == alternate.source &&
                 candidate.ospf_path_type == alternate.ospf_path_type &&
                 candidate.protocol_instance ==
                     alternate.protocol_instance;
        });
    if (primary != next.begin() + next_count)
      next_alternates[retained_ipv6_alternates++] = alternate;
  }
  next_alternate_count = retained_ipv6_alternates;
  if (next_count + next_alternate_count > next.size()) {
    last_rebuild_valid_ = false;
    return false;
  }

  const bool changed =
      next_count != count_ ||
      next_alternate_count != previous_alternate_count ||
      next_alternate_count != 0U ||
      !std::equal(next.begin(), next.begin() + next_count, routes_.begin(),
                  [](const Ipv6Route &left, const Ipv6Route &right) {
                    return left.network == right.network &&
                           left.next_hop == right.next_hop &&
                           left.interface_id == right.interface_id &&
                           left.physical_port_ordinal ==
                               right.physical_port_ordinal &&
                           left.prefix_length == right.prefix_length &&
                           left.preference == right.preference &&
                           left.metric == right.metric &&
                           left.source == right.source &&
                           left.ospf_path_type == right.ospf_path_type &&
                           left.protocol_instance == right.protocol_instance;
                  });
  if (changed) {
    routes_ = next;
    count_ = static_cast<std::uint16_t>(next_count);
    loop_free_alternate_count_ =
        static_cast<std::uint16_t>(next_alternate_count);
  }
  last_rebuild_valid_ = true;
  return changed;
}

Ipv6FibProgram Ipv6RouteTable::compile(std::uint64_t generation) const noexcept {
  Ipv6FibProgram result{.generation = generation,
                        .count = count_,
                        .loop_free_alternate_count =
                            loop_free_alternate_count_};
  std::copy_n(routes_.begin(), count_, result.routes.begin());
  std::copy_n(loop_free_alternates_.begin(), loop_free_alternate_count_,
              result.routes.begin() + count_);
  return result;
}

bool lookup(const Ipv6FibProgram &fib, const ip::Ipv6 &destination,
            Ipv6Route &selected, std::uint64_t flow_hash) noexcept {
  const Ipv6Route *best{};
  std::array<const Ipv6Route *, device_catalog::maximum_ecmp_paths> equal{};
  std::size_t equal_count{};
  for (std::size_t index = 0; index < fib.count; ++index) {
    const auto &candidate = fib.routes[index];
    const ip::Ipv6Prefix prefix{.network = candidate.network,
                                .length = candidate.prefix_length};
    if (!ip::contains(prefix, destination))
      continue;
    if (!best || candidate.prefix_length > best->prefix_length) {
      best = &candidate;
      equal[0] = best;
      equal_count = 1U;
    } else if (candidate.prefix_length == best->prefix_length &&
               candidate.network == best->network &&
               same_selection_class(candidate, *best) &&
               equal_count < equal.size()) {
      equal[equal_count++] = &candidate;
    }
  }
  if (!best)
    return false;
  selected = *equal[flow_hash % equal_count];
  return true;
}

bool lookup_loop_free_alternate(const Ipv6FibProgram &fib,
                                const ip::Ipv6 &destination,
                                Ipv6Route &selected,
                                std::uint64_t flow_hash) noexcept {
  const Ipv6Route *best{};
  std::array<const Ipv6Route *, device_catalog::maximum_ecmp_paths> equal{};
  std::size_t equal_count{};
  for (std::size_t index{}; index < fib.loop_free_alternate_count; ++index) {
    const auto &candidate = fib.routes[fib.count + index];
    if (!ip::contains(
            {.network = candidate.network,
             .length = candidate.prefix_length},
            destination))
      continue;
    if (!best || candidate.prefix_length > best->prefix_length) {
      best = &candidate;
      equal[0U] = best;
      equal_count = 1U;
    } else if (candidate.prefix_length == best->prefix_length &&
               candidate.network == best->network &&
               equal_count < equal.size()) {
      equal[equal_count++] = &candidate;
    }
  }
  if (!best)
    return false;
  selected = *equal[flow_hash % equal_count];
  return true;
}

} // namespace router::lab::routing
