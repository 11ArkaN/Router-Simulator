// Multi-device connected, static and protocol route selection. Each router runs this
// independently from its local configuration and never inspects the lab graph.

#include "router/multi_device_routing.hpp"
#include "router/routing_selected_candidates.hpp"

#include <algorithm>
#include <tuple>
#include <type_traits>
#include <climits>
#include <iterator>

namespace router::lab::routing {
namespace {


// Two immutable owner-retained protocol generations share one bounded input
// view. No concatenation, allocation or pointer subtraction crosses arenas.
// The caller keeps both spans alive throughout the synchronous rebuild.
template <typename Entry>
struct DynamicView {
  std::span<const Entry> first, second;
  [[nodiscard]] std::size_t size() const noexcept { return first.size() + second.size(); }
  [[nodiscard]] const Entry &operator[](std::size_t index) const noexcept {
    return index < first.size() ? first[index] : second[index - first.size()];
  }
  struct Iterator {
    using iterator_category = std::forward_iterator_tag;
    using value_type = Entry;
    using difference_type = std::ptrdiff_t;
    using pointer = const Entry *;
    using reference = const Entry &;
    const DynamicView *view{};
    std::size_t index{};
    reference operator*() const noexcept { return (*view)[index]; }
    pointer operator->() const noexcept { return &**this; }
    Iterator &operator++() noexcept { ++index; return *this; }
    Iterator operator++(int) noexcept { auto old = *this; ++*this; return old; }
    bool operator==(const Iterator &) const = default;
  };
  Iterator begin() const noexcept { return {this, 0U}; }
  Iterator end() const noexcept { return {this, size()}; }
};

template <typename RouteValue>
[[nodiscard]] constexpr std::uint16_t default_preference(const RouteValue &route) noexcept {
  switch (route.source) {
  case RouteSource::connected: return 0U;
  case RouteSource::static_route: return 5U;
  case RouteSource::ospf:
  case RouteSource::ospf3:
    return route.ospf_path_type == OspfPathType::intra_area ||
        route.ospf_path_type == OspfPathType::inter_area ? 10U : 150U;
  case RouteSource::isis:
    switch (route.isis_path_type) {
    case IsisPathType::level1_internal: return 15U;
    case IsisPathType::level2_internal: return 18U;
    case IsisPathType::level1_external: return 160U;
    case IsisPathType::level2_external: return 165U;
    case IsisPathType::none: return 255U;
    }
  }
  return 255U;
}

template <typename RouteValue>
[[nodiscard]] constexpr bool secondary_metric(const RouteValue &route) noexcept {
  return route.ospf_path_type == OspfPathType::external_type_2 ||
      route.ospf_path_type == OspfPathType::nssa_type_2 ||
      (std::is_integral_v<decltype(route.network)> && route.source == RouteSource::isis && route.isis_rank >= 3U);
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
  if (left.source != right.source) return left.source < right.source;
  if (left.preference != right.preference) return left.preference < right.preference;
  if (left.source == RouteSource::isis && left.isis_rank != right.isis_rank)
    return left.isis_rank < right.isis_rank;
  if (path_rank(left.ospf_path_type) != path_rank(right.ospf_path_type))
    return path_rank(left.ospf_path_type) < path_rank(right.ospf_path_type);
  if (left.metric != right.metric)
    return left.metric < right.metric;
  // RFC 2328 section 16.4 uses internal cost as the tie-break among otherwise
  // equal Type 2 routes. It is harmlessly zero for non-OSPF and non-Type-2
  // candidates, whose complete cost is already stored in metric.
  if constexpr (requires { left.internal_metric; }) {
    if (secondary_metric(left) && left.internal_metric != right.internal_metric)
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

// Compare protocols only after each protocol has selected its own winning
// paths. The default preference table applies to different protocols, not to
// competing paths inside one protocol. Equal protocol paths share one minimum
// default priority so mixed internal/external provenance cannot create a
// non-transitive sort comparator or split their ECMP membership.
template <typename RouteValue>
std::size_t select_routes(std::span<RouteValue> rows, std::uint16_t width) noexcept {
  std::sort(rows.begin(), rows.end(), [](const auto &left, const auto &right) {
    if (left.network != right.network) return left.network < right.network;
    if (left.prefix_length != right.prefix_length) return left.prefix_length > right.prefix_length;
    if (left.source != right.source) return left.source < right.source;
    if (!same_selection_class(left, right)) return selection_less(left, right);
    if (left.next_hop != right.next_hop) return left.next_hop < right.next_hop;
    if constexpr (requires { left.port_ordinal; })
      return std::tie(left.port_ordinal, left.interface_id) < std::tie(right.port_ordinal, right.interface_id);
    else return left.interface_id < right.interface_id;
  });
  std::size_t written{};
  for (std::size_t begin{}; begin < rows.size();) {
    auto end = begin + 1U;
    while (end < rows.size() && rows[end].network == rows[begin].network &&
        rows[end].prefix_length == rows[begin].prefix_length) ++end;
    auto best_begin = begin, best_end = begin;
    auto best_key = std::tuple{UINT16_MAX, UINT16_MAX, RouteSource::isis};
    for (auto source = begin; source < end;) {
      auto source_end = source + 1U;
      while (source_end < end && rows[source_end].source == rows[source].source) ++source_end;
      auto equal_end = source + 1U;
      auto priority = default_preference(rows[source]);
      while (equal_end < source_end && same_selection_class(rows[equal_end], rows[source])) {
        priority = std::min(priority, default_preference(rows[equal_end]));
        ++equal_end;
      }
      const auto key = std::tuple{rows[source].preference, priority, rows[source].source};
      if (key < best_key) { best_key = key; best_begin = source; best_end = equal_end; }
      source = source_end;
    }
    for (auto index = best_begin; index < best_end && index - best_begin < width; ++index)
      rows[written++] = rows[index];
    begin = end;
  }
  return written;
}

template <typename Entry, typename Eligible>
const Entry *best_dynamic_route(DynamicView<Entry> input, std::span<const bool> selected_isis,
    Eligible eligible) noexcept {
  constexpr auto sources = static_cast<std::size_t>(RouteSource::isis) + 1U;
  std::array<const Entry *, sources> best{};
  std::array<std::uint16_t, sources> priority{};
  for (std::size_t index{}; index < input.size(); ++index) {
    const auto &entry = input[index];
    if (!entry.configured || !entry.operational || entry.loop_free_alternate ||
        (entry.source == RouteSource::isis && !selected_isis[index]) || !eligible(entry)) continue;
    const auto source = static_cast<std::size_t>(entry.source);
    auto &selected = best[source];
    if (!selected || entry.prefix_length > selected->prefix_length ||
        (entry.prefix_length == selected->prefix_length && selection_less(entry, *selected))) {
      selected = &entry;
      priority[source] = default_preference(entry);
    } else if (entry.prefix_length == selected->prefix_length && same_selection_class(entry, *selected))
      priority[source] = std::min(priority[source], default_preference(entry));
  }
  const Entry *selected{};
  auto selected_key = std::tuple{INT_MAX, UINT16_MAX, UINT16_MAX, RouteSource::isis};
  for (std::size_t source{}; source < best.size(); ++source) if (best[source]) {
    const auto &entry = *best[source];
    const auto key = std::tuple{-static_cast<int>(entry.prefix_length), entry.preference, priority[source], entry.source};
    if (key < selected_key) { selected_key = key; selected = &entry; }
  }
  return selected;
}

// Prune structured IS-IS distances before global preference. Combining both
// orders in one comparator would create cycles across protocol candidates.
// Fixed index scratch bounds memory and avoids quadratic prefix comparisons.
template <typename Entry>
[[nodiscard]] auto isis_distance_key(const Entry &entry) noexcept {
  const auto secondary = std::is_integral_v<decltype(entry.network)> && entry.isis_rank >= 3U
      ? entry.internal_metric : 0U;
  return std::tuple{entry.isis_rank, entry.metric, secondary};
}
template <typename Entry>
[[nodiscard]] auto isis_prefix_key(const Entry &entry) noexcept {
  if constexpr (std::is_integral_v<decltype(entry.network)>)
    return std::tuple{entry.network & prefix_mask(entry.prefix_length), entry.prefix_length, entry.protocol_instance};
  else return std::tuple{entry.network, entry.prefix_length, entry.protocol_instance};
}
template <typename Entry>
void select_isis_distances(DynamicView<Entry> input, std::span<bool> selected) noexcept {
  static_assert(device_catalog::maximum_dynamic_routes_per_router <= UINT16_MAX);
  std::array<std::uint16_t, device_catalog::maximum_dynamic_routes_per_router> indices{};
  std::size_t count{};
  for (std::size_t index{}; index < input.size(); ++index)
    if (input[index].source == RouteSource::isis && input[index].configured &&
        input[index].operational && !input[index].loop_free_alternate)
      indices[count++] = static_cast<std::uint16_t>(index);
  std::sort(indices.begin(), indices.begin() + count, [&](auto left, auto right) {
    const auto a = isis_prefix_key(input[left]), b = isis_prefix_key(input[right]);
    return a != b ? a < b : isis_distance_key(input[left]) < isis_distance_key(input[right]);
  });
  for (std::size_t begin{}; begin < count;) {
    auto end = begin + 1U;
    const auto key = isis_prefix_key(input[indices[begin]]);
    const auto distance = isis_distance_key(input[indices[begin]]);
    selected[indices[begin]] = true;
    while (end < count && isis_prefix_key(input[indices[end]]) == key) {
      selected[indices[end]] = isis_distance_key(input[indices[end]]) == distance;
      ++end;
    }
    begin = end;
  }
}

template <typename Entry>
bool select_projection_candidates(std::span<const Entry> first, std::span<const Entry> second,
    std::span<bool> output) noexcept {
  constexpr auto capacity = device_catalog::maximum_dynamic_routes_per_router;
  if (first.size() > capacity || second.size() > capacity - first.size() || output.size() != first.size() + second.size()) return false;
  const DynamicView<Entry> input{first, second};
  constexpr bool ipv6 = std::is_same_v<Entry, Ipv6DynamicInput>;
  for (const auto &entry : input)
    if (entry.configured && entry.source == RouteSource::isis && entry.prefix_length > (ipv6 ? 128U : 32U)) return false;
  std::fill(output.begin(), output.end(), false);
  select_isis_distances(input, output);
  return true;
}

template <typename Program, typename Entry>
void compile_routes(Program &output, std::uint64_t generation,
    std::span<const Entry> primary, std::span<const Entry> repairs, bool reset_unused = true) noexcept {
  output.generation = generation;
  output.count = static_cast<std::uint16_t>(primary.size());
  output.loop_free_alternate_count = static_cast<std::uint16_t>(repairs.size());
  if (reset_unused) std::fill(output.routes.begin(), output.routes.end(), Entry{});
  std::copy(primary.begin(), primary.end(), output.routes.begin());
  std::copy(repairs.begin(), repairs.end(), output.routes.begin() + primary.size());
}
} // namespace

bool select_isis_candidates(std::span<const DynamicInput> first, std::span<const DynamicInput> second,
    std::span<bool> output) noexcept { return select_projection_candidates(first, second, output); }
bool select_isis_candidates(std::span<const Ipv6DynamicInput> first, std::span<const Ipv6DynamicInput> second,
    std::span<bool> output) noexcept { return select_projection_candidates(first, second, output); }

bool RouteTable::rebuild(std::span<const ConnectedInput> connected,
                         std::span<const StaticInput> statics,
                         std::span<const DynamicInput> primary_dynamic,
                         std::uint16_t maximum_ecmp_paths,
                         std::span<const DynamicInput> additional_dynamic) noexcept {
  const DynamicView<DynamicInput> dynamic{primary_dynamic, additional_dynamic};
  std::array<Route, device_catalog::maximum_fib_routes_per_router> next{};
  std::array<Route, device_catalog::maximum_fib_routes_per_router>
      next_alternates{};
  std::size_t next_count{};
  std::size_t next_alternate_count{};
  if (primary_dynamic.size() > device_catalog::maximum_dynamic_routes_per_router ||
      additional_dynamic.size() > device_catalog::maximum_dynamic_routes_per_router - primary_dynamic.size()) {
    last_rebuild_valid_ = false;
    return false;
  }

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
         (entry.source == RouteSource::isis && (!entry.interface_id || !entry.interface_generation ||
          entry.protocol_instance > device_catalog::isis_instance_last ||
          entry.preference == 0U || entry.preference > 255U)) ||
         entry.port_ordinal >= device_catalog::maximum_ports_per_router ||
         (!dynamic_source(entry.source) || !valid_route_path(entry.source, entry.ospf_path_type, entry.isis_path_type, entry.isis_rank, false)))) {
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
        .local_system = entry.local_system, .interface_id = entry.interface_id,
        .interface_generation = entry.interface_generation};
  }

  std::array<bool, device_catalog::maximum_dynamic_routes_per_router> selected_isis{};
  select_isis_distances(dynamic, std::span{selected_isis}.first(dynamic.size()));
  // Dynamic candidates are already resolved to a physical adjacency by their
  // protocol owner. Keeping that publication separate from static intent is
  // what lets indirect resolution exclude static-to-static recursion.
  for (std::size_t dynamic_index{}; dynamic_index < dynamic.size(); ++dynamic_index) {
      const auto &entry = dynamic[dynamic_index];
    if (!entry.configured || !entry.operational ||
        entry.loop_free_alternate)
      continue;
    // Type 2 external routes first compare the external metric, then the cost
    // to the ASBR. The FIB does not need that second control-plane quantity,
    // so discard only dominated Type 2 candidates before creating compact FIB
    // rows. Equal internal costs remain available for ECMP.
    if (entry.source == RouteSource::isis &&
        !selected_isis[dynamic_index]) continue;
    const bool type_two = secondary_metric(entry);
    const bool dominated =
        type_two && entry.source != RouteSource::isis &&
        std::any_of(dynamic.begin(), dynamic.end(), [&](const auto &other) {
          return other.configured && other.operational &&
                 !other.loop_free_alternate &&
                 other.network == entry.network &&
                 other.prefix_length == entry.prefix_length &&
                 other.preference == entry.preference &&
                 other.source == entry.source &&
                 other.ospf_path_type == entry.ospf_path_type &&
                 other.isis_path_type == entry.isis_path_type && other.isis_rank == entry.isis_rank &&
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
        .protocol_instance = entry.protocol_instance,
        .interface_id = entry.interface_id,
        .isis_path_type = entry.isis_path_type, .isis_rank = entry.isis_rank,
        .interface_generation = entry.interface_generation};
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
                 candidate.isis_path_type == entry.isis_path_type && candidate.isis_rank == entry.isis_rank &&
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
        .protocol_instance = entry.protocol_instance,
        .interface_id = entry.interface_id,
        .isis_path_type = entry.isis_path_type, .isis_rank = entry.isis_rank,
        .interface_generation = entry.interface_generation};
  }
  std::sort(
      next_alternates.begin(),
      next_alternates.begin() + next_alternate_count,
      [](const Route &left, const Route &right) {
        return std::tie(left.network, left.prefix_length, left.next_hop,
                        left.port_ordinal, left.interface_id) <
               std::tie(right.network, right.prefix_length, right.next_hop,
                        right.port_ordinal, right.interface_id);
      });
  next_alternate_count = static_cast<std::size_t>(std::distance(
      next_alternates.begin(),
      std::unique(next_alternates.begin(),
                  next_alternates.begin() + next_alternate_count,
                  [](const Route &left, const Route &right) {
                    return left.network == right.network &&
                           left.prefix_length == right.prefix_length &&
                           left.next_hop == right.next_hop &&
                           left.port_ordinal == right.port_ordinal && left.interface_id == right.interface_id;
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
          .local_system = false, .interface_id = resolution->interface_id,
          .interface_generation = resolution->interface_generation};
      continue;
    }

    // Find the best dynamic route covering the indirect address. Prefix
    // length wins first, then protocol preference and metric. Every equal
    // resolved path is expanded into the static route's own ECMP candidates.
    const auto *best = best_dynamic_route(dynamic, std::span<const bool>{selected_isis}.first(dynamic.size()),
        [&](const auto &candidate) {
          const auto mask = prefix_mask(candidate.prefix_length);
          return (entry.next_hop & mask) == (candidate.network & mask);
        });
    if (!best)
      continue;
    for (std::size_t dynamic_index{}; dynamic_index < dynamic.size(); ++dynamic_index) {
      const auto &candidate = dynamic[dynamic_index];
      if (candidate.source == RouteSource::isis &&
          !selected_isis[dynamic_index]) continue;
      if (!candidate.configured || !candidate.operational ||
          candidate.loop_free_alternate ||
          candidate.prefix_length != best->prefix_length ||
          !same_selection_class(candidate, *best))
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
          .local_system = false, .interface_id = candidate.interface_id,
          .interface_generation = candidate.interface_generation};
    }
  }

  next_count = select_routes(std::span{next}.first(next_count), maximum_ecmp_paths);

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
                 candidate.isis_path_type == alternate.isis_path_type && candidate.isis_rank == alternate.isis_rank &&
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
                  [](const Route &left, const Route &right) { return left == right; }) ||
      !std::equal(
          next_alternates.begin(),
          next_alternates.begin() + next_alternate_count,
          loop_free_alternates_.begin(),
          [](const Route &left, const Route &right) { return left == right; });
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
  FibProgram output;
  compile_routes(output, generation, std::span{routes_}.first(count_),
      std::span{loop_free_alternates_}.first(loop_free_alternate_count_), false);
  return output;
}
void RouteTable::compile_into(FibProgram &output, std::uint64_t generation) const noexcept {
  compile_routes(output, generation, std::span{routes_}.first(count_),
      std::span{loop_free_alternates_}.first(loop_free_alternate_count_));
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
    std::span<const Ipv6DynamicInput> primary_dynamic,
    std::uint16_t maximum_ecmp_paths,
    std::span<const Ipv6DynamicInput> additional_dynamic) noexcept {
  const DynamicView<Ipv6DynamicInput> dynamic{primary_dynamic, additional_dynamic};
  // One bounded primary generation remains automatic storage. Repairs are
  // staged later in their existing owner array only after every fallible
  // primary calculation has succeeded. This avoids both the former second
  // stack array and a heap allocation that could fail at the configured Wasm
  // memory ceiling during a large laboratory.
  std::array<Ipv6Route,
             device_catalog::maximum_fib_routes_per_router> next{};
  std::size_t next_count{};
  std::size_t next_alternate_count{};
  if (primary_dynamic.size() > device_catalog::maximum_dynamic_routes_per_router ||
      additional_dynamic.size() > device_catalog::maximum_dynamic_routes_per_router - primary_dynamic.size()) {
    last_rebuild_valid_ = false;
    return false;
  }

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
        ((entry.source == RouteSource::isis && (!entry.interface_generation ||
          entry.protocol_instance > device_catalog::isis_instance_last ||
          entry.preference == 0U || entry.preference > 255U)) || entry.interface_id == 0U ||
         entry.physical_port_ordinal >=
             device_catalog::maximum_ports_per_router ||
         entry.prefix_length > ip::ipv6_address_bits ||
         ip::mask(entry.network, entry.prefix_length) != entry.network ||
         ip::is_unspecified(entry.next_hop) ||
         ip::is_multicast(entry.next_hop) ||
         (!dynamic_source(entry.source) || !valid_route_path(entry.source, entry.ospf_path_type, entry.isis_path_type, entry.isis_rank, true)))) {
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
                                     .source = RouteSource::connected,
                                     .interface_generation = entry.interface_generation};
    }
    return true;
  };
  if (!append_connected(connected) ||
      !append_connected(additional_connected)) {
    last_rebuild_valid_ = false;
    return false;
  }

  std::array<bool, device_catalog::maximum_dynamic_routes_per_router> selected_isis{};
  select_isis_distances(dynamic, std::span{selected_isis}.first(dynamic.size()));
  for (std::size_t dynamic_index{}; dynamic_index < dynamic.size(); ++dynamic_index) {
      const auto &entry = dynamic[dynamic_index];
    if (!entry.configured || !entry.operational ||
        entry.loop_free_alternate)
      continue;
    if (entry.source == RouteSource::isis &&
        !selected_isis[dynamic_index]) continue;
    const bool type_two = secondary_metric(entry);
    const bool dominated =
        type_two && entry.source != RouteSource::isis &&
        std::any_of(dynamic.begin(), dynamic.end(), [&](const auto &other) {
          return other.configured && other.operational &&
                 !other.loop_free_alternate &&
                 other.network == entry.network &&
                 other.prefix_length == entry.prefix_length &&
                 other.preference == entry.preference &&
                 other.source == entry.source &&
                 other.ospf_path_type == entry.ospf_path_type &&
                 other.isis_path_type == entry.isis_path_type && other.isis_rank == entry.isis_rank &&
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
        .protocol_instance = entry.protocol_instance,
        .isis_path_type = entry.isis_path_type, .isis_rank = entry.isis_rank,
        .interface_generation = entry.interface_generation};
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
          .source = RouteSource::static_route,
          .interface_generation = resolution->interface_generation};
      continue;
    }

    // Link-local indirect addresses are not meaningful without a scoped
    // protocol resolver. The configured zone is used to constrain dynamic
    // candidates exactly as it constrains direct Neighbor Discovery.
    const auto *best = best_dynamic_route(dynamic, std::span<const bool>{selected_isis}.first(dynamic.size()),
        [&](const auto &candidate) {
          if (ip::is_link_local(entry.next_hop) && candidate.interface_id != entry.outgoing_interface_id)
            return false;
          return ip::contains(ip::Ipv6Prefix{candidate.network, candidate.prefix_length}, entry.next_hop);
        });
    if (!best)
      continue;
    for (std::size_t dynamic_index{}; dynamic_index < dynamic.size(); ++dynamic_index) {
      const auto &candidate = dynamic[dynamic_index];
      if (candidate.source == RouteSource::isis &&
          !selected_isis[dynamic_index]) continue;
      if (!candidate.configured || !candidate.operational ||
          candidate.loop_free_alternate ||
          candidate.prefix_length != best->prefix_length ||
          !same_selection_class(candidate, *best) ||
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
          .source = RouteSource::static_route,
          .interface_generation = candidate.interface_generation};
    }
  }

  next_count = select_routes(std::span{next}.first(next_count), maximum_ecmp_paths);

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
        .protocol_instance = entry.protocol_instance,
        .isis_path_type = entry.isis_path_type, .isis_rank = entry.isis_rank,
        .interface_generation = entry.interface_generation};
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
                 candidate.isis_path_type == alternate.isis_path_type && candidate.isis_rank == alternate.isis_rank &&
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
                  [](const Ipv6Route &left, const Ipv6Route &right) { return left == right; });
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
  Ipv6FibProgram output;
  compile_routes(output, generation, std::span{routes_}.first(count_),
      std::span{loop_free_alternates_}.first(loop_free_alternate_count_), false);
  return output;
}
void Ipv6RouteTable::compile_into(Ipv6FibProgram &output, std::uint64_t generation) const noexcept {
  compile_routes(output, generation, std::span{routes_}.first(count_),
      std::span{loop_free_alternates_}.first(loop_free_alternate_count_));
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

bool RouteTable::same_selection(const RouteTable &other) const noexcept {
  return count_ == other.count_ &&
      loop_free_alternate_count_ == other.loop_free_alternate_count_ &&
      std::equal(routes_.begin(), routes_.begin() + count_, other.routes_.begin()) &&
      std::equal(loop_free_alternates_.begin(),
                 loop_free_alternates_.begin() + loop_free_alternate_count_,
                 other.loop_free_alternates_.begin());
}

bool Ipv6RouteTable::same_selection(const Ipv6RouteTable &other) const noexcept {
  return count_ == other.count_ &&
      loop_free_alternate_count_ == other.loop_free_alternate_count_ &&
      std::equal(routes_.begin(), routes_.begin() + count_, other.routes_.begin()) &&
      std::equal(loop_free_alternates_.begin(),
                 loop_free_alternates_.begin() + loop_free_alternate_count_,
                 other.loop_free_alternates_.begin());
}

} // namespace router::lab::routing
