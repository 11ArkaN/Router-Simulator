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
    if (entry.configured && entry.prefix_length > 32U) {
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
        .prefix_length = entry.prefix_length};
  }

  for (const auto &entry : statics) {
    if (!entry.configured)
      continue;
    const ConnectedInput *resolution{};
    for (const auto &candidate : connected) {
      if (!candidate.configured || !candidate.operational)
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
        .prefix_length = entry.prefix_length};
  }

  const bool changed =
      next_count != count_ ||
      !std::equal(next.begin(), next.begin() + next_count, routes_.begin(),
                  [](const Route &left, const Route &right) {
                    return left.network == right.network &&
                           left.next_hop == right.next_hop &&
                           left.port_ordinal == right.port_ordinal &&
                           left.prefix_length == right.prefix_length;
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

} // namespace router::lab::routing
