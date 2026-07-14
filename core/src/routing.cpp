// Connected and static route selection plus contiguous longest-prefix lookup.
// Control owns the RIB and publishes complete FIB generations by value.

#include "router/routing.hpp"

#include <algorithm>

namespace router::routing {
bool ConnectedRib::rebuild(const DeviceState& device) noexcept {
  // Connected routes are derived only from operational routed interfaces.
  // Removing a card, MDA, signal, or interface therefore withdraws the route
  // through the same dependency chain instead of a special failure shortcut.
  std::array<Route, 8> next{};
  std::uint8_t next_count = 0;
  if (device.interface_operational(0)) {
    next[next_count++] = {profile::router_networks[0], profile::host_prefix_lengths[0], 0, 0};
  }
  if (device.interface_operational(1)) {
    next[next_count++] = {profile::router_networks[1], profile::host_prefix_lengths[1], 1, 0};
  }
  for (const auto& route : device.static_routes) {
    if (!route.valid || next_count == next.size()) continue;
    for (std::uint8_t port = 0; port < device.interfaces.size(); ++port) {
      const auto mask = prefix_mask(profile::host_prefix_lengths[port]);
      if (device.interface_operational(port) &&
          (route.next_hop & mask) == profile::router_networks[port]) {
        next[next_count++] = {route.network, route.prefix_length, port, route.next_hop};
        break;
      }
    }
  }
  // Compare before assignment so callers program forwarding only when the RIB
  // content really changes. This keeps failure flaps cheap at shard boundaries.
  const bool changed = next_count != count_ ||
                       !std::equal(next.begin(), next.begin() + next_count, entries_.begin(),
                                   [](const Route& a, const Route& b) {
                                     return a.network == b.network &&
                                            a.prefix_length == b.prefix_length &&
                                            a.port_index == b.port_index &&
                                            a.next_hop == b.next_hop;
                                   });
  entries_ = next;
  count_ = next_count;
  return changed;
}

FibProgram ConnectedRib::compile(std::uint64_t generation) const noexcept {
  // Compilation creates an immutable snapshot. The forwarding owner can replace
  // its table in one assignment without reading live control-plane storage.
  FibProgram program{.generation = generation, .count = count_};
  std::copy_n(entries_.begin(), count_, program.entries.begin());
  for (const auto& route : entries()) program.port_operational[route.port_index] = true;
  return program;
}

bool lookup(const FibProgram& fib, std::uint32_t destination,
            std::uint8_t& port_index, std::uint32_t* next_hop) noexcept {
  // The small milestone table favors a contiguous scan. A trie would add memory
  // and branches without a measured gain at this route count. The API permits a
  // later implementation change without touching packet forwarding callers.
  const Route* best = nullptr;
  for (std::size_t i = 0; i < fib.count; ++i) {
    const auto& route = fib.entries[i];
    if ((destination & prefix_mask(route.prefix_length)) != route.network) continue;
    // Selecting the longest matching prefix is required even when connected
    // routes overlap with more general routes added in a later milestone.
    if (!best || route.prefix_length > best->prefix_length) best = &route;
  }
  if (!best) return false;
  port_index = best->port_index;
  if (next_hop) *next_hop = best->next_hop;
  return true;
}

}  // namespace router::routing
