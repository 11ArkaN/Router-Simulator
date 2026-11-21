// Local adjacency seeds belong to the instance control owner. This value
// adapter maps accepted Up peers into an immutable LSDB graph without reading
// remote runtime state. It owns no adjacency, timer or forwarding catalog.

// Source: iso.10589.2002.lsdb_link_graph

#pragma once

#include "router/isis_link_graph.hpp"
#include "router/isis_spf.hpp"

#include <algorithm>

namespace router::isis {
struct P2pSpfSeed {
  packet::isis::SystemId peer{};
  std::uint32_t metric{};
  std::uint16_t first_hop{};
};
enum class SeedStatus : std::uint8_t { applied, invalid, capacity };
struct SeedResult { SeedStatus status{}; std::size_t count{}; };
// Requires same-level, same-MT accepted Up P2P/LAN snapshots and current effective
// local metrics. Tokens name the owner's actual next-hop catalog, not a MAC.
// ISO Annex C initializes local distances from adjacencies, independently of
// stale own LSP metrics. Peers lacking a live eligible root cannot expand.
// No allocation. Invalid input or insufficient output preserves every byte.
// Parallel adjacencies retain distinct tokens. Caller owns output on its shard.
[[nodiscard]] inline SeedResult p2p_spf_seeds(const LinkGraph &graph,
    std::span<const P2pSpfSeed> seeds, std::uint16_t catalog_size,
    std::uint32_t maximum_metric, std::span<SpfEdge> output) noexcept {
  if (!graph.root() || !maximum_metric || catalog_size > routing::ShortestPaths::maximum_first_hops)
    return {SeedStatus::invalid, 0U};
  const auto target = [&](const auto &seed) {
    packet::isis::LanId id{};
    std::copy(seed.peer.begin(), seed.peer.end(), id.begin());
    return std::find_if(graph.nodes().begin(), graph.nodes().end(), [&](const auto &node) { return node.id == id; });
  };
  std::size_t count{};
  for (const auto &seed : seeds) {
    if (seed.first_hop >= catalog_size || seed.metric > maximum_metric)
      return {SeedStatus::invalid, 0U};
    if (target(seed) != graph.nodes().end()) ++count;
  }
  if (count > output.size()) return {SeedStatus::capacity, 0U};
  count = 0U;
  for (const auto &seed : seeds) {
    const auto found = target(seed);
    if (found != graph.nodes().end()) output[count++] = {
        static_cast<std::uint32_t>(found - graph.nodes().begin()), seed.metric, seed.first_hop};
  }
  return {SeedStatus::applied, count};
}
} // namespace router::isis
