// The instance shard owns two complete P2P SPF input generations. Translation
// combines its immutable LSDB graph with accepted local adjacency seeds; it
// cannot inspect another router, a port owner or topology editor state.

// Source: iso.10589.2002.lsdb_link_graph

#pragma once

#include "router/isis_p2p_spf_seed.hpp"

#include <limits>
#include <stdexcept>

namespace router::isis {
class P2pSpfInput final {
public:
  // Cold allocation only. Budgets are emulator inputs, not SR OS limits.
  // Invalid or unrepresentable budgets throw before any generation exists.
  P2pSpfInput(std::size_t nodes, std::size_t edges) : maximum_nodes_(nodes), maximum_edges_(edges) {
    if (!nodes || !edges || nodes > std::numeric_limits<std::uint32_t>::max() ||
        edges > std::numeric_limits<std::uint32_t>::max() || nodes > published_.vertices.max_size() ||
        edges > published_.edges.max_size()) throw std::invalid_argument("Invalid IS-IS SPF input budget");
    for (auto *value : {&published_, &working_}) {
      value->vertices.reserve(nodes);
      value->edges.reserve(edges);
    }
  }
  // Same instance owner, no concurrent graph mutation and no allocation.
  // Root arcs use actual local metrics and tokens even before own LSP refresh.
  // Non-root arcs retain the graph's reverse-connectivity/overload filtering.
  // This adapter explicitly refuses LAN graphs until LAN next-hop binding is
  // supplied. Every refusal preserves the previous complete publication.
  [[nodiscard]] bool rebuild(const LinkGraph &graph, std::span<const P2pSpfSeed> local,
      std::uint16_t catalog_size, std::uint32_t maximum_metric) noexcept {
    if (!graph.root() || graph.nodes().size() > maximum_nodes_ ||
        std::any_of(graph.nodes().begin(), graph.nodes().end(), [](const auto &node) { return node.id[6U] != 0U; })) return false;
    const auto seeds = p2p_spf_seeds(graph, local, catalog_size, maximum_metric, seeds_);
    if (seeds.status != SeedStatus::applied) return false;
    std::size_t count = seeds.count;
    if (count > maximum_edges_) return false;
    for (const auto &arc : graph.links()) if (arc.source != *graph.root()) {
      if (count == maximum_edges_) return false;
      ++count;
    }
    if (count > maximum_edges_) return false;
    working_.vertices.clear();
    working_.edges.clear();
    std::size_t cursor{};
    for (std::size_t vertex{}; vertex < graph.nodes().size(); ++vertex) {
      const auto first = working_.edges.size();
      if (vertex == *graph.root())
        working_.edges.insert(working_.edges.end(), seeds_.begin(), seeds_.begin() + seeds.count);
      while (cursor < graph.links().size() && graph.links()[cursor].source == vertex) {
        const auto &arc = graph.links()[cursor++];
        if (vertex != *graph.root()) working_.edges.push_back({arc.target, arc.metric, no_first_hop});
      }
      working_.vertices.push_back({static_cast<std::uint32_t>(first),
          static_cast<std::uint32_t>(working_.edges.size() - first), 1U});
    }
    std::swap(published_, working_);
    return true;
  }
  // Views expire on successful rebuild or destruction, on this shard only.
  [[nodiscard]] std::span<const SpfVertex> vertices() const noexcept { return published_.vertices; }
  [[nodiscard]] std::span<const SpfEdge> edges() const noexcept { return published_.edges; }
private:
  struct Generation { std::vector<SpfVertex> vertices; std::vector<SpfEdge> edges; };
  std::size_t maximum_nodes_{}, maximum_edges_{};
  Generation published_, working_;
  std::array<SpfEdge, device_catalog::maximum_ecmp_paths> seeds_{};
};
} // namespace router::isis
