// The instance shard owns two complete SPF input generations. Translation
// combines its immutable LSDB graph with accepted local adjacency seeds; it
// cannot inspect another router, a port owner or topology editor state.

// Source: iso.10589.2002.lsdb_link_graph

#pragma once

#include "router/isis_p2p_spf_seed.hpp"

#include <limits>
#include <stdexcept>

namespace router::isis {
struct LanSpfCircuit {
  // Same-owner value projection of one current level/MT LAN circuit. The
  // interface identity orders initialization deterministically. A DIS token,
  // when present, must name an actual Up seed on this circuit at this metric.
  std::uint64_t interface_id{};
  packet::isis::LanId pseudonode{};
  std::uint32_t metric{};
  std::optional<std::uint16_t> designated_first_hop{};
};
class SpfInput final {
public:
  // Cold allocation only. Budgets are emulator inputs, not SR OS limits.
  // Invalid or unrepresentable budgets throw before any generation exists.
  SpfInput(std::size_t nodes, std::size_t edges) : maximum_nodes_(nodes), maximum_edges_(edges) {
    if (!nodes || !edges || nodes > std::numeric_limits<std::uint32_t>::max() ||
        edges > std::numeric_limits<std::uint32_t>::max() || nodes > published_.vertices.max_size() ||
        edges > published_.edges.max_size()) throw std::invalid_argument("Invalid IS-IS SPF input budget");
    seeds_.resize(edges);
    for (auto *value : {&published_, &working_}) {
      value->vertices.reserve(nodes);
      value->edges.reserve(edges);
    }
  }
  // Same instance owner, no concurrent graph mutation and no allocation.
  // Root arcs use actual local metrics and tokens even before own LSP refresh.
  // Non-root arcs retain the graph's reverse-connectivity/overload filtering.
  // Local seeds include actual Up P2P/LAN adjacencies. ISO C.2.5/RFC1195 C.1
  // initialize remaining pseudonode neighbors through the actual DIS adjacency.
  // LAN projections are sorted unique by interface identity. Missing DIS
  // binding disables that circuit's indirect initialization; no address or
  // token is fabricated. Pseudonodes win equal-distance selection (C.2.7).
  // Every refusal preserves the previous complete publication.
  [[nodiscard]] bool rebuild(const LinkGraph &graph, std::span<const P2pSpfSeed> local,
      std::uint16_t catalog_size, std::uint32_t maximum_metric,
      std::span<const LanSpfCircuit> lans = {}) noexcept {
    if (!graph.root() || graph.nodes().size() > maximum_nodes_) return false;
    const auto seeds = p2p_spf_seeds(graph, local, catalog_size, maximum_metric, seeds_);
    if (seeds.status != SeedStatus::applied) return false;
    std::size_t seed_count = seeds.count;
    for (std::size_t circuit{}; circuit < lans.size(); ++circuit) {
      const auto &lan = lans[circuit];
      if (!lan.interface_id || !lan.pseudonode[6U] || lan.metric > maximum_metric ||
          (circuit && lans[circuit - 1U].interface_id >= lan.interface_id)) return false;
      if (!lan.designated_first_hop) continue;
      if (*lan.designated_first_hop >= catalog_size) return false;
      const auto designated = std::find_if(local.begin(), local.end(), [&](const auto &peer) {
        return peer.first_hop == *lan.designated_first_hop && peer.metric == lan.metric;
      });
      if (designated == local.end()) return false;
      // Election may change before the winner advertises its new LAN ID.
      // Preserve actual adjacency initialization, but do not route old PN
      // membership through a different router's newly selected DIS token.
      if (!std::equal(designated->peer.begin(), designated->peer.end(), lan.pseudonode.begin())) continue;
      // A Hello alone cannot make an expired or family-ineligible DIS root
      // usable as a forwarding neighbor. Only resolved actual seeds qualify.
      if (std::none_of(seeds_.begin(), seeds_.begin() + seeds.count,
          [&](const auto &seed) {
            const auto &id = graph.nodes()[seed.target_vertex].id;
            return seed.first_hop == *lan.designated_first_hop && !id[6U] &&
                std::equal(id.begin(), id.begin() + 6U, lan.pseudonode.begin());
          })) continue;
      const auto found = std::lower_bound(graph.nodes().begin(), graph.nodes().end(), lan.pseudonode,
          [](const auto &node, const auto &id) { return node.id < id; });
      if (found == graph.nodes().end() || found->id != lan.pseudonode) continue;
      const auto vertex = static_cast<std::uint32_t>(found - graph.nodes().begin());
      auto arc = std::lower_bound(graph.links().begin(), graph.links().end(), vertex,
          [](const auto &edge, auto source) { return edge.source < source; });
      for (; arc != graph.links().end() && arc->source == vertex; ++arc) {
        if (arc->target == *graph.root() || graph.nodes()[arc->target].id[6U] ||
            std::any_of(seeds_.begin(), seeds_.begin() + seed_count,
                [&](const auto &seed) { return seed.target_vertex == arc->target; })) continue;
        if (seed_count == maximum_edges_) return false;
        seeds_[seed_count++] = {arc->target, lan.metric, *lan.designated_first_hop};
      }
    }
    std::size_t count = seed_count;
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
        working_.edges.insert(working_.edges.end(), seeds_.begin(), seeds_.begin() + seed_count);
      while (cursor < graph.links().size() && graph.links()[cursor].source == vertex) {
        const auto &arc = graph.links()[cursor++];
        if (vertex != *graph.root()) working_.edges.push_back({arc.target, arc.metric, no_first_hop});
      }
      working_.vertices.push_back({static_cast<std::uint32_t>(first),
          static_cast<std::uint32_t>(working_.edges.size() - first),
          static_cast<std::uint8_t>(graph.nodes()[vertex].id[6U] ? 0U : 1U)});
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
  std::vector<SpfEdge> seeds_;
};
} // namespace router::isis
