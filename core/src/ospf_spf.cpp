// Dijkstra SPF implementation for RFC 2328 section 16 and RFC 5340 section
// 4.8. It computes topology distance and equal-cost first-hop sets only.
// Inter-area and external route preference remain separate route-calculation
// phases because mixing their rules into graph relaxation would be incorrect.

#include "router/ospf_spf.hpp"

#include <algorithm>
#include <bit>
#include <limits>

namespace router::ospf {

SpfCalculator::SpfCalculator(std::size_t maximum_vertices,
                             std::size_t maximum_pending_candidates)
    : maximum_vertices_(maximum_vertices),
      maximum_pending_candidates_(maximum_pending_candidates) {
  // Allocation belongs to construction and therefore to the protocol-instance
  // owner. The real-time calculate path reuses these capacities.
  published_.reserve(maximum_vertices_);
  scratch_.reserve(maximum_vertices_);
  candidates_.reserve(maximum_pending_candidates_);
}

bool SpfCalculator::calculate(
    std::uint32_t root_vertex, std::span<const SpfVertex> vertices,
    std::span<const SpfEdge> edges,
    std::uint16_t first_hop_count_value) noexcept {
  if (vertices.empty() || vertices.size() > maximum_vertices_ ||
      root_vertex >= vertices.size() ||
      maximum_pending_candidates_ == 0U ||
      first_hop_count_value > device_catalog::maximum_ecmp_paths)
    return false;

  // Validate every adjacency extent and target before touching scratch state.
  // This preserves the previous published generation after a malformed LSDB
  // translation rather than exposing a partial tree.
  for (const auto &vertex : vertices) {
    const auto first = static_cast<std::size_t>(vertex.first_edge);
    const auto count = static_cast<std::size_t>(vertex.edge_count);
    if (first > edges.size() || count > edges.size() - first)
      return false;
    for (const auto &edge : edges.subspan(first, count)) {
      if (edge.target_vertex >= vertices.size() ||
          edge.cost >= ls_infinity ||
          (edge.first_hop != no_first_hop &&
           edge.first_hop >= first_hop_count_value))
        return false;
    }
  }

  scratch_.assign(vertices.size(), VertexState{});
  candidates_.clear();
  scratch_[root_vertex].distance = 0U;
  scratch_[root_vertex].revision = 1U;
  candidates_.push_back(
      {.distance = 0U, .vertex = root_vertex, .revision = 1U});

  // std::push_heap is a max-heap by default. Reverse distance and vertex order
  // to obtain a stable min-heap. Vertex order is not a route tie-break; it
  // makes processing reproducible while equal-cost first hops are merged.
  const auto candidate_later = [](const Candidate &left,
                                  const Candidate &right) noexcept {
    return left.distance > right.distance ||
           (left.distance == right.distance && left.vertex > right.vertex);
  };
  const auto push_candidate = [this, candidate_later](
                                  Candidate value) noexcept {
    if (candidates_.size() >= maximum_pending_candidates_)
      return false;
    candidates_.push_back(value);
    std::push_heap(candidates_.begin(), candidates_.end(), candidate_later);
    return true;
  };

  while (!candidates_.empty()) {
    std::pop_heap(candidates_.begin(), candidates_.end(), candidate_later);
    const auto candidate = candidates_.back();
    candidates_.pop_back();
    const auto &current = scratch_[candidate.vertex];
    if (candidate.distance != current.distance ||
        candidate.revision != current.revision)
      continue;

    const auto &vertex = vertices[candidate.vertex];
    const auto outgoing = edges.subspan(vertex.first_edge, vertex.edge_count);
    for (const auto &edge : outgoing) {
      if (current.distance >= ls_infinity - edge.cost)
        continue;
      const auto proposed_distance = current.distance + edge.cost;
      auto proposed_hops = current.first_hops;
      if (edge.first_hop != no_first_hop) {
        const auto word = static_cast<std::size_t>(edge.first_hop / 64U);
        const auto bit = static_cast<std::uint8_t>(edge.first_hop % 64U);
        // Once a path has a forwarding first hop, later graph arcs cannot
        // replace it. The token on a later arc is used only when a root to
        // transit-network arc intentionally carried no token.
        const bool has_hop = std::any_of(
            proposed_hops.begin(), proposed_hops.end(),
            [](std::uint64_t value) { return value != 0U; });
        if (!has_hop)
          proposed_hops[word] |= std::uint64_t{1U} << bit;
      }

      auto &target = scratch_[edge.target_vertex];
      bool changed{};
      if (proposed_distance < target.distance) {
        target.distance = proposed_distance;
        target.first_hops = proposed_hops;
        changed = true;
      } else if (proposed_distance == target.distance) {
        for (std::size_t word = 0U; word < target.first_hops.size(); ++word) {
          const auto merged =
              target.first_hops[word] | proposed_hops[word];
          changed = changed || merged != target.first_hops[word];
          target.first_hops[word] = merged;
        }
      }
      if (changed) {
        ++target.revision;
        if (!push_candidate({.distance = target.distance,
                             .vertex = edge.target_vertex,
                             .revision = target.revision}))
          return false;
      }
    }
  }

  published_.swap(scratch_);
  published_count_ = vertices.size();
  published_first_hop_count_ = first_hop_count_value;
  return true;
}

bool SpfCalculator::reachable(std::size_t vertex) const noexcept {
  return vertex < published_count_ &&
         published_[vertex].distance < ls_infinity;
}

std::optional<std::uint32_t>
SpfCalculator::cost(std::size_t vertex) const noexcept {
  return reachable(vertex)
             ? std::optional<std::uint32_t>{published_[vertex].distance}
             : std::nullopt;
}

std::size_t
SpfCalculator::first_hop_count(std::size_t vertex) const noexcept {
  if (!reachable(vertex))
    return 0U;
  std::size_t result{};
  for (const auto word : published_[vertex].first_hops)
    result += static_cast<std::size_t>(std::popcount(word));
  return result;
}

std::optional<std::uint16_t>
SpfCalculator::first_hop(std::size_t vertex,
                         std::size_t ordinal) const noexcept {
  if (!reachable(vertex))
    return std::nullopt;
  std::size_t seen{};
  for (std::uint16_t index = 0U; index < published_first_hop_count_; ++index) {
    const auto word = static_cast<std::size_t>(index / 64U);
    const auto bit = static_cast<std::uint8_t>(index % 64U);
    if ((published_[vertex].first_hops[word] &
         (std::uint64_t{1U} << bit)) == 0U)
      continue;
    if (seen++ == ordinal)
      return index;
  }
  return std::nullopt;
}

} // namespace router::ospf
