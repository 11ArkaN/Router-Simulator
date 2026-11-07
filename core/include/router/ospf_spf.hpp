// OSPF metric policy for the shared bounded shortest-path mechanism. The
// enclosing OSPF process remains the sole state owner and translates only its
// own LSDB. RFC 2328 LSInfinity is excluded from finite path distances.

#pragma once

#include "router/shortest_paths.hpp"

namespace router::ospf {

inline constexpr std::uint32_t ls_infinity = 0x00ffffffU;
inline constexpr auto no_first_hop = routing::no_first_hop;
inline constexpr auto first_hop_word_count = routing::first_hop_word_count;
using SpfVertex = routing::SpfVertex;
using SpfEdge = routing::SpfEdge;

class SpfCalculator final : public routing::ShortestPaths {
public:
  // Allocates reusable scratch on the owning control shard. calculate rejects
  // LSInfinity edges and paths reaching LSInfinity without replacing results.
  SpfCalculator(std::size_t maximum_vertices, std::size_t maximum_pending_candidates)
      : ShortestPaths(maximum_vertices, maximum_pending_candidates,
                      {ls_infinity - 1U, ls_infinity - 1U, false}) {}
};

} // namespace router::ospf
