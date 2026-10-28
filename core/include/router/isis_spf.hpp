// IS-IS distance policies for the shared bounded SPF mechanism. One instance
// control owner supplies an eligible, bidirectional graph from its local LSDB.
// No peer or editor state is accessible through this interface.

#pragma once

#include "router/isis_reachability.hpp"
#include "router/shortest_paths.hpp"

namespace router::isis {

enum class MetricStyle : std::uint8_t { narrow, wide };
using SpfVertex = routing::SpfVertex;
using SpfEdge = routing::SpfEdge;
inline constexpr auto no_first_hop = routing::no_first_hop;

class SpfCalculator final : public routing::ShortestPaths {
public:
  // ISO 10589 Annex C admits distance 1023 and discards larger paths.
  // RFC 5305 admits MAX_PATH_METRIC and saturates additions at that value.
  // The owner must exclude maximum-wide-metric links, overload transit arcs,
  // and links without the required reverse connectivity before calculation.
  // Invalid graph or exhausted scratch preserves the published generation.
  SpfCalculator(std::size_t maximum_vertices, std::size_t maximum_pending_candidates,
                MetricStyle style)
      : ShortestPaths(maximum_vertices, maximum_pending_candidates,
          style == MetricStyle::wide
              ? routing::DistancePolicy{packet::isis::maximum_path_metric,
                    packet::isis::maximum_link_metric - 1U, true, true}
              : routing::DistancePolicy{1023U, 63U, false, true}) {}
};

} // namespace router::isis
