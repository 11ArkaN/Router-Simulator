// OSPF SPF tests prove shortest-path selection, ECMP first-hop propagation,
// transit-network zero-cost arcs, unreachable vertices and atomic rejection of
// malformed or over-capacity calculations.

#include "router/ospf_spf.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_spf_tests() {
  using namespace router::ospf;

  // Two equal root branches reach vertex 3 with cost 20. A direct cost-30 arc
  // is discovered first but must be replaced rather than retained as ECMP.
  const std::array vertices{
      SpfVertex{.first_edge = 0U, .edge_count = 3U},
      SpfVertex{.first_edge = 3U, .edge_count = 1U},
      SpfVertex{.first_edge = 4U, .edge_count = 1U},
      SpfVertex{.first_edge = 5U, .edge_count = 0U},
      SpfVertex{.first_edge = 5U, .edge_count = 0U}};
  const std::array edges{
      SpfEdge{.target_vertex = 1U, .cost = 10U, .first_hop = 0U},
      SpfEdge{.target_vertex = 2U, .cost = 10U, .first_hop = 1U},
      SpfEdge{.target_vertex = 3U, .cost = 30U, .first_hop = 2U},
      SpfEdge{.target_vertex = 3U,
              .cost = 10U,
              .first_hop = no_first_hop},
      SpfEdge{.target_vertex = 3U,
              .cost = 10U,
              .first_hop = no_first_hop}};
  SpfCalculator calculator(16U, 64U);
  require(calculator.calculate(0U, vertices, edges, 3U) &&
              calculator.cost(0U) == std::optional<std::uint32_t>{0U} &&
              calculator.cost(3U) == std::optional<std::uint32_t>{20U} &&
              calculator.first_hop_count(3U) == 2U &&
              calculator.first_hop(3U, 0U) ==
                  std::optional<std::uint16_t>{0U} &&
              calculator.first_hop(3U, 1U) ==
                  std::optional<std::uint16_t>{1U} &&
              !calculator.first_hop(3U, 2U) &&
              !calculator.reachable(4U),
          "OSPF Dijkstra did not select the equal shortest paths");

  // A router-to-network edge has cost but no concrete next-hop token. The
  // zero-cost network-to-router arcs introduce the directly reachable
  // neighbors, and their tokens must survive all later router arcs.
  const std::array broadcast_vertices{
      SpfVertex{.first_edge = 0U, .edge_count = 1U},
      SpfVertex{.first_edge = 1U, .edge_count = 2U},
      SpfVertex{.first_edge = 3U, .edge_count = 1U},
      SpfVertex{.first_edge = 4U, .edge_count = 1U},
      SpfVertex{.first_edge = 5U, .edge_count = 0U}};
  const std::array broadcast_edges{
      SpfEdge{.target_vertex = 1U,
              .cost = 5U,
              .first_hop = no_first_hop},
      SpfEdge{.target_vertex = 2U, .cost = 0U, .first_hop = 0U},
      SpfEdge{.target_vertex = 3U, .cost = 0U, .first_hop = 1U},
      SpfEdge{.target_vertex = 4U,
              .cost = 10U,
              .first_hop = no_first_hop},
      SpfEdge{.target_vertex = 4U,
              .cost = 10U,
              .first_hop = no_first_hop}};
  require(calculator.calculate(0U, broadcast_vertices, broadcast_edges, 2U) &&
              calculator.cost(4U) == std::optional<std::uint32_t>{15U} &&
              calculator.first_hop_count(4U) == 2U,
          "OSPF transit-network next-hop calculation is incorrect");

  // A failed generation cannot replace the last complete result. This is the
  // route-publication boundary later used by the OSPF process.
  auto malformed = broadcast_edges;
  malformed[4U].target_vertex = 99U;
  require(!calculator.calculate(0U, broadcast_vertices, malformed, 2U) &&
              calculator.cost(4U) == std::optional<std::uint32_t>{15U} &&
              calculator.first_hop_count(4U) == 2U,
          "invalid OSPF graph replaced the published SPF generation");

  SpfCalculator constrained(16U, 1U);
  require(!constrained.calculate(0U, vertices, edges, 3U) &&
              constrained.vertex_count() == 0U,
          "OSPF candidate overflow produced a partial SPF result");
}
