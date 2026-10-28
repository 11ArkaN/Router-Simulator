// Finite IS-IS metric boundaries differ from the OSPF infinity sentinel.
// These indexed graphs exercise exact limits, saturation, ECMP and atomic
// rejection without a topology editor or access to another router's LSDB.

#include "router/isis_spf.hpp"
#include "router/ospf_spf.hpp"

#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_spf_tests() {
  using namespace router::isis;
  std::array<SpfVertex, 20U> narrow_vertices{};
  std::array<SpfEdge, 18U> narrow_edges{};
  for (std::uint32_t index{}; index < narrow_edges.size(); ++index) {
    narrow_vertices[index] = {index, 1U};
    narrow_edges[index] = {index + 1U, index < 16U ? 63U : index == 16U ? 15U : 1U,
                           index == 0U ? std::uint16_t{0U} : no_first_hop};
  }
  SpfCalculator narrow(20U, 64U, MetricStyle::narrow);
  require(narrow.calculate(0U, narrow_vertices, narrow_edges, 1U) &&
      narrow.cost(17U) == 1023U && narrow.first_hop(17U, 0U) == 0U &&
      !narrow.reachable(18U) && !narrow.reachable(19U),
      "IS-IS narrow SPF lost finite maximum or admitted excessive distance");
  narrow_edges[0].cost = 64U;
  require(!narrow.calculate(0U, narrow_vertices, narrow_edges, 1U) && narrow.cost(17U) == 1023U,
      "IS-IS narrow SPF published an invalid metric generation");

  // 254 maximum-usable links plus 508 equals exactly 0xFE000000.
  // A zero-cost pseudonode arc and a positive arc must both retain that
  // finite value. A separate unreachable vertex keeps the distinct sentinel.
  std::array<SpfVertex, 259U> wide_vertices{};
  std::array<SpfEdge, 257U> wide_edges{};
  for (std::uint32_t index{}; index < wide_edges.size(); ++index) {
    wide_vertices[index] = {index, 1U};
    const auto metric = index < 254U ? router::packet::isis::maximum_link_metric - 1U
                                   : index == 254U ? 508U : index == 255U ? 0U : 1U;
    wide_edges[index] = {index + 1U, metric,
                        index == 0U ? std::uint16_t{0U} : no_first_hop};
  }
  SpfCalculator wide(259U, 1024U, MetricStyle::wide);
  require(wide.calculate(0U, wide_vertices, wide_edges, 1U) &&
      wide.cost(254U) == router::packet::isis::maximum_path_metric - 508U &&
      wide.cost(255U) == router::packet::isis::maximum_path_metric &&
      wide.cost(256U) == router::packet::isis::maximum_path_metric &&
      wide.cost(257U) == router::packet::isis::maximum_path_metric &&
      wide.first_hop(257U, 0U) == 0U && !wide.reachable(258U),
      "IS-IS wide SPF confused saturation with unreachable state");
  wide_edges[0].cost = router::packet::isis::maximum_link_metric;
  require(!wide.calculate(0U, wide_vertices, wide_edges, 1U) &&
      wide.cost(257U) == router::packet::isis::maximum_path_metric,
      "IS-IS wide SPF accepted an excluded maximum-link-metric edge");

  const std::array diamond_vertices{SpfVertex{0U, 2U}, SpfVertex{2U, 1U},
      SpfVertex{3U, 1U}, SpfVertex{4U, 1U}, SpfVertex{5U, 0U}};
  const std::array diamond_edges{SpfEdge{1U, 10U, 0U}, SpfEdge{2U, 10U, 1U},
      SpfEdge{3U, 0U, no_first_hop}, SpfEdge{3U, 0U, no_first_hop},
      SpfEdge{4U, 5U, no_first_hop}};
  require(wide.calculate(0U, diamond_vertices, diamond_edges, 2U) &&
      wide.cost(4U) == 15U && wide.first_hop_count(4U) == 2U &&
      wide.first_hop(4U, 0U) == 0U && wide.first_hop(4U, 1U) == 1U,
      "IS-IS SPF lost equal-cost first hops through zero-cost arcs");
  // Equal-cost pseudonodes precede routers even when their indexed key sorts
  // later. Closed PATHS entries never acquire a reverse first hop afterward.
  const std::array tied_vertices{SpfVertex{0U, 2U, 1U}, SpfVertex{2U, 3U, 1U},
      SpfVertex{5U, 1U, 0U}, SpfVertex{6U, 0U, 1U}};
  const std::array tied_edges{SpfEdge{1U, 10U, 0U}, SpfEdge{2U, 10U, 1U},
      SpfEdge{2U, 0U, no_first_hop}, SpfEdge{0U, 0U, no_first_hop},
      SpfEdge{3U, 5U, no_first_hop}, SpfEdge{1U, 0U, no_first_hop}};
  require(wide.calculate(0U, tied_vertices, tied_edges, 2U) &&
      wide.first_hop_count(0U) == 0U && wide.first_hop_count(1U) == 2U &&
      wide.first_hop_count(2U) == 1U && wide.first_hop(2U, 0U) == 1U &&
      wide.cost(3U) == 15U && wide.first_hop_count(3U) == 2U,
      "IS-IS SPF failed pseudonode precedence or reopened closed PATHS");
  SpfCalculator bounded(259U, 1U, MetricStyle::wide);
  require(!bounded.calculate(0U, diamond_vertices, diamond_edges, 2U) && bounded.vertex_count() == 0U,
      "IS-IS SPF published a partial tree after workspace exhaustion");

  const std::array ospf_vertices{SpfVertex{0U, 1U}, SpfVertex{1U, 1U}, SpfVertex{2U, 0U}};
  const std::array ospf_edges{SpfEdge{1U, router::ospf::ls_infinity - 1U, 0U},
      SpfEdge{2U, 1U, no_first_hop}};
  router::ospf::SpfCalculator ospf(3U, 4U);
  require(ospf.calculate(0U, ospf_vertices, ospf_edges, 1U) &&
      ospf.cost(1U) == router::ospf::ls_infinity - 1U && !ospf.reachable(2U),
      "Shared SPF changed OSPF LSInfinity exclusion");
  bool rejected{};
  try { router::routing::ShortestPaths invalid(1U, 1U, {0xffffffffU, 1U, true}); }
  catch (const std::invalid_argument &) { rejected = true; }
  require(rejected, "Shared SPF accepted a finite cap equal to its unreachable sentinel");
}
