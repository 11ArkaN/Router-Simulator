// Encoded LSDB fixtures exercise eligibility before distance calculation. The
// test owns clocks and bytes; no adjacency or editor graph supplies reachability.

#include "router/isis_link_graph.hpp"
#include "router/isis_basic_tlvs.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/isis_multi_topology.hpp"
#include "router/isis_narrow_reachability.hpp"
#include "router/isis_spf.hpp"

#include <algorithm>
#include <memory>
#include <limits>
#include <source_location>
#include <string>
#include <stdexcept>

namespace {
using namespace router;
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS LSDB link graph invariant failed at " + std::to_string(location.line()));
}
LanId node(std::uint8_t number, std::uint8_t pseudonode = 0U) { return {1U, 2U, 3U, 4U, 5U, number, pseudonode}; }
LspId identity(LanId id, std::uint8_t fragment = 0U) {
  LspId result{};
  std::copy(id.begin(), id.end(), result.begin());
  result.back() = fragment;
  return result;
}
struct Fixture {
  LinkStateDatabase database{PduType::lsp_l1, {16U, 32768U}};
  std::unique_ptr<PduScratch> scratch{std::make_unique<PduScratch>()};
  RuntimeClock::time_point now{};
  void install(LanId id, std::span<const std::uint8_t> options, std::uint8_t flags = 3U,
      std::uint32_t sequence = 1U, std::uint8_t fragment = 0U, std::uint16_t lifetime = 1200U) {
    LspContents content;
    content.header = {PduType::lsp_l1, identity(id, fragment), lifetime, sequence, flags};
    content.options = options;
    content.maximum_pdu_octets = 1492U;
    const auto encoded = build_lsp_pdu(content, scratch->options, scratch->pdu);
    require(encoded.status == LspBuildStatus::encoded &&
        database.install(encoded.bytes, now, 1200U, 60s) == LspInstallResult::installed);
  }
};
std::vector<std::uint8_t> options(std::span<const ExtendedNeighbor> links,
    std::span<const TopologyComponent> topologies = {}, bool ipv6 = true, std::uint16_t topology = 0U) {
  std::array<std::uint8_t, 1024U> buffer{};
  TlvWriter writer(buffer);
  const std::array<std::uint8_t, 2U> protocols{ipv4_nlpid, ipv6_nlpid};
  require(writer.append(129U, std::span{protocols}.first(ipv6 ? 2U : 1U)));
  if (!topologies.empty()) require(encode_topologies(writer, topologies, true));
  for (const auto &link : links)
    require(topology ? encode_mt_neighbor(writer, topology, link) : encode_extended_neighbor(writer, link));
  return {writer.bytes().begin(), writer.bytes().end()};
}
bool arc(const LinkGraph &graph, LanId from, LanId to, std::uint32_t metric) {
  return std::any_of(graph.links().begin(), graph.links().end(), [&](const auto &link) {
    return graph.nodes()[link.source].id == from && graph.nodes()[link.target].id == to && link.metric == metric;
  });
}
}
void isis_link_graph_tests() {
  for (const auto budget : {std::size_t{}, std::numeric_limits<std::size_t>::max()}) {
    bool refused{};
    try { LinkGraph invalid(budget, 1U); } catch (const std::invalid_argument &) { refused = true; }
    require(refused);
  }
  Fixture f;
  const auto a = node(1U), b = node(2U), c = node(3U);
  const std::array ab{ExtendedNeighbor{b, 10U, {}}};
  const std::array ba_bc{ExtendedNeighbor{a, 20U, {}}, ExtendedNeighbor{c, 1U, {}}};
  const std::array cb{ExtendedNeighbor{b, 2U, {}}};
  f.install(a, options(ab));
  f.install(b, options(ba_bc));
  f.install(c, options(cb), 3U, 1U, 1U);
  LinkGraph graph(8U, 16U);
  const LinkGraphSelection selected{a, 0U, ipv4_nlpid, GraphMetricStyle::wide};
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied && graph.root() &&
      graph.nodes().size() == 2U && graph.links().size() == 2U && arc(graph, a, b, 10U) && arc(graph, b, a, 20U));
  // A live nonzero fragment becomes eligible only while its fragment zero lives.
  f.install(c, options({}), 3U, 1U, 0U, 1U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      graph.nodes().size() == 3U && graph.links().size() == 4U && arc(graph, b, c, 1U) && arc(graph, c, b, 2U));
  f.install(b, options(ba_bc), 7U, 1U, 1U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied && graph.links().size() == 4U);
  std::vector<SpfVertex> vertices(graph.nodes().size());
  std::vector<SpfEdge> edges;
  for (std::size_t source{}; source < vertices.size(); ++source) {
    vertices[source].first_edge = static_cast<std::uint32_t>(edges.size());
    for (const auto &link : graph.links()) if (link.source == source) {
      edges.push_back({link.target, link.metric, source == *graph.root() ? std::uint16_t{0U} : no_first_hop});
      ++vertices[source].edge_count;
    }
  }
  SpfCalculator spf(8U, 64U, MetricStyle::wide);
  require(spf.calculate(*graph.root(), vertices, edges, 1U) && spf.cost(2U) == 11U && spf.first_hop_count(2U) == 1U);
  f.now += 2s;
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      graph.nodes().size() == 2U && graph.links().size() == 2U);
  f.install(c, options({}), 3U, 2U);
  f.install(b, options(ba_bc), 7U, 2U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      graph.links().size() == 2U && arc(graph, a, b, 10U) && arc(graph, c, b, 2U));
  require(graph.rebuild(f.database, {b, 0U, ipv4_nlpid, GraphMetricStyle::wide}, f.now) == LinkGraphStatus::applied && graph.links().size() == 4U);
  // A maximum-cost reverse advertisement still establishes reported presence;
  // only its own directed arc is excluded from normal path construction.
  const std::array maximum{ExtendedNeighbor{b, maximum_link_metric, {}}};
  f.install(a, options(maximum), 3U, 2U);
  f.install(b, options(ba_bc), 3U, 3U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      !arc(graph, a, b, maximum_link_metric) && arc(graph, b, a, 20U));
  f.install(b, options(ba_bc, {}, false), 3U, 4U);
  require(graph.rebuild(f.database, {a, 0U, ipv6_nlpid, GraphMetricStyle::wide}, f.now) == LinkGraphStatus::applied &&
      graph.nodes().size() == 2U && graph.links().empty());
  const auto prior_nodes = graph.nodes().size();
  require(graph.rebuild(f.database, {a, 4096U, {}, GraphMetricStyle::wide}, f.now) == LinkGraphStatus::invalid_selection &&
      graph.nodes().size() == prior_nodes && graph.links().empty());

  Fixture lan;
  const auto pn = node(9U, 1U);
  const std::array<TopologyComponent, 2U> both{{{0U}, {2U}}};
  const std::array<TopologyComponent, 1U> mt2{{{2U}}};
  const std::array ap{ExtendedNeighbor{pn, 10U, {}}};
  const std::array bp{ExtendedNeighbor{pn, 20U, {}}};
  const std::array pa_pb{ExtendedNeighbor{a, 0U, {}}, ExtendedNeighbor{b, 0U, {}}};
  lan.install(a, options(ap, both, true, 2U), 7U);
  lan.install(b, options(bp, mt2, true, 2U));
  // A legacy DIS pseudonode carries standard neighbors and no NLPID or MT TLV.
  std::array<std::uint8_t, 128U> pn_buffer{};
  TlvWriter pn_options(pn_buffer);
  for (const auto &entry : pa_pb) require(encode_extended_neighbor(pn_options, entry));
  lan.install(pn, pn_options.bytes());
  require(graph.rebuild(lan.database, {a, 2U, ipv6_nlpid, GraphMetricStyle::wide}, lan.now) == LinkGraphStatus::applied &&
      graph.nodes().size() == 3U && graph.links().size() == 4U && arc(graph, a, pn, 10U) &&
      arc(graph, pn, b, 0U) && !graph.nodes()[*graph.root()].overloaded);
  lan.install(b, options({}, mt2), 3U, 2U);
  require(graph.rebuild(lan.database, {a, 2U, ipv6_nlpid, GraphMetricStyle::wide}, lan.now) == LinkGraphStatus::applied &&
      graph.links().size() == 2U && !arc(graph, pn, b, 0U));
  LinkGraph small(8U, 1U);
  Fixture empty;
  require(small.rebuild(empty.database, selected, empty.now) == LinkGraphStatus::applied && !small.root());
  require(small.rebuild(lan.database, {a, 2U, ipv6_nlpid, GraphMetricStyle::wide}, lan.now) == LinkGraphStatus::capacity &&
      small.nodes().empty() && small.links().empty() && !small.root());

  Fixture malformed;
  auto invalid_options = options(ab);
  // Keep outer framing valid but add an incomplete second neighbor to TLV 22.
  invalid_options[5U] = 12U;
  invalid_options.push_back(0U);
  malformed.install(a, invalid_options);
  malformed.install(b, options(std::span{ba_bc}.first(1U)));
  require(graph.rebuild(malformed.database, selected, malformed.now) == LinkGraphStatus::applied &&
      graph.nodes().size() == 2U && graph.links().empty() && graph.ignored_options() == 1U &&
      malformed.database.size() == 2U);
  Fixture metrics;
  std::array<std::uint8_t, 128U> mixed_buffer{};
  TlvWriter mixed_a(mixed_buffer);
  require(encode_narrow_neighbor(mixed_a, {{63U, false, {}, {}, {}}, b, false}) &&
      encode_extended_neighbor(mixed_a, {b, 100U, {}}));
  const auto a_options = std::vector<std::uint8_t>(mixed_a.bytes().begin(), mixed_a.bytes().end());
  metrics.install(a, a_options);
  TlvWriter mixed_b(mixed_buffer);
  require(encode_narrow_neighbor(mixed_b, {{5U, false, {}, {}, {}}, a, false}) &&
      encode_extended_neighbor(mixed_b, {a, 50U, {}}));
  metrics.install(b, mixed_b.bytes());
  require(graph.rebuild(metrics.database, {a, 0U, {}, GraphMetricStyle::wide}, metrics.now) == LinkGraphStatus::applied &&
      graph.links().size() == 2U && arc(graph, a, b, 100U) && arc(graph, b, a, 50U));
  require(graph.rebuild(metrics.database, {a, 0U, {}, GraphMetricStyle::narrow}, metrics.now) == LinkGraphStatus::applied &&
      graph.links().size() == 2U && arc(graph, a, b, 63U) && arc(graph, b, a, 5U));
  require(graph.rebuild(metrics.database, {a, 0U, {}, GraphMetricStyle::both_minimum}, metrics.now) == LinkGraphStatus::applied &&
      graph.links().size() == 2U && arc(graph, a, b, 63U) && arc(graph, b, a, 5U));
  require(graph.rebuild(metrics.database, {a, 2U, {}, GraphMetricStyle::narrow}, metrics.now) == LinkGraphStatus::invalid_selection &&
      graph.links().size() == 2U);
  require(graph.rebuild(metrics.database, {a, 0U, {}}, metrics.now) == LinkGraphStatus::invalid_selection &&
      graph.links().size() == 2U);
  auto reserved_metric_bit = a_options;
  reserved_metric_bit[3U] |= 0x80U;
  metrics.install(a, reserved_metric_bit, 3U, 2U);
  require(graph.rebuild(metrics.database, {a, 0U, {}, GraphMetricStyle::narrow}, metrics.now) == LinkGraphStatus::applied &&
      arc(graph, a, b, 63U) && graph.ignored_options() == 0U);
  auto external_neighbor = a_options;
  external_neighbor[3U] |= 0x40U;
  metrics.install(a, external_neighbor, 3U, 3U);
  require(graph.rebuild(metrics.database, {a, 0U, {}, GraphMetricStyle::both_minimum}, metrics.now) == LinkGraphStatus::applied &&
      graph.links().size() == 2U && arc(graph, a, b, 100U) && graph.ignored_options() == 1U);
  LinkGraph bounded(2U, 16U);
  require(bounded.rebuild(metrics.database, selected, metrics.now) == LinkGraphStatus::applied && bounded.nodes().empty());
  const LinkGraphSelection no_family{a, 0U, {}, GraphMetricStyle::wide};
  require(bounded.rebuild(metrics.database, no_family, metrics.now) == LinkGraphStatus::applied &&
      bounded.nodes().size() == 2U && bounded.links().size() == 2U && bounded.root());
  metrics.install(c, {});
  require(bounded.rebuild(metrics.database, no_family, metrics.now) == LinkGraphStatus::capacity &&
      bounded.nodes().size() == 2U && bounded.links().size() == 2U && bounded.root());
  require(graph.rebuild(metrics.database, {node(4U), 0U, {}, GraphMetricStyle::wide}, metrics.now) == LinkGraphStatus::applied && !graph.root());

}
