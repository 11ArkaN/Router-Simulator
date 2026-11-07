// Encoded LSDB fixtures exercise eligibility before distance calculation. The
// test owns clocks and bytes; no adjacency or editor graph supplies reachability.

#include "router/isis_prefix_set.hpp"
#include "router/isis_prefix_distance.hpp"
#include "router/isis_link_graph.hpp"
#include "router/isis_basic_tlvs.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/isis_multi_topology.hpp"
#include "router/isis_narrow_reachability.hpp"
#include "router/isis_spf.hpp"
#include "router/isis_p2p_spf_seed.hpp"
#include "router/isis_p2p_spf_input.hpp"
#include "router/isis_p2p_decision.hpp"
#include "router/isis_prefix_routes.hpp"
#include "router/isis_rib_input.hpp"

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
  const std::array local_seeds{P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 2U}, 30U, 0U},
      P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 2U}, 40U, 1U}};
  std::array<SpfEdge, 2U> seeded{};
  const auto seeded_result = p2p_spf_seeds(graph, local_seeds, 2U, 63U, seeded);
  require(seeded_result.status == SeedStatus::applied && seeded_result.count == 2U &&
      seeded[0U].cost == 30U && seeded[1U].cost == 40U && seeded[0U].first_hop == 0U && seeded[1U].first_hop == 1U);
  const auto saved_seed = seeded;
  require(p2p_spf_seeds(graph, local_seeds, 2U, 63U, std::span{seeded}.first(1U)).status == SeedStatus::capacity &&
      seeded[0U].cost == saved_seed[0U].cost && seeded[1U].cost == saved_seed[1U].cost);
  require(p2p_spf_seeds(graph, local_seeds, 1U, 63U, seeded).status == SeedStatus::invalid &&
      seeded[0U].cost == saved_seed[0U].cost);
  P2pSpfInput limited_input(8U, 1U);
  require(limited_input.rebuild(graph, {}, 0U, 63U) && limited_input.edges().size() == 1U);
  require(!limited_input.rebuild(graph, local_seeds, 2U, 63U) && limited_input.edges().size() == 1U);
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
  P2pSpfInput actual_input(8U, 16U);
  require(actual_input.rebuild(graph, local_seeds, 2U, 63U));
  require(spf.calculate(*graph.root(), actual_input.vertices(), actual_input.edges(), 2U) &&
      spf.cost(2U) == 31U && spf.first_hop_count(2U) == 1U && spf.first_hop(2U, 0U) == 0U);
  const auto retained_edges = actual_input.edges().size();
  require(!actual_input.rebuild(graph, local_seeds, 1U, 63U) && actual_input.edges().size() == retained_edges);
  require(actual_input.rebuild(graph, {}, 0U, 63U) &&
      spf.calculate(*graph.root(), actual_input.vertices(), actual_input.edges(), 0U) && !spf.reachable(2U));
  P2pRouteDecision decision(8U, 16U, 64U, MetricStyle::wide);
  require(decision.calculate(f.database, selected, local_seeds, 2U, f.now) == DecisionStatus::applied &&
      decision.cost(c) == 31U && decision.first_hop_count(c) == 1U && decision.first_hop(c, 0U) == 0U);
  require(decision.calculate(f.database, selected, local_seeds, 1U, f.now) == DecisionStatus::invalid &&
      decision.cost(c) == 31U && decision.first_hop(c, 0U) == 0U);
  require(decision.calculate(f.database, selected, {}, 0U, f.now) == DecisionStatus::applied &&
      !decision.cost(c) && decision.first_hop_count(c) == 0U);
  auto missing_root = selected;
  missing_root.local = node(4U);
  require(decision.calculate(f.database, missing_root, {}, 0U, f.now) == DecisionStatus::applied && !decision.cost(a));
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

  for (const auto budget : {std::size_t{}, std::numeric_limits<std::size_t>::max()}) {
    bool refused{};
    try { ExtendedPrefixSet invalid(budget, 0U); } catch (const std::invalid_argument &) { refused = true; }
    require(refused);
  }
  Fixture prefixes;
  prefixes.install(a, options(ab));
  prefixes.install(b, options(std::span{ba_bc}.first(1U)));
  std::array<std::uint8_t, 256U> prefix_buffer{};
  TlvWriter prefix_writer(prefix_buffer);
  const std::array<std::uint8_t, 7U> attributes{1U, 4U, 0U, 0U, 0U, 42U, 0U};
  ExtendedPrefix advertised{*ip::parse_ip_prefix("192.0.2.0/24"), 5U, true, false, true,
      std::span{attributes}.first(6U)};
  require(encode_extended_prefix(prefix_writer, advertised));
  const auto valid_prefix = std::vector<std::uint8_t>(prefix_writer.bytes().begin(), prefix_writer.bytes().end());
  advertised.metric = maximum_path_metric + 1U;
  require(encode_extended_prefix(prefix_writer, advertised));
  prefixes.install(b, prefix_writer.bytes(), 3U, 1U, 1U);
  prefixes.install(c, valid_prefix, 3U, 1U, 1U);
  require(graph.rebuild(prefixes.database, selected, prefixes.now) == LinkGraphStatus::applied);
  ExtendedPrefixSet collected(4U, 32U);
  require(collected.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::applied &&
      collected.entries().size() == 1U && collected.entries()[0U].origin == identity(b, 1U) &&
      collected.entries()[0U].prefix == advertised.prefix && collected.entries()[0U].metric == 5U &&
      collected.entries()[0U].down && collected.attributes(0U).size() == 6U &&
      std::equal(collected.attributes(0U).begin(), collected.attributes(0U).end(), attributes.begin()));
  // Collection owns attributes, so subsequent LSDB replacement cannot alter it.
  auto replaced_prefix = valid_prefix;
  replaced_prefix.back() = 99U;
  prefixes.install(b, replaced_prefix, 3U, 2U, 1U);
  require(collected.attributes(0U)[5U] == 42U);
  auto malformed_prefix = valid_prefix;
  ++malformed_prefix[1U];
  malformed_prefix.push_back(0U);
  prefixes.install(b, malformed_prefix, 3U, 3U, 1U);
  require(graph.rebuild(prefixes.database, selected, prefixes.now) == LinkGraphStatus::applied &&
      collected.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::applied &&
      collected.entries().empty() && collected.ignored_options() == 1U);
  prefixes.install(b, valid_prefix, 3U, 4U, 1U);
  require(graph.rebuild(prefixes.database, selected, prefixes.now) == LinkGraphStatus::applied &&
      collected.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::applied);
  ExtendedPrefixSet attributes_small(4U, 5U);
  require(attributes_small.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::capacity &&
      attributes_small.entries().empty());
  // A later capacity failure retains every old record and attribute byte.
  prefixes.install(b, valid_prefix, 3U, 1U, 2U);
  ExtendedPrefixSet one_prefix(1U, 6U);
  prefixes.install(b, {}, 3U, 2U, 2U);
  require(graph.rebuild(prefixes.database, selected, prefixes.now) == LinkGraphStatus::applied &&
      one_prefix.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::applied);
  prefixes.install(b, malformed_prefix, 3U, 3U, 2U);
  require(graph.rebuild(prefixes.database, selected, prefixes.now) == LinkGraphStatus::applied &&
      one_prefix.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::applied &&
      one_prefix.entries().size() == 1U && one_prefix.ignored_options() == 1U);
  prefixes.install(b, valid_prefix, 3U, 4U, 2U);
  require(graph.rebuild(prefixes.database, selected, prefixes.now) == LinkGraphStatus::applied &&
      one_prefix.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::capacity &&
      one_prefix.entries().size() == 1U && one_prefix.attributes(0U)[5U] == 42U);
  require(graph.rebuild(prefixes.database, no_family, prefixes.now) == LinkGraphStatus::applied &&
      one_prefix.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::invalid_selection &&
      one_prefix.entries().size() == 1U);
  require(graph.rebuild(prefixes.database, {node(4U), 0U, ipv4_nlpid, GraphMetricStyle::wide}, prefixes.now) == LinkGraphStatus::applied &&
      one_prefix.rebuild(prefixes.database, graph, prefixes.now) == PrefixSetStatus::applied && one_prefix.entries().empty());

  Fixture mt_prefixes;
  mt_prefixes.install(a, options(ab, both, true, 2U));
  mt_prefixes.install(b, options(std::span{ba_bc}.first(1U), mt2, true, 2U));
  TlvWriter mt_prefix_writer(prefix_buffer);
  ExtendedPrefix v6_prefix{*ip::parse_ip_prefix("2001:db8:42::/64"), maximum_path_metric, true, true, false, {}};
  require(encode_extended_prefix(mt_prefix_writer, v6_prefix) &&
      encode_mt_prefix(mt_prefix_writer, 2U, v6_prefix) && encode_mt_prefix(mt_prefix_writer, 3U, v6_prefix));
  mt_prefixes.install(b, mt_prefix_writer.bytes(), 3U, 1U, 1U);
  mt_prefixes.install(pn, mt_prefix_writer.bytes());
  // A received, well-framed MT2 option can still carry a prohibited link-local
  // prefix. Keep the LSP but exclude that entry from normal prefix decisions.
  const std::array<std::uint8_t, 18U> link_local_mt{237U, 16U, 0U, 2U,
      0U, 0U, 0U, 5U, 0U, 64U, 0xfeU, 0x80U, 0U, 0U, 0U, 0U, 0U, 0U};
  mt_prefixes.install(b, link_local_mt, 3U, 1U, 2U);
  require(graph.rebuild(mt_prefixes.database, {a, 2U, ipv6_nlpid, GraphMetricStyle::wide}, mt_prefixes.now) == LinkGraphStatus::applied &&
      collected.rebuild(mt_prefixes.database, graph, mt_prefixes.now) == PrefixSetStatus::applied &&
      collected.entries().size() == 1U && collected.entries()[0U].origin == identity(b, 1U) &&
      collected.entries()[0U].metric == maximum_path_metric && collected.entries()[0U].external &&
      collected.entries()[0U].down && collected.entries()[0U].prefix == v6_prefix.prefix);
  // MT membership changes on fragment zero immediately gate retained prefixes.
  mt_prefixes.install(b, options(std::span{ba_bc}.first(1U)), 3U, 2U);
  require(graph.rebuild(mt_prefixes.database, {a, 2U, ipv6_nlpid, GraphMetricStyle::wide}, mt_prefixes.now) == LinkGraphStatus::applied &&
      collected.rebuild(mt_prefixes.database, graph, mt_prefixes.now) == PrefixSetStatus::applied && collected.entries().empty());

  PrefixPath path{ip::AddressFamily::ipv4, MetricStyle::narrow, 1U, false, false, false, 10U, 100U};
  require(prefix_distance(path) == PrefixDistance{0U, 110U, 0U});
  path.external_route = true;
  require(prefix_distance(path) == PrefixDistance{0U, 110U, 0U});
  path.external_metric = true;
  require(prefix_distance(path) == PrefixDistance{3U, 10U, 100U});
  path.down = true;
  require(prefix_distance(path) == PrefixDistance{5U, 10U, 100U});
  path.level = 2U;
  require(prefix_distance(path) == PrefixDistance{4U, 10U, 100U});
  path.external_route = false;
  require(!prefix_distance(path));
  path.external_metric = false;
  require(prefix_distance(path) == PrefixDistance{1U, 110U, 0U});
  path.advertised_metric = 63U;
  path.origin_distance = 960U;
  require(prefix_distance(path) == PrefixDistance{1U, 1023U, 0U});
  ++path.origin_distance;
  require(!prefix_distance(path));
  path.style = MetricStyle::wide;
  path.advertised_metric = maximum_path_metric;
  path.origin_distance = 1U;
  require(prefix_distance(path) == PrefixDistance{1U, maximum_path_metric, 0U});
  ++path.advertised_metric;
  require(!prefix_distance(path));
  path.family = ip::AddressFamily::ipv6;
  path.advertised_metric = 1U;
  path.origin_distance = 10U;
  require(prefix_distance(path) == PrefixDistance{2U, 11U, 0U});
  path.level = 1U;
  require(prefix_distance(path) == PrefixDistance{3U, 11U, 0U});
  path.down = false;
  require(prefix_distance(path) == PrefixDistance{0U, 11U, 0U});
  path.level = 2U;
  require(prefix_distance(path) == PrefixDistance{1U, 11U, 0U});
  path.style = MetricStyle::narrow;
  require(!prefix_distance(path));
  path.style = MetricStyle::wide;
  path.level = 0U;
  require(!prefix_distance(path));
  require(PrefixDistance{0U, maximum_path_metric, 0U} < PrefixDistance{1U, 0U, 0U} &&
      PrefixDistance{3U, 1U, 1000U} < PrefixDistance{3U, 2U, 1U} &&
      PrefixDistance{3U, 1U, 9U} < PrefixDistance{3U, 1U, 10U});

  Fixture atomic_prefixes;
  atomic_prefixes.install(a, options(ab));
  atomic_prefixes.install(b, options(std::span{ba_bc}.first(1U)));
  atomic_prefixes.install(b, valid_prefix, 3U, 1U, 1U);
  P2pRouteDecision prefix_decision(8U, 16U, 32U, MetricStyle::wide, PrefixCollectionBudget{1U, 6U});
  require(prefix_decision.calculate(atomic_prefixes.database, selected, std::span{local_seeds}.first(1U), 2U,
      atomic_prefixes.now) == DecisionStatus::applied && prefix_decision.prefixes().size() == 1U &&
      prefix_decision.prefixes()[0U].level == 1U &&
      prefix_decision.distance_to_prefix(0U) == PrefixDistance{2U, 35U, 0U});
  std::array<std::uint8_t, 64U> hello_storage{};
  TlvWriter hello_writer(hello_storage);
  const std::array<std::uint8_t, 1U> hello_protocols{ipv4_nlpid};
  const std::array<packet::Ipv4, 1U> hello_addresses{{{192U, 0U, 2U, 2U}}};
  require(hello_writer.append(129U, hello_protocols) &&
      encode_fixed_addresses<4U>(hello_writer, 132U, hello_addresses));
  P2pSnapshot accepted;
  std::copy_n(b.begin(), accepted.neighbor_system.size(), accepted.neighbor_system.begin());
  accepted.present = accepted.iso_up = true;
  accepted.usage = Levels::both;
  std::array<std::optional<AdjacencyNextHop>, 2U> bindings{
      bind_p2p_next_hop(accepted, hello_writer.bytes(), hello_protocols,
          {42U, 7U, 1U}, 1U, *ip::parse_ip_address("192.0.2.2")),
      bind_p2p_next_hop(accepted, hello_writer.bytes(), hello_protocols,
          {43U, 8U, 2U}, 1U, *ip::parse_ip_address("192.0.2.2"))};
  std::array<PrefixRouteCandidate, 2U> routes{};
  auto candidate_result = collect_prefix_routes(prefix_decision, bindings, routes);
  require(candidate_result.status == PrefixRoutesStatus::applied && candidate_result.count == 1U &&
      routes[0U].distance == PrefixDistance{2U, 35U, 0U} &&
      routes[0U].destination == prefix_decision.prefixes()[0U].prefix &&
      routes[0U].origin == prefix_decision.prefixes()[0U].origin &&
      routes[0U].next_hop.interface.interface_id == 42U && routes[0U].down);
  const auto rib_candidate = make_ipv4_rib_input(routes[0U], 7U, 15U);
  require(rib_candidate && rib_candidate->metric == 35U && rib_candidate->isis_rank == 2U &&
      rib_candidate->interface_id == 42U && rib_candidate->interface_generation == 7U &&
      rib_candidate->protocol_instance == 7U && rib_candidate->next_hop == 0xc0000202U &&
      rib_candidate->source == lab::routing::RouteSource::isis && !make_ipv6_rib_input(routes[0U], 7U, 15U));
  const auto retained_routes = routes;
  require(collect_prefix_routes(prefix_decision, bindings, {}).status == PrefixRoutesStatus::capacity &&
      routes == retained_routes);
  require(collect_prefix_routes(prefix_decision, {}, routes).status == PrefixRoutesStatus::invalid &&
      routes == retained_routes);
  bindings[0U]->level = 2U;
  require(collect_prefix_routes(prefix_decision, bindings, routes).status == PrefixRoutesStatus::invalid &&
      routes == retained_routes);
  bindings[0U]->level = 1U;
  bindings[0U]->address = *ip::parse_ip_address("fe80::2");
  require(collect_prefix_routes(prefix_decision, bindings, routes).status == PrefixRoutesStatus::invalid &&
      routes == retained_routes);
  bindings[0U].reset();
  candidate_result = collect_prefix_routes(prefix_decision, bindings, routes);
  require(candidate_result.status == PrefixRoutesStatus::applied && candidate_result.count == 0U);
  bindings[0U] = retained_routes[0U].next_hop;
  auto equal_seeds = local_seeds;
  equal_seeds[1U].metric = equal_seeds[0U].metric;
  require(prefix_decision.calculate(atomic_prefixes.database, selected, equal_seeds, 2U,
      atomic_prefixes.now) == DecisionStatus::applied);
  candidate_result = collect_prefix_routes(prefix_decision, bindings, routes);
  require(candidate_result.status == PrefixRoutesStatus::applied && candidate_result.count == 2U &&
      routes[0U].next_hop.interface.interface_id == 42U &&
      routes[1U].next_hop.interface.interface_id == 43U && routes[0U].distance == routes[1U].distance);
  const auto retained_ecmp = routes;
  require(collect_prefix_routes(prefix_decision, bindings, std::span{routes}.first(1U)).status ==
      PrefixRoutesStatus::capacity && routes == retained_ecmp);
  atomic_prefixes.install(b, valid_prefix, 3U, 1U, 2U);
  auto more_expensive = local_seeds;
  more_expensive[0U].metric = 50U;
  require(prefix_decision.calculate(atomic_prefixes.database, selected, std::span{more_expensive}.first(1U), 2U,
      atomic_prefixes.now) == DecisionStatus::capacity && prefix_decision.prefixes().size() == 1U &&
      prefix_decision.cost(b) == 30U && prefix_decision.prefix_attributes(0U)[5U] == 42U &&
      prefix_decision.distance_to_prefix(0U) == PrefixDistance{2U, 35U, 0U});
  atomic_prefixes.install(b, {}, 3U, 2U, 2U);
  P2pRouteDecision small_pending(8U, 16U, 1U, MetricStyle::wide, PrefixCollectionBudget{4U, 32U});
  require(small_pending.calculate(atomic_prefixes.database, selected, std::span{local_seeds}.first(1U), 2U,
      atomic_prefixes.now) == DecisionStatus::applied);
  atomic_prefixes.install(c, options({}));
  atomic_prefixes.install(b, replaced_prefix, 3U, 2U, 1U);
  const std::array split_seeds{local_seeds[0U], P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 3U}, 1U, 1U}};
  require(small_pending.calculate(atomic_prefixes.database, selected, split_seeds, 2U,
      atomic_prefixes.now) == DecisionStatus::calculation_failed && small_pending.cost(b) == 30U &&
      small_pending.prefixes().size() == 1U && small_pending.prefix_attributes(0U)[5U] == 42U &&
      small_pending.distance_to_prefix(0U) == PrefixDistance{2U, 35U, 0U});
  require(prefix_decision.calculate(atomic_prefixes.database, {node(4U), 0U, ipv4_nlpid, GraphMetricStyle::wide},
      {}, 0U, atomic_prefixes.now) == DecisionStatus::applied && prefix_decision.prefixes().empty() &&
      !prefix_decision.cost(b) && !prefix_decision.distance_to_prefix(0U));
  atomic_prefixes.install(b, valid_prefix, 3U, 3U, 1U);
  require(graph.rebuild(atomic_prefixes.database, selected, atomic_prefixes.now) == LinkGraphStatus::applied);
  ExtendedPrefixSet transaction(4U, 32U);
  require(transaction.rebuild(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::applied);
  atomic_prefixes.install(b, replaced_prefix, 3U, 4U, 1U);
  require(graph.rebuild(atomic_prefixes.database, selected, atomic_prefixes.now) == LinkGraphStatus::applied &&
      transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::applied &&
      transaction.attributes(0U)[5U] == 42U);
  transaction.abort();
  require(!transaction.commit() && transaction.attributes(0U)[5U] == 42U);
  require(transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::applied &&
      transaction.commit() && transaction.attributes(0U)[5U] == 99U && !transaction.commit());
  require(transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::applied &&
      graph.rebuild(atomic_prefixes.database, no_family, atomic_prefixes.now) == LinkGraphStatus::applied &&
      transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::invalid_selection &&
      !transaction.commit() && transaction.attributes(0U)[5U] == 99U);

}
