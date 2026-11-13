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
  explicit Fixture(LsdbLimits limits = {16U, 32768U}) : database(PduType::lsp_l1, limits) {}
  LinkStateDatabase database;
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
void lan_spf_inputs() {
  Fixture f;
  const auto a = node(1U), b = node(2U), dis = node(3U), c = node(4U), pn = node(3U, 7U);
  const std::array ap{ExtendedNeighbor{pn, 10U, {}}};
  const std::array bp_bc{ExtendedNeighbor{pn, 30U, {}}, ExtendedNeighbor{c, 7U, {}}};
  const std::array dp{ExtendedNeighbor{pn, 20U, {}}};
  const std::array cb{ExtendedNeighbor{b, 8U, {}}};
  f.install(a, options(ap));
  auto b_options = options(bp_bc);
  std::array<std::uint8_t, 64U> prefix_bytes{};
  TlvWriter prefix_writer(prefix_bytes);
  ExtendedPrefix v4;
  v4.prefix.network.bytes = {192U, 0U, 2U, 2U};
  v4.prefix.length = 32U;
  v4.metric = 5U;
  ExtendedPrefix v6;
  v6.prefix.network.family = ip::AddressFamily::ipv6;
  v6.prefix.network.bytes = {0x20U, 1U, 0x0dU, 0xb8U, 0U, 2U};
  v6.prefix.length = 64U;
  v6.metric = 7U;
  require(encode_extended_prefix(prefix_writer, v4) && encode_extended_prefix(prefix_writer, v6));
  b_options.insert(b_options.end(), prefix_writer.bytes().begin(), prefix_writer.bytes().end());
  f.install(b, b_options);
  f.install(dis, options(dp));
  f.install(c, options(cb));
  std::array<std::uint8_t, 128U> pn_bytes{};
  TlvWriter writer(pn_bytes);
  for (const auto id : {a, b, dis}) require(encode_extended_neighbor(writer, {id, 0U, {}}));
  f.install(pn, writer.bytes());
  LinkGraph graph(8U, 32U);
  const LinkGraphSelection selection{a, 0U, ipv4_nlpid, GraphMetricStyle::wide};
  require(graph.rebuild(f.database, selection, f.now) == LinkGraphStatus::applied);
  const auto vertex = [&](LanId id) {
    const auto found = std::find_if(graph.nodes().begin(), graph.nodes().end(), [&](const auto &value) { return value.id == id; });
    require(found != graph.nodes().end());
    return static_cast<std::uint32_t>(found - graph.nodes().begin());
  };
  const std::array<P2pSpfSeed, 1U> dis_only{{{{1U, 2U, 3U, 4U, 5U, 3U}, 10U, 0U}}};
  const std::array lans{LanSpfCircuit{101U, pn, 10U, std::uint16_t{0U}}};
  SpfInput input(8U, 32U);
  SpfCalculator spf(8U, 32U, MetricStyle::wide);
  require(input.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, lans) &&
      input.vertices()[vertex(pn)].tie_priority == 0U && input.vertices()[vertex(b)].tie_priority == 1U &&
      spf.calculate(*graph.root(), input.vertices(), input.edges(), 2U) &&
      spf.cost(vertex(b)) == 10U && spf.first_hop(vertex(b), 0U) == 0U &&
      spf.cost(vertex(c)) == 17U && spf.first_hop(vertex(c), 0U) == 0U);
  // A real local adjacency takes precedence over indirect initialization
  // through the DIS, even while both use the same LAN cost.
  const std::array direct{dis_only[0U], P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 2U}, 10U, 1U}};
  require(input.rebuild(graph, direct, 2U, maximum_link_metric - 1U, lans) &&
      spf.calculate(*graph.root(), input.vertices(), input.edges(), 2U) &&
      spf.cost(vertex(b)) == 10U && spf.first_hop_count(vertex(b)) == 1U && spf.first_hop(vertex(b), 0U) == 1U &&
      spf.cost(vertex(c)) == 17U && spf.first_hop(vertex(c), 0U) == 1U && !spf.first_hop_count(*graph.root()));
  P2pRouteDecision decision(8U, 32U, 64U, MetricStyle::wide, PrefixCollectionBudget{4U, 64U});
  require(decision.calculate(f.database, selection, dis_only, 2U, f.now, lans) == DecisionStatus::applied &&
      decision.cost(b) == 10U && decision.prefixes().size() == 1U &&
      decision.prefixes()[0U].prefix == v4.prefix && decision.distance_to_prefix(0U) == std::optional{PrefixDistance{0U, 15U, 0U}});
  require(decision.calculate(f.database, {a, 0U, ipv6_nlpid, GraphMetricStyle::wide}, direct, 2U,
      f.now, lans) == DecisionStatus::applied && decision.first_hop(b, 0U) == 1U &&
      decision.prefixes().size() == 1U && decision.prefixes()[0U].prefix == v6.prefix &&
      decision.distance_to_prefix(0U) == std::optional{PrefixDistance{0U, 17U, 0U}});
  const auto decision_saved = decision.checkpoint();
  const DecisionConfiguration expected_decision{8U, 32U, 64U, MetricStyle::wide, PrefixCollectionBudget{4U, 64U}};
  auto restored_decision = P2pRouteDecision::restore_checkpoint(decision_saved, expected_decision);
  require(restored_decision && restored_decision->cost(b) == 10U && restored_decision->first_hop(b, 0U) == 1U &&
      restored_decision->prefixes()[0U] == decision.prefixes()[0U] &&
      restored_decision->distance_to_prefix(0U) == decision.distance_to_prefix(0U));
  for (unsigned invalid{}; invalid < 11U; ++invalid) {
    auto bad = decision_saved;
    switch (invalid) {
      case 0U: ++bad.version; break;
      case 1U: ++bad.configuration.links; break;
      case 2U: bad.identities.pop_back(); break;
      case 3U: bad.identities[1U] = bad.identities[0U]; break;
      case 4U: bad.paths.vertices[1U].first_hops[0U] |= 4U; break;
      case 5U: bad.prefixes.reset(); break;
      case 6U: bad.prefixes->entries[0U].origin[0U] ^= 1U; break;
      case 7U: bad.prefixes->entries[0U].prefix.length = 129U; break;
      case 8U: bad.prefixes->entries[0U].attributes_offset = 1U; break;
      case 9U: bad.prefixes->attributes.push_back(1U); break;
      default: bad.prefixes->entries[0U].level = 0U; break;
    }
    require(!P2pRouteDecision::restore_checkpoint(bad, expected_decision) && restored_decision->first_hop(b, 0U) == 1U);
  }
  require(restored_decision->calculate(f.database, selection, dis_only, 2U, f.now, lans) == DecisionStatus::applied &&
      restored_decision->distance_to_prefix(0U) == PrefixDistance{0U, 15U, 0U});
  const std::vector<SpfEdge> saved(input.edges().begin(), input.edges().end());
  const auto unchanged = [&] {
    return std::equal(saved.begin(), saved.end(), input.edges().begin(), input.edges().end(),
        [](const auto &left, const auto &right) {
          return left.target_vertex == right.target_vertex && left.cost == right.cost && left.first_hop == right.first_hop;
        });
  };
  const std::array invalid_token{LanSpfCircuit{101U, pn, 10U, std::uint16_t{1U}}};
  const std::array invalid_metric{LanSpfCircuit{101U, pn, 11U, std::uint16_t{0U}}};
  const std::array unsorted{lans[0U], LanSpfCircuit{100U, pn, 10U, std::uint16_t{0U}}};
  require(!input.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, invalid_token) && unchanged() &&
      !input.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, invalid_metric) && unchanged() &&
      !input.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, unsorted) && unchanged());
  require(decision.calculate(f.database, selection, dis_only, 2U, f.now, invalid_token) == DecisionStatus::invalid &&
      decision.first_hop(b, 0U) == 1U && decision.prefixes()[0U].prefix == v6.prefix &&
      decision.distance_to_prefix(0U) == std::optional{PrefixDistance{0U, 17U, 0U}});
  // A newly selected DIS can still advertise the old winner's LAN ID until
  // its next Hello. Real local adjacencies stay usable without PN fallback.
  require(input.rebuild(graph, direct, 2U, maximum_link_metric - 1U, invalid_token) &&
      spf.calculate(*graph.root(), input.vertices(), input.edges(), 2U) &&
      spf.cost(vertex(b)) == 10U && spf.first_hop(vertex(b), 0U) == 1U);
  SpfInput bounded(8U, 8U);
  require(!bounded.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, lans) && bounded.vertices().empty());
  // A remote LAN remains a normal transit graph for a P2P-only local owner.
  Fixture remote;
  remote.install(a, options(std::array{ExtendedNeighbor{dis, 10U, {}}}));
  remote.install(dis, options(std::array{ExtendedNeighbor{a, 20U, {}}, ExtendedNeighbor{pn, 20U, {}}}));
  remote.install(b, options(bp_bc));
  remote.install(c, options(cb));
  TlvWriter remote_pn(pn_bytes);
  for (const auto id : {b, dis}) require(encode_extended_neighbor(remote_pn, {id, 0U, {}}));
  remote.install(pn, remote_pn.bytes());
  LinkGraph remote_graph(8U, 32U);
  require(remote_graph.rebuild(remote.database, selection, remote.now) == LinkGraphStatus::applied &&
      input.rebuild(remote_graph, dis_only, 2U, maximum_link_metric - 1U) &&
      spf.calculate(*remote_graph.root(), input.vertices(), input.edges(), 2U) && spf.cost(vertex(c)) == 37U);
  auto dis_v6 = options(dp);
  dis_v6[2U] = ipv6_nlpid;
  f.install(dis, dis_v6, 3U, 2U);
  require(graph.rebuild(f.database, selection, f.now) == LinkGraphStatus::applied &&
      input.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, lans) &&
      spf.calculate(*graph.root(), input.vertices(), input.edges(), 2U) && !spf.reachable(vertex(b)));
  f.install(dis, options(dp), 3U, 3U);
  f.install(b, options(std::span(bp_bc).subspan(1U)), 3U, 2U);
  require(graph.rebuild(f.database, selection, f.now) == LinkGraphStatus::applied &&
      input.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, lans) &&
      spf.calculate(*graph.root(), input.vertices(), input.edges(), 2U) && !spf.reachable(vertex(b)));
  f.install(b, options(bp_bc), 3U, 3U);
  f.install(pn, {}, 3U, 2U, 0U, 0U);
  require(graph.rebuild(f.database, selection, f.now) == LinkGraphStatus::applied &&
      input.rebuild(graph, dis_only, 2U, maximum_link_metric - 1U, lans) &&
      spf.calculate(*graph.root(), input.vertices(), input.edges(), 2U) && !spf.reachable(vertex(b)));
  require(input.rebuild(graph, direct, 2U, maximum_link_metric - 1U, lans) &&
      spf.calculate(*graph.root(), input.vertices(), input.edges(), 2U) && spf.cost(vertex(c)) == 17U);
}
void multipart_links() {
  const auto a = node(1U), b = node(2U);
  Fixture f;
  const std::array reverse{ExtendedNeighbor{a, 20U, {}}};
  f.install(b, options(reverse));
  const std::array<std::uint8_t, 10U> id_one{4U, 8U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 7U};
  const std::array<std::uint8_t, 10U> id_two{4U, 8U, 0U, 0U, 0U, 2U, 0U, 0U, 0U, 8U};
  const std::array first{ExtendedNeighbor{b, 30U, id_one}}, later{ExtendedNeighbor{b, 1U, id_one}};
  // Arrival order does not choose which fragment supplies the fixed metric.
  f.install(a, options(later), 3U, 1U, 2U); f.install(a, options(first));
  LinkGraph graph(2U, 16U);
  const LinkGraphSelection selected{a, 0U, ipv4_nlpid, GraphMetricStyle::wide};
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied && arc(graph, a, b, 30U));
  const std::array parallel{ExtendedNeighbor{b, 10U, id_two}};
  f.install(a, options(parallel), 3U, 1U, 3U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied && arc(graph, a, b, 10U));
  const std::array unusable{ExtendedNeighbor{b, maximum_link_metric, id_one}};
  f.install(a, options(unusable), 3U, 2U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied && arc(graph, a, b, 10U));
  f.install(a, {}, 3U, 2U, 3U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      !arc(graph, a, b, 1U) && graph.links().size() == 1U && arc(graph, b, a, 20U));
  std::array<std::uint8_t, 128U> left{}, right{};
  const std::array<std::uint8_t, 4U> local_one{192U, 0U, 2U, 1U}, local_two{192U, 0U, 2U, 3U}, peer{192U, 0U, 2U, 2U};
  TlvWriter left_v4(left), right_v4(right);
  require(left_v4.append(6U, local_one) && left_v4.append(6U, local_two) && left_v4.append(8U, peer) &&
      right_v4.append(8U, peer) && right_v4.append(6U, local_two) && right_v4.append(6U, local_one));
  const std::array v4_first{ExtendedNeighbor{b, 50U, left_v4.bytes()}}, v4_later{ExtendedNeighbor{b, 1U, right_v4.bytes()}};
  f.install(a, options(v4_first), 3U, 3U); f.install(a, options(v4_later), 3U, 2U, 2U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied && arc(graph, a, b, 50U));
  const auto global_one = *ip::parse_ipv6("2001:db8::1"), global_two = *ip::parse_ipv6("2001:db8::3"), peer6 = *ip::parse_ipv6("2001:db8::2");
  TlvWriter left_v6(left), right_v6(right);
  require(left_v6.append(12U, global_one) && left_v6.append(12U, global_two) && left_v6.append(13U, peer6) &&
      right_v6.append(13U, peer6) && right_v6.append(12U, global_two) && right_v6.append(12U, global_one) && right_v6.append(12U, global_one));
  const std::array v6_first{ExtendedNeighbor{b, 60U, left_v6.bytes()}}, v6_later{ExtendedNeighbor{b, 1U, right_v6.bytes()}};
  f.install(a, options(v6_first), 3U, 4U); f.install(a, options(v6_later), 3U, 3U, 2U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied && arc(graph, a, b, 60U));
}
void multipart_prefixes() {
  const auto a = node(1U), b = node(2U);
  const LinkGraphSelection selected{a, 0U, ipv4_nlpid, GraphMetricStyle::wide};
  const auto prefix = *ip::parse_ip_prefix("192.0.2.0/24");
  const auto other = *ip::parse_ip_prefix("192.0.3.0/24");
  const std::array<std::uint8_t, 6U> tag{1U, 4U, 0U, 0U, 0U, 42U};
  const std::array<std::uint8_t, 10U> wide_tag{2U, 8U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 7U};
  const std::array<std::uint8_t, 4U> unknown{250U, 2U, 0xabU, 0xcdU};
  Fixture f;
  f.install(a, options({})); f.install(b, options({}));
  std::array<std::uint8_t, 1492U> buffer{};
  TlvWriter high(buffer);
  require(encode_extended_prefix(high, {prefix, 2U, false, false, true, unknown}) &&
      encode_extended_prefix(high, {other, 9U, false, false, true, wide_tag}));
  f.install(b, high.bytes(), 3U, 1U, 3U);
  TlvWriter low(buffer);
  require(encode_extended_prefix(low, {prefix, 50U, true, false, true, tag}) &&
      encode_extended_prefix(low, {other, 7U, false, false, true, unknown}) &&
      encode_extended_prefix(low, {prefix, 1U, false, false, true, wide_tag}));
  f.install(b, low.bytes(), 3U, 1U, 1U);
  LinkGraph graph(2U, 1U);
  ExtendedPrefixSet collected(16U, 2048U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      collected.rebuild(f.database, graph, f.now) == PrefixSetStatus::applied && collected.entries().size() == 2U);
  require(collected.entries()[0U].origin == identity(b, 1U) && collected.entries()[0U].metric == 50U &&
      collected.entries()[0U].down && collected.entries()[1U].metric == 7U && collected.attributes(0U).size() == 20U);
  std::vector<std::uint8_t> expected(tag.begin(), tag.end());
  expected.insert(expected.end(), wide_tag.begin(), wide_tag.end());
  expected.insert(expected.end(), unknown.begin(), unknown.end());
  require(std::ranges::equal(collected.attributes(0U), expected));
  packet::isis::SystemId peer{};
  std::copy_n(b.begin(), peer.size(), peer.begin());
  const std::array seeds{P2pSpfSeed{peer, 10U, 0U}};
  P2pRouteDecision decision(2U, 4U, 8U, MetricStyle::wide, PrefixCollectionBudget{16U, 2048U});
  require(decision.calculate(f.database, selected, seeds, 1U, f.now) == DecisionStatus::applied &&
      decision.prefixes().size() == 2U && decision.distance_to_prefix(0U) == PrefixDistance{2U, 60U, 0U} &&
      std::ranges::equal(decision.prefix_attributes(0U), expected));
  const auto saved = collected.checkpoint();
  ExtendedPrefixSet restored(16U, 2048U);
  require(saved.version == 2U && restored.restore(saved) && std::ranges::equal(restored.attributes(0U), expected));
  auto invalid = saved; invalid.version = 1U;
  require(!restored.restore(invalid) && std::ranges::equal(restored.attributes(0U), expected));
  invalid = saved; invalid.entries[1U].prefix = invalid.entries[0U].prefix;
  require(!restored.restore(invalid) && restored.entries().size() == 2U);
  // A later cheap part must not resurrect a prefix whose first metric is unusable.
  TlvWriter unusable(buffer);
  require(encode_extended_prefix(unusable, {prefix, maximum_path_metric + 1U, false, false, false, {}}));
  f.install(b, unusable.bytes(), 3U, 2U, 1U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      collected.rebuild(f.database, graph, f.now) == PrefixSetStatus::applied && collected.entries().size() == 1U &&
      collected.entries()[0U].prefix == other);
  TlvWriter empty_parts(buffer);
  require(encode_extended_prefix(empty_parts, {prefix, 100U, true, false, false, {}}) &&
      encode_extended_prefix(empty_parts, {prefix, 1U, false, false, false, {}}));
  f.install(b, empty_parts.bytes(), 3U, 3U, 1U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      collected.rebuild(f.database, graph, f.now) == PrefixSetStatus::applied &&
      collected.entries()[0U].metric == 100U && collected.entries()[0U].down && collected.attributes(0U).size() == unknown.size());
  Fixture mt;
  const std::array topology{TopologyComponent{2U, false, false}};
  mt.install(a, options({}, topology)); mt.install(b, options({}, topology));
  const auto v6 = *ip::parse_ip_prefix("2001:db8::/64");
  TlvWriter mt_parts(buffer);
  require(encode_mt_prefix(mt_parts, 2U, {v6, 70U, true, true, true, tag}) &&
      encode_mt_prefix(mt_parts, 2U, {v6, 1U, false, false, true, wide_tag}));
  mt.install(b, mt_parts.bytes(), 3U, 1U, 1U);
  require(graph.rebuild(mt.database, {a, 2U, ipv6_nlpid, GraphMetricStyle::wide}, mt.now) == LinkGraphStatus::applied &&
      collected.rebuild(mt.database, graph, mt.now) == PrefixSetStatus::applied && collected.entries().size() == 1U &&
      collected.entries()[0U].metric == 70U && collected.entries()[0U].external && collected.entries()[0U].down &&
      collected.attributes(0U).size() == tag.size() + wide_tag.size());
  ExtendedPrefixSet recovered_v6(16U, 2048U);
  require(recovered_v6.restore(collected.checkpoint()) && recovered_v6.entries()[0U].external);
  const std::array<std::uint8_t, 3U> external_flags{4U, 1U, 0x80U}, internal_flags{4U, 1U, 0U};
  TlvWriter external_parts(buffer);
  require(encode_extended_prefix(external_parts, {prefix, 25U, false, false, true, external_flags}) &&
      encode_extended_prefix(external_parts, {prefix, 1U, false, false, true, internal_flags}));
  f.install(b, external_parts.bytes(), 3U, 4U, 1U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      collected.rebuild(f.database, graph, f.now) == PrefixSetStatus::applied && collected.entries()[0U].external &&
      decision.calculate(f.database, selected, seeds, 1U, f.now) == DecisionStatus::applied &&
      decision.prefixes()[0U].external && decision.distance_to_prefix(0U) == PrefixDistance{0U, 35U, 0U});
  auto saved_external = collected.checkpoint();
  require(restored.restore(saved_external) && restored.entries()[0U].external);
  saved_external.entries[0U].external = false;
  require(!restored.restore(saved_external) && restored.entries()[0U].external);
  const std::array<std::uint8_t, 2U> empty_flags{4U, 0U};
  TlvWriter zero_flags(buffer);
  require(encode_extended_prefix(zero_flags, {prefix, 25U, false, false, true, empty_flags}) &&
      encode_extended_prefix(zero_flags, {prefix, 1U, false, false, true, external_flags}));
  f.install(b, zero_flags.bytes(), 3U, 5U, 1U);
  require(graph.rebuild(f.database, selected, f.now) == LinkGraphStatus::applied &&
      collected.rebuild(f.database, graph, f.now) == PrefixSetStatus::applied && !collected.entries()[0U].external);
  // Combined attributes may exceed one wire TLV. The per-object host field is
  // still bounded; overflow must preserve the complete previously joined image.
  Fixture large({128U, 200000U});
  large.install(a, options({})); large.install(b, options({}));
  std::array<std::uint8_t, 246U> attributes{};
  attributes.fill(99U); attributes[0U] = 250U; attributes[1U] = 244U;
  TlvWriter parts(buffer);
  for (unsigned part{}; part < 4U; ++part)
    require(encode_extended_prefix(parts, {prefix, 5U, false, false, true, attributes}));
  const std::vector<std::uint8_t> body(parts.bytes().begin(), parts.bytes().end());
  for (std::uint8_t fragment = 1U; fragment <= 66U; ++fragment) large.install(b, body, 3U, 1U, fragment);
  ExtendedPrefixSet joined(300U, 80000U);
  require(graph.rebuild(large.database, selected, large.now) == LinkGraphStatus::applied &&
      joined.rebuild(large.database, graph, large.now) == PrefixSetStatus::applied && joined.entries().size() == 1U &&
      joined.attributes(0U).size() == 64944U);
  ExtendedPrefixSet recovered(300U, 80000U);
  require(recovered.restore(joined.checkpoint()) && recovered.attributes(0U).size() == 64944U);
  large.install(b, body, 3U, 1U, 67U);
  require(graph.rebuild(large.database, selected, large.now) == LinkGraphStatus::applied &&
      joined.rebuild(large.database, graph, large.now) == PrefixSetStatus::capacity &&
      joined.attributes(0U).size() == 64944U && joined.entries()[0U].metric == 5U);
}
}
void isis_link_graph_tests() {
  lan_spf_inputs();
  multipart_links();
  multipart_prefixes();
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
  const auto missing_saved = decision.checkpoint();
  require(missing_saved.identities.empty() && missing_saved.paths.vertices.empty());
  auto missing_restored = P2pRouteDecision::restore_checkpoint(missing_saved, {8U, 16U, 64U, MetricStyle::wide, {}});
  require(missing_restored && !missing_restored->cost(a) && !missing_restored->cost(c));
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
      collected.entries()[0U].down && collected.attributes(0U).size() == 12U &&
      std::equal(collected.attributes(0U).begin(), collected.attributes(0U).begin() + 6U, attributes.begin()) &&
      std::equal(collected.attributes(0U).begin() + 6U, collected.attributes(0U).end(), attributes.begin()));
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
  const auto retained_prefixes = prefix_decision.checkpoint();
  const DecisionConfiguration prefix_policy{8U, 16U, 32U, MetricStyle::wide, PrefixCollectionBudget{1U, 6U}};
  auto prefix_restored = P2pRouteDecision::restore_checkpoint(retained_prefixes, prefix_policy);
  require(prefix_restored && std::ranges::equal(prefix_restored->prefix_attributes(0U), prefix_decision.prefix_attributes(0U)));
  auto bad_attributes = retained_prefixes;
  bad_attributes.prefixes->attributes[1U] = 255U;
  require(!P2pRouteDecision::restore_checkpoint(bad_attributes, prefix_policy));
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
  const auto before_prepared = transaction.checkpoint();
  atomic_prefixes.install(b, replaced_prefix, 3U, 4U, 1U);
  require(graph.rebuild(atomic_prefixes.database, selected, atomic_prefixes.now) == LinkGraphStatus::applied &&
      transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::applied &&
      transaction.attributes(0U)[5U] == 42U);
  bool prepared_capture_refused{};
  try { static_cast<void>(transaction.checkpoint()); }
  catch (const std::invalid_argument &) { prepared_capture_refused = true; }
  require(prepared_capture_refused && !transaction.restore(before_prepared) && transaction.attributes(0U)[5U] == 42U);
  transaction.abort();
  require(!transaction.commit() && transaction.attributes(0U)[5U] == 42U);
  require(transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::applied &&
      transaction.commit() && transaction.attributes(0U)[5U] == 99U && !transaction.commit());
  require(transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::applied &&
      graph.rebuild(atomic_prefixes.database, no_family, atomic_prefixes.now) == LinkGraphStatus::applied &&
      transaction.prepare(atomic_prefixes.database, graph, atomic_prefixes.now) == PrefixSetStatus::invalid_selection &&
      !transaction.commit() && transaction.attributes(0U)[5U] == 99U);

}
