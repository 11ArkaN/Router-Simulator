// Encoded local L1 databases and completed SPF generations exercise hierarchy
// fallback selection. Each fixture owns its bytes, clocks and accepted-Hello
// bindings; no remote runtime or editor topology supplies routing knowledge.
#include "router/isis_attached_default.hpp"
#include "router/isis_area_attachment.hpp"
#include "router/isis_area_set.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/isis_rib_input.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS attached default invariant at " + std::to_string(where.line()));
}
LanId node(std::uint8_t index, std::uint8_t pseudonode = 0U) { return {1U, 2U, 3U, 4U, 5U, index, pseudonode}; }
LspId identity(LanId source, std::uint8_t fragment = 0U) {
  LspId id{}; std::copy(source.begin(), source.end(), id.begin()); id.back() = fragment; return id;
}
std::vector<std::uint8_t> options(std::span<const ExtendedNeighbor> links,
    std::optional<TopologyComponent> topology = {}, std::span<const ExtendedPrefix> prefixes = {}) {
  std::array<std::uint8_t, 1024U> bytes{};
  TlvWriter writer(bytes);
  const std::array protocols{ipv4_nlpid, ipv6_nlpid};
  require(writer.append(129U, protocols));
  if (topology) {
    const std::array components{*topology};
    require(encode_topologies(writer, components, true));
  }
  for (const auto &link : links)
    require(topology ? encode_mt_neighbor(writer, topology->id, link) : encode_extended_neighbor(writer, link));
  for (const auto &prefix : prefixes) require(encode_extended_prefix(writer, prefix));
  return {writer.bytes().begin(), writer.bytes().end()};
}
struct Fixture {
  PduType type;
  LinkStateDatabase database;
  explicit Fixture(PduType selected = PduType::lsp_l1) : type(selected), database(selected, {16U, 32768U}) {}
  std::unique_ptr<PduScratch> scratch{std::make_unique<PduScratch>()};
  RuntimeClock::time_point now{};
  std::uint32_t sequence{};
  void install(LanId source, std::span<const std::uint8_t> bytes, std::uint8_t flags,
      std::uint8_t fragment = 0U, std::uint16_t lifetime = 1200U) {
    LspContents content;
    content.header = {type, identity(source, fragment), lifetime, ++sequence, flags};
    content.options = bytes; content.maximum_pdu_octets = 1492U;
    const auto encoded = build_lsp_pdu(content, scratch->options, scratch->pdu);
    require(encoded.status == LspBuildStatus::encoded &&
        database.install(encoded.bytes, now, 1200U, 60s) == LspInstallResult::installed);
  }
};
auto bindings(ip::AddressFamily family) {
  std::array<std::optional<AdjacencyNextHop>, 3U> result;
  for (std::size_t index{}; index < result.size(); ++index) {
    std::array<std::uint8_t, 96U> bytes{};
    TlvWriter hello(bytes);
    const std::array protocols{ipv4_nlpid, ipv6_nlpid};
    const std::array<packet::Ipv4, 1U> ipv4{packet::Ipv4{192U, 0U, 2U, static_cast<std::uint8_t>(index + 2U)}};
    const std::array<packet::Ipv6, 1U> ipv6{*ip::parse_ipv6("fe80::" + std::to_string(index + 2U))};
    require(hello.append(129U, protocols) && encode_fixed_addresses<4U>(hello, 132U, ipv4) &&
        encode_fixed_addresses<16U>(hello, 232U, ipv6));
    P2pSnapshot peer; peer.present = peer.iso_up = true; peer.usage = Levels::both;
    const auto source = node(static_cast<std::uint8_t>(index + 2U));
    std::copy_n(source.begin(), peer.neighbor_system.size(), peer.neighbor_system.begin());
    const auto selected = family == ip::AddressFamily::ipv6 ? ip::IpAddress{family, ipv6.front()} :
        *ip::parse_ip_address("192.0.2." + std::to_string(index + 2U));
    result[index] = bind_p2p_next_hop(peer, hello.bytes(), protocols,
        {42U + index, 7U, static_cast<std::uint16_t>(index + 1U)}, 1U, selected);
    require(result[index].has_value());
  }
  return result;
}
}
void isis_attached_default_tests() {
  const packet::isis::SystemId local_system{1U, 2U, 3U, 4U, 5U, 1U};
  Fixture f;
  const auto a = node(1U), b = node(2U), c = node(3U), d = node(4U);
  const std::array local{ExtendedNeighbor{b, 10U, {}}, ExtendedNeighbor{c, 10U, {}}, ExtendedNeighbor{d, 20U, {}}};
  const std::array back{ExtendedNeighbor{a, 10U, {}}};
  f.install(a, options(local), 1U);
  f.install(b, options(back), 11U); f.install(c, options(back), 11U); f.install(d, options(back), 11U);
  const std::array seeds{P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 2U}, 10U, 0U},
      P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 3U}, 10U, 1U}, P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 4U}, 20U, 2U}};
  const DecisionConfiguration configuration{8U, 24U, 64U, MetricStyle::wide, PrefixCollectionBudget{8U, 128U}};
  P2pRouteDecision decision(8U, 24U, 64U, MetricStyle::wide, configuration.prefixes);
  const auto calculate = [&](std::uint8_t protocol, std::uint16_t topology = 0U) {
    require(decision.calculate(f.database, {a, topology, protocol, GraphMetricStyle::wide}, seeds, 3U, f.now) == DecisionStatus::applied);
  };
  auto next_hops = bindings(ip::AddressFamily::ipv4);
  std::array<PrefixRouteCandidate, 4U> routes;
  calculate(ipv4_nlpid);
  auto result = collect_attached_default_routes(f.database, decision, next_hops, {}, f.now, routes);
  require(result.status == PrefixRoutesStatus::applied && result.count == 2U);
  require(routes[0U].destination == *ip::parse_ip_prefix("0.0.0.0/0") &&
      routes[0U].distance == PrefixDistance{0U, 10U, 0U} && routes[0U].next_hop.interface.interface_id == 42U &&
      routes[1U].next_hop.interface.interface_id == 43U);
  const auto mapped = make_ipv4_rib_input(routes[0U], 0U, 15U);
  require(mapped && mapped->prefix_length == 0U && mapped->metric == 10U && mapped->preference == 15U);
  const auto saved_routes = routes;
  require(collect_attached_default_routes(f.database, decision, next_hops, {}, f.now,
      std::span{routes}.first(1U)).status == PrefixRoutesStatus::capacity && routes == saved_routes);
  auto invalid = next_hops; invalid[0U]->level = 2U;
  require(collect_attached_default_routes(f.database, decision, invalid, {}, f.now, routes).status == PrefixRoutesStatus::invalid && routes == saved_routes);
  require(collect_attached_default_routes(f.database, decision, next_hops, {ip::AddressFamily::ipv4, 0U, true}, f.now, routes).count == 0U);
  auto restored = P2pRouteDecision::restore_checkpoint(decision.checkpoint(), configuration);
  require(restored && collect_attached_default_routes(f.database, *restored, next_hops, {}, f.now, routes).count == 2U && routes == saved_routes);
  // L1 overload prevents transit through an exit, but does not remove the
  // directly reachable exit's independent L2 attachment.
  f.install(b, options(back), 15U); calculate(ipv4_nlpid);
  require(collect_attached_default_routes(f.database, decision, next_hops, {}, f.now, routes).count == 2U);
  f.install(b, options(back), 11U); calculate(ipv4_nlpid);
  // Unresolved nearest exits do not manufacture a different, more costly SPF.
  invalid = next_hops; invalid[0U].reset(); invalid[1U].reset();
  require(collect_attached_default_routes(f.database, decision, invalid, {}, f.now, routes).count == 0U);
  f.install(a, options(local), 11U); calculate(ipv4_nlpid);
  require(collect_attached_default_routes(f.database, decision, next_hops, {}, f.now, routes).count == 0U);
  f.install(a, options(local), 1U);
  ExtendedPrefix explicit_v4; explicit_v4.metric = 50U;
  const std::array v4_default{explicit_v4};
  f.install(b, options(back, {}, v4_default), 11U); calculate(ipv4_nlpid);
  require(collect_attached_default_routes(f.database, decision, next_hops, {}, f.now, routes).count == 0U);
  calculate(ipv6_nlpid); next_hops = bindings(ip::AddressFamily::ipv6);
  const AttachedDefaultSelection v6{ip::AddressFamily::ipv6};
  result = collect_attached_default_routes(f.database, decision, next_hops, v6, f.now, routes);
  require(result.count == 2U && routes[0U].destination == *ip::parse_ip_prefix("::/0") &&
      make_ipv6_rib_input(routes[0U], 0U, 15U).has_value());
  ExtendedPrefix explicit_v6; explicit_v6.prefix.network.family = ip::AddressFamily::ipv6; explicit_v6.metric = 70U;
  const std::array defaults{explicit_v4, explicit_v6};
  f.install(b, options(back, {}, defaults), 11U); calculate(ipv6_nlpid);
  require(collect_attached_default_routes(f.database, decision, next_hops, v6, f.now, routes).count == 0U);
  // A fragment or pseudonode cannot attach an otherwise unattached root.
  f.install(b, options(back), 3U); f.install(b, options(back), 11U, 1U);
  f.install(c, options(back), 1U); f.install(node(3U, 7U), options({}), 11U);
  f.install(d, options(back), 3U); calculate(ipv6_nlpid);
  require(collect_attached_default_routes(f.database, decision, next_hops, v6, f.now, routes).count == 0U);
  f.install(b, options(back), 11U, 0U, 1U); f.install(c, options(back), 11U);
  f.now += 2s; calculate(ipv6_nlpid);
  result = collect_attached_default_routes(f.database, decision, next_hops, v6, f.now, routes);
  require(result.count == 1U && routes[0U].next_hop.interface.interface_id == 43U);
  // Base-header ATT never substitutes for the selected MT's attached flag.
  f.install(a, options(local, TopologyComponent{2U}), 1U);
  for (const auto id : {b, c, d}) f.install(id, options(back, TopologyComponent{2U}), 11U);
  calculate(ipv6_nlpid, 2U);
  require(collect_attached_default_routes(f.database, decision, next_hops, {ip::AddressFamily::ipv6, 2U}, f.now, routes).count == 0U);
  f.install(b, options(back, TopologyComponent{2U, false, true}), 3U);
  f.install(c, options(back, TopologyComponent{2U, false, true}), 3U);
  calculate(ipv6_nlpid, 2U);
  require(collect_attached_default_routes(f.database, decision, next_hops, {ip::AddressFamily::ipv6, 2U}, f.now, routes).count == 2U);
  P2pRouteDecision area_decision(8U, 24U, 64U, MetricStyle::wide);
  Fixture backbone{PduType::lsp_l2};
  const NeighborArea ours{{0x49U, 0U, 1U}, 3U}, remote{{0x49U, 0U, 2U}, 3U};
  const std::array local_areas{ours};
  const auto area_options = [&](const NeighborArea &area, std::span<const ExtendedNeighbor> links) {
    auto encoded = options(links);
    std::array<std::uint8_t, 32U> bytes{};
    TlvWriter writer(bytes); const std::array areas{area.view()};
    require(encode_area_addresses(writer, areas));
    encoded.insert(encoded.end(), writer.bytes().begin(), writer.bytes().end());
    return encoded;
  };
  backbone.install(a, area_options(ours, local), 3U);
  backbone.install(b, area_options(ours, back), 3U);
  backbone.install(c, area_options(ours, back), 3U);
  backbone.install(d, area_options(remote, {}), 3U);
  const auto backbone_spf = [&] {
    require(area_decision.calculate(backbone.database, {a, 0U, std::nullopt, GraphMetricStyle::wide},
        std::span{seeds}.first(2U), 3U, backbone.now) == DecisionStatus::applied);
  };
  backbone_spf();
  require(!reachable_other_area(backbone.database, area_decision, local_areas, backbone.now, local_system));
  backbone.install(b, area_options(remote, back), 3U, 0U, 1U); backbone_spf();
  require(reachable_other_area(backbone.database, area_decision, local_areas, backbone.now, local_system));
  backbone.now += 2s; backbone_spf();
  require(!reachable_other_area(backbone.database, area_decision, local_areas, backbone.now, local_system));
  backbone.install(a, area_options(remote, local), 3U); backbone_spf();
  require(!reachable_other_area(backbone.database, area_decision, local_areas, backbone.now, local_system));
  backbone.install(a, area_options(ours, local), 3U); backbone_spf();
  Fixture merged;
  const NeighborArea lower{{0x48U}, 1U}, unreachable{{0x47U}, 1U};
  merged.install(a, area_options(ours, local), 3U);
  merged.install(b, area_options(remote, back), 3U);
  merged.install(c, area_options(lower, back), 3U);
  merged.install(d, area_options(unreachable, {}), 3U);
  merged.install(b, area_options(unreachable, back), 3U, 1U);
  require(area_decision.calculate(merged.database, {a, 0U, std::nullopt, GraphMetricStyle::wide},
      std::span{seeds}.first(2U), 3U, merged.now) == DecisionStatus::applied);
  std::array<NeighborArea, 2U> area_set;
  require(collect_area_addresses(merged.database, area_decision, merged.now, area_set) == 2U &&
      area_set[0U] == lower && area_set[1U] == ours);
  require(collect_area_addresses(merged.database, area_decision, merged.now, std::span{area_set}.first(1U)) == 1U &&
      area_set[0U] == lower);
  require(!collect_area_addresses(backbone.database, area_decision, merged.now, area_set));
  P2pRouteDecision backbone_decision(8U, 24U, 64U, MetricStyle::wide);
  backbone.install(b, area_options(remote, back), 3U);
  require(backbone_decision.calculate(backbone.database, {a, 0U, std::nullopt, GraphMetricStyle::wide},
      std::span{seeds}.first(2U), 3U, backbone.now) == DecisionStatus::applied);
  require(derive_area_attachment(merged.database, area_decision, backbone.database,
      backbone_decision, 2U, false, backbone.now, local_system) == true);
  require(derive_area_attachment(merged.database, area_decision, backbone.database,
      backbone_decision, 2U, true, backbone.now, local_system) == false);
  require(!derive_area_attachment(merged.database, area_decision, backbone.database,
      backbone_decision, 0U, false, backbone.now, local_system));
  const std::array manual_areas{remote, ours};
  AreaAddressSet owned_areas(2U, manual_areas);
  std::vector<NeighborArea> notifications;
  notifications.reserve(4U);
  const AreaSetObserver area_observer{&notifications, +[](void *opaque, const ManualAreaDropped &event) noexcept {
    static_cast<std::vector<NeighborArea> *>(opaque)->push_back(event.area);
  }};
  const auto dropped = owned_areas.recompute(merged.database, area_decision, merged.now, area_observer);
  require(dropped.valid && dropped.changed && dropped.events == 1U && notifications.size() == 1U &&
      notifications.back() == remote && owned_areas.manual_addresses_dropped() == 1U);
  require(owned_areas.recompute(merged.database, area_decision, merged.now, area_observer).events == 0U);
  auto area_image = owned_areas.checkpoint();
  AreaAddressSet resumed_areas(2U, manual_areas);
  require(resumed_areas.restore(area_image) &&
      resumed_areas.recompute(merged.database, area_decision, merged.now, area_observer).events == 0U);
  area_image.rejected[0U] = 2U;
  require(!resumed_areas.restore(area_image) && resumed_areas.manual_addresses_dropped() == 1U);
  require(!owned_areas.recompute(backbone.database, area_decision, merged.now, area_observer).valid &&
      owned_areas.manual_addresses_dropped() == 1U && notifications.size() == 1U);
  const auto merged_spf = [&] {
    require(area_decision.calculate(merged.database, {a, 0U, std::nullopt, GraphMetricStyle::wide},
        std::span{seeds}.first(2U), 3U, merged.now) == DecisionStatus::applied);
  };
  merged.install(c, area_options(ours, back), 3U); merged_spf();
  require(owned_areas.recompute(merged.database, area_decision, merged.now, area_observer).events == 0U &&
      notifications.size() == 1U && owned_areas.effective().size() == 2U);
  area_image = owned_areas.checkpoint();
  area_image.manual_addresses_dropped = UINT32_MAX;
  require(owned_areas.restore(area_image));
  merged.install(c, area_options(lower, back), 3U); merged_spf();
  require(owned_areas.recompute(merged.database, area_decision, merged.now, area_observer).events == 1U &&
      notifications.size() == 2U && notifications.back() == remote && owned_areas.manual_addresses_dropped() == 0U);
  owned_areas.reset_to_manual();
  require(owned_areas.manual_addresses_dropped() == 0U && notifications.size() == 2U);
  require(owned_areas.recompute(merged.database, area_decision, merged.now, area_observer).events == 1U &&
      owned_areas.manual_addresses_dropped() == 1U && notifications.size() == 3U);
  Fixture incomplete_area;
  incomplete_area.install(a, area_options(ours, {}), 1U);
  P2pRouteDecision incomplete_decision(8U, 24U, 64U, MetricStyle::wide);
  require(incomplete_decision.calculate(incomplete_area.database, {a, 0U, std::nullopt, GraphMetricStyle::wide},
      {}, 3U, incomplete_area.now) == DecisionStatus::applied);
  AreaAddressSet missing_manual(2U, manual_areas);
  require(missing_manual.recompute(incomplete_area.database, incomplete_decision, incomplete_area.now, area_observer).events == 0U &&
      notifications.size() == 3U && missing_manual.manual_addresses_dropped() == 0U);
  // Two attached exits behind the same actual first hop produce one candidate.
  Fixture shared;
  const std::array to_b{ExtendedNeighbor{b, 5U, {}}};
  const std::array from_b{ExtendedNeighbor{a, 5U, {}}, ExtendedNeighbor{c, 5U, {}}, ExtendedNeighbor{d, 5U, {}}};
  const std::array to_b_again{ExtendedNeighbor{b, 5U, {}}};
  shared.install(a, options(to_b), 1U); shared.install(b, options(from_b), 3U);
  shared.install(c, options(to_b_again), 11U); shared.install(d, options(to_b_again), 11U);
  const std::array shared_seed{P2pSpfSeed{{1U, 2U, 3U, 4U, 5U, 2U}, 5U, 0U}};
  require(decision.calculate(shared.database, {a, 0U, ipv6_nlpid, GraphMetricStyle::wide}, shared_seed, 3U, shared.now) == DecisionStatus::applied);
  result = collect_attached_default_routes(shared.database, decision, next_hops, v6, shared.now, routes);
  require(result.count == 1U && routes[0U].distance.metric == 10U);
}
