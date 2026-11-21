// One instance control owner derives fallback routes from its current L1 LSDB
// and completed family/topology decision. Inputs remain immutable; temporary
// token bits are local, and no adjacency, timer or remote state is retained.
// Source: iso.10589.2002.attached_default
#pragma once
#include "router/isis_graph_metadata.hpp"
#include "router/isis_prefix_routes.hpp"
#include <algorithm>
#include <array>
namespace router::isis {
struct AttachedDefaultSelection {
  ip::AddressFamily family{ip::AddressFamily::ipv4};
  std::uint16_t topology{};
  bool ignore{};
};
// Same owner: database is L1 and decision/bindings match its current revision,
// selected family and wide topology. ISO 7.2.9 selects the minimum-cost attached
// exits; RFC 1195 defines fallback routing, while RFC 3787 permits explicit
// L1 defaults. A usable explicit default takes precedence over this fallback.
// Local attachment selects Self and produces no next hop. Equal exits share
// one candidate per actual first-hop token, including LAN and parallel links.
// No allocation. Callbacks follow visit_prefix_routes' unpublished-storage
// contract; false reports capacity, and malformed tokens report invalid.
template <typename Visit>
[[nodiscard]] inline PrefixRoutesResult visit_attached_default_routes(
    const LinkStateDatabase &database, const P2pRouteDecision &decision,
    std::span<const std::optional<AdjacencyNextHop>> bindings,
    AttachedDefaultSelection selected, RuntimeClock::time_point now, Visit visit) noexcept {
  if ((selected.family != ip::AddressFamily::ipv4 && selected.family != ip::AddressFamily::ipv6) ||
      selected.topology > packet::isis::maximum_topology_id ||
      bindings.size() > routing::ShortestPaths::maximum_first_hops)
    return {PrefixRoutesStatus::invalid, 0U};
  if (selected.ignore) return {PrefixRoutesStatus::applied, 0U};
  bool explicit_default{};
  const auto prefixes = visit_prefix_routes(decision, bindings, [&](std::size_t, const auto &route) {
    explicit_default = explicit_default || (!route.destination.length && route.destination.network.family == selected.family);
    return true;
  });
  if (prefixes.status != PrefixRoutesStatus::applied) return prefixes;
  if (explicit_default) return {PrefixRoutesStatus::applied, 0U};
  const LinkGraphSelection metadata{{}, selected.topology,
      selected.family == ip::AddressFamily::ipv6 ? packet::isis::ipv6_nlpid : packet::isis::ipv4_nlpid,
      GraphMetricStyle::wide};
  const auto eligible = [&](const StoredLspView &record) {
    if (record.header.id[6U] || record.header.id[7U] || !record.header.remaining_seconds ||
        !record.header.sequence || !record.header.checksum || (record.header.flags & 3U) != 3U) return false;
    const auto root = graph_root_metadata(record, metadata);
    return root.valid && root.supported && root.attached;
  };
  const auto identity = [](const StoredLspView &record) {
    packet::isis::LanId id{};
    std::copy_n(record.header.id.begin(), id.size(), id.begin());
    return id;
  };
  std::optional<std::uint32_t> nearest;
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto record = database.at(index, now);
    if (!record) continue;
    if (record->pdu.type != packet::isis::PduType::lsp_l1) return {PrefixRoutesStatus::invalid, 0U};
    if (!eligible(*record)) continue;
    const auto cost = decision.cost(identity(*record));
    if (cost && (!nearest || *cost < *nearest)) nearest = cost;
  }
  if (!nearest) return {PrefixRoutesStatus::applied, 0U};
  const auto distance = prefix_distance({selected.family, MetricStyle::wide, 1U, false, false, false, 0U, *nearest});
  if (!distance) return {PrefixRoutesStatus::invalid, 0U};
  std::array<std::uint64_t, routing::first_hop_word_count> emitted{};
  std::size_t count{};
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto record = database.at(index, now);
    if (!record || !eligible(*record)) continue;
    const auto id = identity(*record);
    if (decision.cost(id) != nearest) continue;
    for (std::size_t hop{}; hop < decision.first_hop_count(id); ++hop) {
      const auto token = decision.first_hop(id, hop);
      if (!token || *token >= bindings.size()) return {PrefixRoutesStatus::invalid, 0U};
      const auto &binding = bindings[*token];
      if (!binding) continue;
      if (binding->level != 1U || binding->address.family != selected.family) return {PrefixRoutesStatus::invalid, 0U};
      const auto bit = std::uint64_t{1U} << (*token % 64U);
      auto &word = emitted[*token / 64U];
      if (word & bit) continue;
      word |= bit;
      ip::IpPrefix destination;
      destination.network.family = selected.family;
      if (!visit(count, PrefixRouteCandidate{destination, *distance, *binding, record->header.id, false, false}))
        return {PrefixRoutesStatus::capacity, 0U};
      ++count;
    }
  }
  return {PrefixRoutesStatus::applied, count};
}
// Two-pass preflight preserves output on invalid input or insufficient space.
[[nodiscard]] inline PrefixRoutesResult collect_attached_default_routes(
    const LinkStateDatabase &database, const P2pRouteDecision &decision,
    std::span<const std::optional<AdjacencyNextHop>> bindings,
    AttachedDefaultSelection selected, RuntimeClock::time_point now,
    std::span<PrefixRouteCandidate> output) noexcept {
  const auto prepared = visit_attached_default_routes(database, decision, bindings, selected, now,
      [&](std::size_t index, const auto &) { return index < output.size(); });
  if (prepared.status != PrefixRoutesStatus::applied) return prepared;
  return visit_attached_default_routes(database, decision, bindings, selected, now,
      [&](std::size_t index, const auto &candidate) { output[index] = candidate; return true; });
}
}
