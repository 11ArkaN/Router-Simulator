// Translate one complete P2P decision into scoped prefix/next-hop candidates.
// The instance control owner retains decision and binding generations; this
// allocation-free value adapter never reads a remote router or changes a RIB.

// Source: ietf.isis.prefix_next_hop_candidates

#pragma once

#include "router/isis_next_hop.hpp"
#include "router/isis_p2p_decision.hpp"

namespace router::isis {
struct PrefixRouteCandidate {
  ip::IpPrefix destination;
  PrefixDistance distance;
  AdjacencyNextHop next_hop;
  packet::isis::LspId origin{};
  bool down{}, external{};
  bool operator==(const PrefixRouteCandidate &) const = default;
};
enum class PrefixRoutesStatus : std::uint8_t { applied, invalid, capacity };
struct PrefixRoutesResult { PrefixRoutesStatus status{}; std::size_t count{}; };
// Preconditions: the owning shard fenced the completed decision against its
// current LSDB/adjacency revision. Binding index is the exact first-hop token
// catalog used by that calculation, with current accepted-Hello bindings.
// An absent binding is an unresolved adjacency and yields no usable route.
// Origins without first hops (including the local root) yield no candidate.
// Copies class, cost, provenance and scoped next hops; preserves parallel ECMP
// adjacencies. Prefix policy and best-class selection precede RIB publication
// in their separate owner. Attributes remain in the decision, not borrowed here.
// Same-owner immutable inputs, exclusive nonaliasing output. Two-pass preflight
// preserves output on invalid tokens, family/level mismatch or capacity refusal.
// Applied count zero is a complete withdrawal, not a retained old selection.
// The callback must not throw and may write only unpublished caller-owned
// storage. A late
// refusal can leave callback side effects there; no partial generation may
// escape. false means output capacity refusal. Inputs remain immutable.
template <typename Visit>
[[nodiscard]] inline PrefixRoutesResult visit_prefix_routes(
    const P2pRouteDecision &decision,
    std::span<const std::optional<AdjacencyNextHop>> bindings, Visit visit) noexcept {
  std::size_t count{};
  const auto prefixes = decision.prefixes();
  for (std::size_t index{}; index < prefixes.size(); ++index) {
    const auto distance = decision.distance_to_prefix(index);
    if (!distance) continue;
    const auto &prefix = prefixes[index];
    packet::isis::LanId origin{};
    std::copy_n(prefix.origin.begin(), origin.size(), origin.begin());
    for (std::size_t hop{}; hop < decision.first_hop_count(origin); ++hop) {
      const auto token = decision.first_hop(origin, hop);
      if (!token || *token >= bindings.size()) return {PrefixRoutesStatus::invalid, 0U};
      const auto &binding = bindings[*token];
      if (!binding) continue;
      if (binding->level != prefix.level || binding->address.family != prefix.prefix.network.family)
        return {PrefixRoutesStatus::invalid, 0U};
      if (!visit(count, PrefixRouteCandidate{prefix.prefix, *distance, *binding,
              prefix.origin, prefix.down, prefix.external})) return {PrefixRoutesStatus::capacity, 0U};
      ++count;
    }
  }
  return {PrefixRoutesStatus::applied, count};
}
[[nodiscard]] inline PrefixRoutesResult collect_prefix_routes(
    const P2pRouteDecision &decision,
    std::span<const std::optional<AdjacencyNextHop>> bindings,
    std::span<PrefixRouteCandidate> output) noexcept {
  const auto prepared = visit_prefix_routes(decision, bindings,
      [&](std::size_t index, const auto &) { return index < output.size(); });
  if (prepared.status != PrefixRoutesStatus::applied) return prepared;
  return visit_prefix_routes(decision, bindings, [&](std::size_t index, const auto &candidate) {
    output[index] = candidate;
    return true;
  });
}
} // namespace router::isis
