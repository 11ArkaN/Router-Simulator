// One instance control shard owns graph translation, SPF scratch and the
// identity projection of its last complete P2P decision. Dependencies point
// to local LSDB values and shared distance calculation, never another router.

// Source: iso.10589.2002.lsdb_link_graph

#pragma once

#include "router/isis_p2p_spf_input.hpp"

namespace router::isis {
enum class DecisionStatus : std::uint8_t { applied, invalid, capacity, calculation_failed };
class P2pRouteDecision final {
public:
  // Cold allocation uses explicit emulator budgets and distance policy.
  // The configuration owner resolves mixed-mode distance semantics beforehand.
  P2pRouteDecision(std::size_t nodes, std::size_t links, std::size_t pending, MetricStyle distance)
      : graph_(nodes, links), input_(nodes, links), calculator_(nodes, pending, checked(distance)),
        maximum_metric_(distance == MetricStyle::wide ? packet::isis::maximum_link_metric - 1U : 63U) {
    identities_.reserve(nodes);
  }
  // Same owner, immutable database during the call, accepted same-level/MT
  // local seeds only. No allocation. Failure preserves the last complete
  // identity/cost/first-hop result. A valid missing root publishes an empty
  // result so the route owner can withdraw this protocol's candidates.
  [[nodiscard]] DecisionStatus calculate(const LinkStateDatabase &database,
      const LinkGraphSelection &selection, std::span<const P2pSpfSeed> local,
      std::uint16_t catalog_size, RuntimeClock::time_point now) noexcept {
    const auto translated = graph_.rebuild(database, selection, now);
    if (translated != LinkGraphStatus::applied)
      return translated == LinkGraphStatus::capacity ? DecisionStatus::capacity : DecisionStatus::invalid;
    if (!graph_.root()) { identities_.clear(); return DecisionStatus::applied; }
    if (!input_.rebuild(graph_, local, catalog_size, maximum_metric_)) return DecisionStatus::invalid;
    if (!calculator_.calculate(*graph_.root(), input_.vertices(), input_.edges(), catalog_size))
      return DecisionStatus::calculation_failed;
    identities_.clear();
    for (const auto &node : graph_.nodes()) identities_.push_back(node.id);
    return DecisionStatus::applied;
  }
  // Value results from the last successful decision. An unknown/unreachable
  // origin has no distance or next hop. No borrowed LSDB data escapes.
  [[nodiscard]] std::optional<std::uint32_t> cost(const packet::isis::LanId &id) const noexcept {
    const auto index = find(id);
    return index ? calculator_.cost(*index) : std::nullopt;
  }
  [[nodiscard]] std::size_t first_hop_count(const packet::isis::LanId &id) const noexcept {
    const auto index = find(id);
    return index ? calculator_.first_hop_count(*index) : 0U;
  }
  [[nodiscard]] std::optional<std::uint16_t> first_hop(const packet::isis::LanId &id,
      std::size_t ordinal) const noexcept {
    const auto index = find(id);
    return index ? calculator_.first_hop(*index, ordinal) : std::nullopt;
  }
private:
  static MetricStyle checked(MetricStyle style) {
    if (style > MetricStyle::wide) throw std::invalid_argument("Invalid IS-IS distance policy");
    return style;
  }
  [[nodiscard]] std::optional<std::size_t> find(const packet::isis::LanId &id) const noexcept {
    const auto found = std::lower_bound(identities_.begin(), identities_.end(), id);
    return found != identities_.end() && *found == id ?
        std::optional{static_cast<std::size_t>(found - identities_.begin())} : std::nullopt;
  }
  LinkGraph graph_;
  P2pSpfInput input_;
  SpfCalculator calculator_;
  std::uint32_t maximum_metric_{};
  std::vector<packet::isis::LanId> identities_;
};
} // namespace router::isis
