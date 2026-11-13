// Metric-selected link graph translated only from one immutable local LSDB visit.
// The instance control owner owns both generations and scratch; borrowed packet
// views never escape rebuild. This layer selects no routes or forwarding peers.

#pragma once

#include "router/isis_lsdb.hpp"
#include "router/isis_neighbor_key.hpp"

namespace router::isis {
enum class GraphMetricStyle : std::uint8_t { unresolved, narrow, wide, both_minimum };
struct LinkGraphSelection {
  packet::isis::LanId local{};
  std::uint16_t topology{};
  // nullopt selects family-independent reachability, needed for area decisions.
  std::optional<std::uint8_t> protocol;
  // Explicit experimental selection, not an SR OS default or distance policy.
  GraphMetricStyle metrics{GraphMetricStyle::unresolved};
};
struct LinkNode {
  packet::isis::LanId id{};
  bool overloaded{}, attached{};
};
struct LinkArc {
  std::uint32_t source{}, target{}, metric{};
  bool operator==(const LinkArc &) const = default;
};
enum class LinkGraphStatus : std::uint8_t { applied, capacity, invalid_selection, malformed_database };
class LinkGraph final {
public:
  // Explicit emulator budgets count eligible nodes and encoded neighbor entries
  // with eligible targets before duplicate reduction. Allocates both generations and scratch once;
  // invalid zero or unrepresentable budgets throw invalid_argument.
  LinkGraph(std::size_t maximum_nodes, std::size_t maximum_links);
  LinkGraph(const LinkGraph &) = delete;
  LinkGraph &operator=(const LinkGraph &) = delete;
  // Same instance shard, with no concurrent LSDB mutation. No allocation.
  // ISO 7.2.5 gates fragments on a live root, 7.2.8 gates reverse links and
  // overload transit. RFC 5120 keeps pseudonodes shared across topologies.
  // Malformed semantic TLVs are ignored without changing the retained LSP.
  // Failure preserves the previous generation; success replaces it atomically,
  // including a missing local root. The caller must then withdraw its routes.
  [[nodiscard]] LinkGraphStatus rebuild(const LinkStateDatabase &database,
      const LinkGraphSelection &selection, RuntimeClock::time_point now) noexcept;
  // Published views remain valid until the next successful rebuild or destruction.
  [[nodiscard]] const LinkGraphSelection &selection() const noexcept { return published_.selection; }
  [[nodiscard]] std::span<const LinkNode> nodes() const noexcept { return published_.nodes; }
  [[nodiscard]] std::span<const LinkArc> links() const noexcept { return published_.links; }
  [[nodiscard]] std::optional<std::uint32_t> root() const noexcept { return published_.root; }
  [[nodiscard]] std::size_t ignored_options() const noexcept { return published_.ignored; }
private:
  struct Generation {
    LinkGraphSelection selection;
    std::vector<LinkNode> nodes;
    std::vector<LinkArc> links;
    std::optional<std::uint32_t> root;
    std::size_t ignored{};
  };
  std::size_t maximum_nodes_{}, maximum_links_{};
  Generation published_, working_;
  struct Candidate {
    LinkArc arc;
    std::uint32_t key_offset{}, order{};
    std::uint16_t key_size{};
    std::uint8_t fragment{};
    bool narrow{};
  };
  std::vector<Candidate> candidates_;
  // One cold-reserved arena holds canonical identifiers for this LSDB visit.
  // Offsets remain local to scratch; failed options roll back both extents.
  std::vector<std::uint8_t> keys_;
};
} // namespace router::isis
