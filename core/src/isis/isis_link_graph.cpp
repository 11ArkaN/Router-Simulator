// ISO 10589 7.2.5 and 7.2.8, RFC 5305 and RFC 5120 govern graph eligibility.
// The calling instance shard owns all buffers. A failed bounded translation
// cannot expose a partially rebuilt graph or mutate its source database.

// Source: iso.10589.2002.lsdb_link_graph

#include "router/isis_link_graph.hpp"
#include "router/isis_basic_tlvs.hpp"
#include "router/isis_multi_topology.hpp"
#include "router/isis_narrow_reachability.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <tuple>

namespace router::isis {
namespace {
packet::isis::LanId node_id(const packet::isis::LspId &id) noexcept {
  packet::isis::LanId result{};
  std::copy_n(id.begin(), result.size(), result.begin());
  return result;
}
struct RootMetadata {
  bool supported{}, overloaded{}, attached{}, valid{true};
  std::size_t ignored{};
};
RootMetadata metadata(const StoredLspView &record, const LinkGraphSelection &selection) noexcept {
  RootMetadata result;
  const bool pseudonode = record.header.id[6U] != 0U;
  result.overloaded = !selection.topology && (record.header.flags & 4U);
  result.attached = !selection.topology && !pseudonode && (record.header.flags & 8U);
  if (pseudonode) { result.supported = true; return result; }
  bool advertised{}, found{}, protocol = !selection.protocol;
  packet::isis::TlvCursor options(record.pdu.tlvs);
  while (const auto option = options.next()) {
    if (option->code == 129U && selection.protocol)
      protocol = protocol || packet::isis::supports_protocol(*option, *selection.protocol);
    if (option->code != 229U) continue;
    packet::isis::TopologyCursor entries(*option, true);
    bool member{}, overloaded{}, attached{};
    while (const auto entry = entries.next()) if (entry->id == selection.topology) {
      member = true;
      overloaded = overloaded || entry->overloaded;
      attached = attached || entry->attached;
    }
    if (!entries.valid()) { ++result.ignored; continue; }
    advertised = true;
    found = found || member;
    if (selection.topology) {
      result.overloaded = result.overloaded || overloaded;
      result.attached = result.attached || attached;
    }
  }
  result.valid = options.valid();
  result.supported = protocol && (found || (!advertised && !selection.topology));
  return result;
}
auto pair_key(const LinkArc &arc) noexcept { return std::pair{arc.source, arc.target}; }
}
LinkGraph::LinkGraph(std::size_t maximum_nodes, std::size_t maximum_links)
    : maximum_nodes_(maximum_nodes), maximum_links_(maximum_links) {
  if (!maximum_nodes || !maximum_links || maximum_nodes > std::numeric_limits<std::uint32_t>::max() ||
      maximum_links > std::numeric_limits<std::uint32_t>::max() ||
      maximum_nodes > published_.nodes.max_size() || maximum_links > candidates_.max_size())
    throw std::invalid_argument("Invalid IS-IS link graph budget");
  for (auto *generation : {&published_, &working_}) {
    generation->nodes.reserve(maximum_nodes);
    generation->links.reserve(maximum_links);
  }
  candidates_.reserve(maximum_links);
}
LinkGraphStatus LinkGraph::rebuild(const LinkStateDatabase &database,
    const LinkGraphSelection &selection, RuntimeClock::time_point now) noexcept {
  if (selection.topology > packet::isis::maximum_topology_id || selection.local[6U] ||
      selection.metrics == GraphMetricStyle::unresolved || selection.metrics > GraphMetricStyle::both_minimum ||
      (selection.topology && selection.metrics != GraphMetricStyle::wide) ||
      (selection.protocol && *selection.protocol != packet::isis::ipv4_nlpid &&
       *selection.protocol != packet::isis::ipv6_nlpid)) return LinkGraphStatus::invalid_selection;
  working_.nodes.clear();
  working_.links.clear();
  working_.root.reset();
  working_.ignored = 0U;
  candidates_.clear();
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto record = database.at(index, now);
    if (!record || record->header.id[7U] || !record->header.remaining_seconds ||
        !record->header.sequence || !record->header.checksum) continue;
    const auto type = record->header.flags & 3U;
    if ((type != 1U && type != 3U) || (record->pdu.type == packet::isis::PduType::lsp_l2 && type != 3U)) continue;
    const auto root = metadata(*record, selection);
    if (!root.valid) return LinkGraphStatus::malformed_database;
    working_.ignored += root.ignored;
    if (!root.supported) continue;
    if (working_.nodes.size() == maximum_nodes_) return LinkGraphStatus::capacity;
    working_.nodes.push_back({node_id(record->header.id), root.overloaded, root.attached});
  }
  std::sort(working_.nodes.begin(), working_.nodes.end(), [](const auto &a, const auto &b) { return a.id < b.id; });
  const auto find = [&](const packet::isis::LanId &id) -> std::optional<std::uint32_t> {
    const auto found = std::lower_bound(working_.nodes.begin(), working_.nodes.end(), id,
        [](const auto &node, const auto &key) { return node.id < key; });
    if (found == working_.nodes.end() || found->id != id) return std::nullopt;
    return static_cast<std::uint32_t>(found - working_.nodes.begin());
  };
  working_.root = find(selection.local);
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto record = database.at(index, now);
    if (!record || !record->header.remaining_seconds || !record->header.sequence || !record->header.checksum) continue;
    const auto source = find(node_id(record->header.id));
    if (!source) continue;
    const bool pseudonode = working_.nodes[*source].id[6U] != 0U;
    packet::isis::TlvCursor options(record->pdu.tlvs);
    while (const auto option = options.next()) {
      auto links = *option;
      if (selection.topology && !pseudonode) {
        if (links.code != 222U) continue;
        const auto wrapped = packet::isis::mt_reachability(links);
        if (!wrapped) { ++working_.ignored; continue; }
        if (wrapped->topology != selection.topology) continue;
        links = wrapped->entries;
      }
      const bool narrow = !selection.topology && links.code == 2U && selection.metrics != GraphMetricStyle::wide;
      if (!narrow && (links.code != 22U || selection.metrics == GraphMetricStyle::narrow)) continue;
      const auto before = candidates_.size();
      bool valid{true}, capacity{};
      const auto append = [&](const auto &entry, std::uint32_t metric) {
        if (pseudonode && metric) { valid = false; return; }
        const auto target = find(entry.id);
        if (!target) return;
        if (candidates_.size() == maximum_links_) { capacity = true; return; }
        candidates_.push_back({*source, *target, metric});
      };
      if (narrow) {
        packet::isis::NarrowNeighborCursor entries(links);
        while (const auto entry = entries.next()) {
          if (entry->metrics.external_metric) valid = false;
          else append(*entry, entry->metrics.metric);
        }
        valid = entries.valid() && valid;
      } else {
        packet::isis::ExtendedNeighborCursor entries(links);
        while (const auto entry = entries.next()) append(*entry, entry->metric);
        valid = entries.valid() && valid;
      }
      if (!valid) {
        candidates_.resize(before);
        ++working_.ignored;
      } else if (capacity) return LinkGraphStatus::capacity;
    }
    if (!options.valid()) return LinkGraphStatus::malformed_database;
  }
  std::sort(candidates_.begin(), candidates_.end(), [](const auto &a, const auto &b) {
    return std::tie(a.source, a.target, a.metric) < std::tie(b.source, b.target, b.metric);
  });
  const auto unique = std::unique(candidates_.begin(), candidates_.end(), [](const auto &a, const auto &b) {
    return pair_key(a) == pair_key(b);
  });
  candidates_.erase(unique, candidates_.end());
  for (const auto &arc : candidates_) {
    // Reverse presence is checked before applying overload or unreachable-cost
    // filtering. Asymmetric defined metrics are legal; the forward cost wins.
    const auto reverse_key = std::pair{arc.target, arc.source};
    const auto reverse = std::lower_bound(candidates_.begin(), candidates_.end(), reverse_key,
        [](const auto &entry, const auto &key) { return pair_key(entry) < key; });
    if (reverse == candidates_.end() || pair_key(*reverse) != reverse_key ||
        arc.metric == packet::isis::maximum_link_metric ||
        (working_.nodes[arc.source].overloaded && working_.root != arc.source)) continue;
    working_.links.push_back(arc);
  }
  std::swap(published_, working_);
  return LinkGraphStatus::applied;
}
} // namespace router::isis
