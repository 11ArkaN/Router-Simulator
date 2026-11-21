// ISO 10589 7.3.7-7.3.10 and RFC 5305 distinguish root circuit costs from
// zero-cost pseudonode edges. P2P peers use SystemID+zero.
// Both metric encodings use shared codecs. A capacity preflight makes the pair
// atomic in the caller's writer without allocating or retaining packet bytes.

// Source: iso.10589.2002.p2p_neighbor_origination

#include "router/isis_neighbor_origination.hpp"

#include <algorithm>
#include <limits>

namespace router::isis {
namespace {
bool append_neighbor(packet::isis::TlvWriter &writer, packet::isis::LanId neighbor,
    std::uint32_t wide, std::optional<std::uint8_t> narrow) noexcept {
  if (narrow && !packet::isis::encode_narrow_neighbor(writer,
      {{*narrow, false, std::nullopt, std::nullopt, std::nullopt}, neighbor, false})) return false;
  return packet::isis::encode_extended_neighbor(writer, {neighbor, wide, {}});
}
}
std::optional<std::size_t> p2p_origin_option_octets(const P2pOriginMetric &metric) noexcept {
  if (!metric.wide || metric.wide > packet::isis::maximum_link_metric ||
      (metric.narrow && (!*metric.narrow || *metric.narrow > 63U))) return std::nullopt;
  return 13U + (metric.narrow ? 14U : 0U);
}
bool append_p2p_origin_neighbor(packet::isis::TlvWriter &writer,
    packet::isis::SystemId peer, const P2pOriginMetric &metric) noexcept {
  const auto size = p2p_origin_option_octets(metric);
  if (!size || writer.available() < *size) return false;
  packet::isis::LanId neighbor{};
  std::copy(peer.begin(), peer.end(), neighbor.begin());
  return append_neighbor(writer, neighbor, metric.wide, metric.narrow);
}
bool append_lan_origin_neighbor(packet::isis::TlvWriter &writer,
    packet::isis::LanId pseudonode, const P2pOriginMetric &metric) noexcept {
  const auto size = p2p_origin_option_octets(metric);
  return pseudonode.back() && size && writer.available() >= *size &&
      append_neighbor(writer, pseudonode, metric.wide, metric.narrow);
}
std::optional<std::size_t> lan_pseudonode_option_octets(std::size_t peer_count, bool narrow) noexcept {
  const std::size_t edge_octets = narrow ? 27U : 13U;
  if (peer_count >= std::numeric_limits<std::size_t>::max() / edge_octets) return std::nullopt;
  return (peer_count + 1U) * edge_octets;
}
bool append_pseudonode_origin_neighbor(packet::isis::TlvWriter &writer,
    packet::isis::SystemId peer, bool narrow) noexcept {
  const auto size = lan_pseudonode_option_octets(0U, narrow);
  if (!size || writer.available() < *size) return false;
  packet::isis::LanId id{};
  std::copy(peer.begin(), peer.end(), id.begin());
  return append_neighbor(writer, id, 0U, narrow ? std::optional<std::uint8_t>{std::uint8_t{0U}} : std::nullopt);
}
bool append_lan_pseudonode_neighbors(packet::isis::TlvWriter &writer,
    packet::isis::SystemId local, std::span<const packet::isis::SystemId> peers,
    bool narrow) noexcept {
  const auto size = lan_pseudonode_option_octets(peers.size(), narrow);
  if (!size || writer.available() < *size || !std::is_sorted(peers.begin(), peers.end()) ||
      std::adjacent_find(peers.begin(), peers.end()) != peers.end() ||
      std::binary_search(peers.begin(), peers.end(), local)) return false;
  if (!append_pseudonode_origin_neighbor(writer, local, narrow)) return false;
  for (const auto &peer : peers) if (!append_pseudonode_origin_neighbor(writer, peer, narrow)) return false;
  return true;
}
std::optional<LspLinkCounts> lsp_link_counts(std::span<const std::uint8_t> options) noexcept {
  LspLinkCounts result;
  packet::isis::TlvCursor cursor(options);
  while (const auto option = cursor.next()) {
    if (option->code == 2U) {
      packet::isis::NarrowNeighborCursor entries(*option);
      while (entries.next()) ++result.narrow;
      if (!entries.valid()) return std::nullopt;
    } else if (option->code == 22U) {
      packet::isis::ExtendedNeighborCursor entries(*option);
      while (entries.next()) ++result.wide;
      if (!entries.valid()) return std::nullopt;
    }
  }
  return cursor.valid() ? std::optional{result} : std::nullopt;
}
} // namespace router::isis
