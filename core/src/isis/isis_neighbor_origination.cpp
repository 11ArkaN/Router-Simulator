// ISO 10589 7.3.7/7.3.9 and RFC 5305 advertise P2P peers as SystemID+zero.
// Both metric encodings use shared codecs. A capacity preflight makes the pair
// atomic in the caller's writer without allocating or retaining packet bytes.

// Source: iso.10589.2002.p2p_neighbor_origination

#include "router/isis_neighbor_origination.hpp"

#include <algorithm>

namespace router::isis {
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
  if (metric.narrow && !packet::isis::encode_narrow_neighbor(writer,
      {{*metric.narrow, false, std::nullopt, std::nullopt, std::nullopt}, neighbor, false})) return false;
  return packet::isis::encode_extended_neighbor(writer, {neighbor, metric.wide, {}});
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
