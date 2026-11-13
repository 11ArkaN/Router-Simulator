// Effective link advertisement metrics are configuration-owned values. The
// instance control owner supplies peers learned from its own accepted Hellos.
// Encoding owns no adjacency, LSDB or transport state and uses caller buffers.

#pragma once

#include "router/isis_narrow_reachability.hpp"
#include "router/isis_reachability.hpp"

namespace router::isis {
struct P2pOriginMetric {
  std::uint32_t wide{};
  std::optional<std::uint8_t> narrow;
  bool operator==(const P2pOriginMetric &) const = default;
};
struct P2pOriginInterface {
  std::uint64_t interface_id{};
  std::array<std::optional<P2pOriginMetric>, 2U> levels;
  bool operator==(const P2pOriginInterface &) const = default;
};
struct LspLinkCounts {
  std::uint32_t narrow{}, wide{};
  bool operator==(const LspLinkCounts &) const = default;
};
// The selected SR OS metric type is 1..16777215. Optional narrow output must
// already be resolved to 1..63 by the configuration owner; no clipping, default
// or migration behavior is inferred here. nullopt means invalid metric values.
[[nodiscard]] std::optional<std::size_t> p2p_origin_option_octets(const P2pOriginMetric &metric) noexcept;
// Requires an accepted Up P2P peer selected for this level by the instance
// owner. Appends its non-pseudonode ID with wide and optional narrow metrics.
// Refusal preserves writer bytes/cursor. No allocation; inputs are value copies.
[[nodiscard]] bool append_p2p_origin_neighbor(packet::isis::TlvWriter &writer,
    packet::isis::SystemId peer, const P2pOriginMetric &metric) noexcept;
// ISO 10589 7.3.7/7.3.9: a LAN's root advertises its designated pseudonode
// with the configured circuit metric. The pseudonode octet must be nonzero.
// Same metric validation and atomic capacity refusal as the P2P form; no
// allocation, retained views or shard affinity. The owner resolves DIS first.
[[nodiscard]] bool append_lan_origin_neighbor(packet::isis::TlvWriter &writer,
    packet::isis::LanId pseudonode, const P2pOriginMetric &metric) noexcept;
// Required space for a pseudonode's own-system edge plus every Up IS peer.
// All edges use zero metrics under ISO 10589 7.3.8/7.3.10. The optional narrow
// form accompanies wide output. Overflow returns nullopt without allocation.
[[nodiscard]] std::optional<std::size_t> lan_pseudonode_option_octets(
    std::size_t peer_count, bool narrow) noexcept;
// Same-owner DIS projection: peers are sorted unique Up system IDs and must
// exclude local. The local system is included exactly once. Invalid ordering,
// self duplication or insufficient space returns false without touching any
// writer bytes. Inputs borrow until return and must not alias writer storage.
[[nodiscard]] bool append_lan_pseudonode_neighbors(packet::isis::TlvWriter &writer,
    packet::isis::SystemId local, std::span<const packet::isis::SystemId> peers,
    bool narrow) noexcept;
// One independently packable pseudonode edge, with zero wide and optional
// narrow metric. The DIS owner validates membership and duplicate suppression.
// Capacity refusal preserves bytes/cursor; inputs are copied, no allocation.
[[nodiscard]] bool append_pseudonode_origin_neighbor(packet::isis::TlvWriter &writer,
    packet::isis::SystemId peer, bool narrow) noexcept;
// Same-owner diagnostic projection of complete encoded neighbor options.
// Malformed framing or entries return nullopt; no borrowed view escapes.
[[nodiscard]] std::optional<LspLinkCounts> lsp_link_counts(std::span<const std::uint8_t> options) noexcept;
} // namespace router::isis
