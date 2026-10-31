// Effective P2P advertisement metrics are configuration-owned values. The
// instance control owner supplies a peer learned from its own accepted Hello.
// Encoding owns no adjacency, LSDB or transport state and uses caller buffers.

#pragma once

#include "router/isis_narrow_reachability.hpp"
#include "router/isis_reachability.hpp"

namespace router::isis {
struct P2pOriginMetric {
  std::uint32_t wide{};
  std::optional<std::uint8_t> narrow;
};
struct P2pOriginInterface {
  std::uint64_t interface_id{};
  std::array<std::optional<P2pOriginMetric>, 2U> levels;
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
// Same-owner diagnostic projection of complete encoded neighbor options.
// Malformed framing or entries return nullopt; no borrowed view escapes.
[[nodiscard]] std::optional<LspLinkCounts> lsp_link_counts(std::span<const std::uint8_t> options) noexcept;
} // namespace router::isis
