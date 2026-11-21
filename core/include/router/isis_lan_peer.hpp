// A LAN level's control owner lends immutable neighbor projections during a
// synchronous query or callback. Spans expire at that owner's next mutation;
// this value owns no adjacency, packet buffer, key or timer.

#pragma once

#include "router/isis_lan_adjacency.hpp"
#include "router/isis_neighbor_attributes.hpp"

namespace router::isis {
struct LanPeerView {
  LanSnapshot adjacency;
  std::span<const NeighborArea> areas;
  // Selected non-secret Hello TLVs, retained independently of receive bytes.
  std::span<const std::uint8_t> attributes;
  packet::isis::PduType type{};
};
} // namespace router::isis
