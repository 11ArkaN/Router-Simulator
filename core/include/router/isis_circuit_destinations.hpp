// Immutable circuit multicast values are copied into each transport owner.
// Configuration resolves addresses; encoded PDU type selects the destination.
// This module owns no membership, packet, protocol state or vendor defaults.

#pragma once

#include "router/isis_packet.hpp"
#include "router/packet.hpp"

namespace router::isis {
struct CircuitDestinations {
  packet::Mac hello{};
  std::array<packet::Mac, 2U> levels{};
  // No allocation or retained input. Unknown PDU types return nullopt.
  [[nodiscard]] std::optional<packet::Mac> select(packet::isis::PduType type) const noexcept {
    using packet::isis::PduType;
    switch (type) {
    case PduType::point_to_point_hello: return hello;
    case PduType::lan_hello_l1: case PduType::lsp_l1: case PduType::csnp_l1: case PduType::psnp_l1: return levels[0U];
    case PduType::lan_hello_l2: case PduType::lsp_l2: case PduType::csnp_l2: case PduType::psnp_l2: return levels[1U];
    default: return std::nullopt;
    }
  }
  [[nodiscard]] bool valid() const noexcept {
    return (hello[0U] & 1U) && (levels[0U][0U] & 1U) && (levels[1U][0U] & 1U);
  }
  // Same physical interface and wire IID are preconditions. A shared address
  // for the same PDU class is ambiguous; cross-level address reuse is legal.
  [[nodiscard]] bool conflicts(const CircuitDestinations &other) const noexcept {
    return hello == other.hello || levels[0U] == other.levels[0U] || levels[1U] == other.levels[1U];
  }
  bool operator==(const CircuitDestinations &) const = default;
};
} // namespace router::isis
