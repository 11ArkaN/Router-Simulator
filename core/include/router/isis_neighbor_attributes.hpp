// Retained IS-IS neighbor area values. The enclosing circuit control owner
// owns their storage; these fixed values have no timer or adjacency state.

#pragma once

#include "router/isis_basic_tlvs.hpp"

namespace router::isis {

struct NeighborArea {
  std::array<std::uint8_t, packet::isis::maximum_area_octets> bytes{};
  std::uint8_t length{};
  // Retained projections guarantee 1 <= length <= bytes.size(). Independent
  // construction must preserve that extent before requesting a borrowed view.
  [[nodiscard]] std::span<const std::uint8_t> view() const noexcept {
    return std::span(bytes).first(length);
  }
};

} // namespace router::isis
