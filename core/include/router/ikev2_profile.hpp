// Adapter from the generated release catalog to the IKEv2 negotiation value
// contract. It copies only implemented rows and preserves catalog preference
// order. Negotiation code therefore contains no release or platform constants.

#pragma once

#include "router/ikev2_negotiation.hpp"

#include <cstddef>
#include <span>

namespace router::ikev2 {

struct TransformProfileResult {
  std::size_t written{};
  std::size_t required{};
};

[[nodiscard]] TransformProfileResult load_implemented_transform_profile(
    std::span<TransformDefinition> output) noexcept;

} // namespace router::ikev2
