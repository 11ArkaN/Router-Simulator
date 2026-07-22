// Profile-driven IKEv2 proposal selection. The codec's parsed views are
// immutable, while this pure selector chooses one offered transform per type
// according to caller-supplied local preference order. No algorithm number or
// platform limit is embedded in the negotiation mechanism.

#pragma once

#include "router/ikev2_payload.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ikev2 {

struct TransformDefinition {
  TransformType type{TransformType::encryption};
  std::uint16_t id{};
  std::uint16_t key_bits{};
  bool key_length_attribute_required{};
  bool authenticated_encryption{};
};

struct NegotiationPolicy {
  ProposalProtocol protocol{ProposalProtocol::ike};
  // Definitions are ordered from most to least preferred. Each definition is
  // an immutable profile record and may be shared across every IKE SA owner.
  std::span<const TransformDefinition> preferences;
  bool require_esn{};
};

enum class NegotiationStatus : std::uint8_t {
  selected,
  no_acceptable_proposal,
  invalid_input,
  output_too_small
};

struct NegotiatedProposal {
  std::size_t proposal_index{};
  std::array<std::size_t, 5U> transform_indices{};
  std::size_t transform_count{};
};

[[nodiscard]] NegotiationStatus select_proposal(
    std::span<const ProposalView> proposals,
    std::span<const TransformView> transforms,
    std::span<const TransformAttributeView> attributes,
    const NegotiationPolicy &policy, NegotiatedProposal &selected) noexcept;

} // namespace router::ikev2
