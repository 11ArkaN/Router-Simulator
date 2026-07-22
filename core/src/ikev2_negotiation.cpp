// RFC 7296 section 3.3 proposal matching. A proposal is accepted as a complete
// conjunction only. Unsupported or contradictory transforms reject that
// proposal instead of silently weakening it or combining it with another one.

#include "router/ikev2_negotiation.hpp"

#include <algorithm>
#include <optional>

namespace router::ikev2 {
namespace {

constexpr std::uint16_t key_length_attribute{14U};

std::optional<std::uint16_t> key_bits(
    std::size_t transform_index, const TransformView &transform,
    std::span<const TransformAttributeView> attributes) noexcept {
  if (transform.first_attribute > attributes.size() ||
      transform.attribute_count >
          attributes.size() - transform.first_attribute)
    return std::nullopt;
  std::optional<std::uint16_t> result;
  for (const auto &attribute : attributes.subspan(transform.first_attribute,
                                                   transform.attribute_count)) {
    if (attribute.transform_index != transform_index)
      return std::nullopt;
    if (attribute.type != key_length_attribute)
      continue;
    if (!attribute.basic || result.has_value())
      return std::nullopt;
    result = attribute.basic_value;
  }
  return result;
}

bool matches_definition(
    std::size_t transform_index, const TransformView &offered,
    const TransformDefinition &definition,
    std::span<const TransformAttributeView> attributes) noexcept {
  if (offered.type != static_cast<std::uint8_t>(definition.type) ||
      offered.id != definition.id)
    return false;
  const auto offered_key_bits = key_bits(transform_index, offered, attributes);
  if (!offered_key_bits.has_value() && offered.attribute_count != 0U)
    return false;
  if (definition.key_length_attribute_required)
    return offered_key_bits.has_value() &&
           *offered_key_bits == definition.key_bits;
  return !offered_key_bits.has_value() || definition.key_bits == 0U ||
         *offered_key_bits == definition.key_bits;
}

std::optional<std::size_t> choose_type(
    TransformType type, const ProposalView &proposal,
    std::span<const TransformView> transforms,
    std::span<const TransformAttributeView> attributes,
    std::span<const TransformDefinition> preferences) noexcept {
  for (const auto &preferred : preferences) {
    if (preferred.type != type)
      continue;
    for (std::size_t relative = 0U; relative < proposal.transform_count;
         ++relative) {
      const auto index = proposal.first_transform + relative;
      if (matches_definition(index, transforms[index], preferred, attributes))
        return index;
    }
  }
  return std::nullopt;
}

bool has_type(TransformType type, const ProposalView &proposal,
              std::span<const TransformView> transforms) noexcept {
  return std::any_of(
      transforms.begin() + static_cast<std::ptrdiff_t>(proposal.first_transform),
      transforms.begin() + static_cast<std::ptrdiff_t>(
                               proposal.first_transform +
                               proposal.transform_count),
      [type](const TransformView &transform) {
        return transform.type == static_cast<std::uint8_t>(type);
      });
}

const TransformDefinition *definition_for(
    const TransformView &transform,
    std::span<const TransformDefinition> definitions) noexcept {
  const auto found = std::find_if(
      definitions.begin(), definitions.end(),
      [&transform](const TransformDefinition &definition) {
        return static_cast<std::uint8_t>(definition.type) == transform.type &&
               definition.id == transform.id;
      });
  return found == definitions.end() ? nullptr : &*found;
}

} // namespace

NegotiationStatus select_proposal(
    std::span<const ProposalView> proposals,
    std::span<const TransformView> transforms,
    std::span<const TransformAttributeView> attributes,
    const NegotiationPolicy &policy, NegotiatedProposal &selected) noexcept {
  if (policy.preferences.empty())
    return NegotiationStatus::invalid_input;
  for (std::size_t proposal_index = 0U; proposal_index < proposals.size();
       ++proposal_index) {
    const auto &proposal = proposals[proposal_index];
    if (proposal.protocol_id != static_cast<std::uint8_t>(policy.protocol) ||
        proposal.first_transform > transforms.size() ||
        proposal.transform_count == 0U ||
        proposal.transform_count > transforms.size() - proposal.first_transform)
      continue;

    NegotiatedProposal candidate{.proposal_index = proposal_index};
    const auto append = [&candidate](std::optional<std::size_t> index) {
      if (!index.has_value() ||
          candidate.transform_count == candidate.transform_indices.size())
        return false;
      candidate.transform_indices[candidate.transform_count++] = *index;
      return true;
    };
    const auto encryption = choose_type(TransformType::encryption, proposal,
                                        transforms, attributes,
                                        policy.preferences);
    const auto integrity = choose_type(TransformType::integrity, proposal,
                                       transforms, attributes,
                                       policy.preferences);
    const auto prf = choose_type(TransformType::prf, proposal, transforms,
                                 attributes, policy.preferences);
    const auto dh = choose_type(TransformType::diffie_hellman, proposal,
                                transforms, attributes, policy.preferences);
    const auto esn = choose_type(TransformType::extended_sequence_numbers,
                                 proposal, transforms, attributes,
                                 policy.preferences);

    const auto *encryption_definition =
        encryption.has_value()
            ? definition_for(transforms[*encryption], policy.preferences)
            : nullptr;
    const bool aead = encryption_definition &&
                      encryption_definition->authenticated_encryption;
    const bool is_ike = policy.protocol == ProposalProtocol::ike;
    const bool is_ah = policy.protocol == ProposalProtocol::ah;

    // IKE and ESP require encryption. AH prohibits it. PRF is required only by
    // the IKE SA. AEAD proposals must omit a separate integrity transform.
    if ((!is_ah && !encryption.has_value()) ||
        (is_ah && has_type(TransformType::encryption, proposal, transforms)) ||
        (is_ike != prf.has_value()) ||
        (is_ike && !dh.has_value()) ||
        (aead && has_type(TransformType::integrity, proposal, transforms)) ||
        (!aead && !integrity.has_value()) ||
        (policy.require_esn && !esn.has_value()))
      continue;

    if (encryption.has_value() && !append(encryption))
      return NegotiationStatus::output_too_small;
    if (prf.has_value() && !append(prf))
      return NegotiationStatus::output_too_small;
    if (integrity.has_value() && !append(integrity))
      return NegotiationStatus::output_too_small;
    if (dh.has_value() && !append(dh))
      return NegotiationStatus::output_too_small;
    if (esn.has_value() && !append(esn))
      return NegotiationStatus::output_too_small;
    selected = candidate;
    return NegotiationStatus::selected;
  }
  return NegotiationStatus::no_acceptable_proposal;
}

} // namespace router::ikev2
