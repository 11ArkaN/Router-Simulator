// Negotiation tests prove local preference ordering, AEAD integrity exclusion
// and whole-proposal selection without mixing transforms between proposals.

#include "router/ikev2_negotiation.hpp"

#include <array>
#include <stdexcept>

void ikev2_negotiation_tests() {
  using namespace router::ikev2;
  const std::array proposals{
      ProposalView{.number = 1U,
                   .protocol_id = 1U,
                   .spi = {},
                   .first_transform = 0U,
                   .transform_count = 3U},
      ProposalView{.number = 2U,
                   .protocol_id = 1U,
                   .spi = {},
                   .first_transform = 3U,
                   .transform_count = 3U}};
  const std::array transforms{
      TransformView{.proposal_index = 0U, .type = 1U, .id = 12U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 0U, .type = 2U, .id = 5U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 0U, .type = 4U, .id = 14U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 1U, .type = 1U, .id = 20U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 1U, .type = 2U, .id = 5U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 1U, .type = 4U, .id = 19U,
                    .first_attribute = 0U, .attribute_count = 0U}};
  const std::array<TransformDefinition, 5U> preferences{
      TransformDefinition{.type = TransformType::encryption,
                          .id = 20U,
                          .key_bits = 128U,
                          .authenticated_encryption = true},
      TransformDefinition{.type = TransformType::encryption, .id = 12U},
      TransformDefinition{.type = TransformType::prf, .id = 5U},
      TransformDefinition{.type = TransformType::diffie_hellman, .id = 19U},
      TransformDefinition{.type = TransformType::diffie_hellman, .id = 14U}};
  NegotiatedProposal selected{};
  const NegotiationPolicy policy{.protocol = ProposalProtocol::ike,
                                 .preferences = preferences};
  if (select_proposal(proposals, transforms, {}, policy, selected) !=
          NegotiationStatus::selected ||
      selected.proposal_index != 1U || selected.transform_count != 3U)
    throw std::runtime_error("IKEv2 complete-proposal ordering failed");

  // A separate integrity transform contradicts an AEAD encryption transform,
  // so the second proposal is no longer acceptable despite supported IDs.
  const std::array contradictory{
      TransformView{.proposal_index = 0U, .type = 1U, .id = 20U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 0U, .type = 2U, .id = 5U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 0U, .type = 4U, .id = 19U,
                    .first_attribute = 0U, .attribute_count = 0U},
      TransformView{.proposal_index = 0U, .type = 3U, .id = 12U,
                    .first_attribute = 0U, .attribute_count = 0U}};
  const std::array<TransformDefinition, 6U> with_integrity{
      preferences[0U], preferences[1U], preferences[2U], preferences[3U],
      preferences[4U],
      TransformDefinition{.type = TransformType::integrity, .id = 12U}};
  const NegotiationPolicy strict{.protocol = ProposalProtocol::ike,
                                 .preferences = with_integrity};
  const std::array contradictory_proposal{
      ProposalView{.number = 2U,
                   .protocol_id = 1U,
                   .spi = {},
                   .first_transform = 0U,
                   .transform_count = 4U}};
  if (select_proposal(contradictory_proposal, contradictory, {}, strict,
                      selected) != NegotiationStatus::no_acceptable_proposal)
    throw std::runtime_error("IKEv2 AEAD plus integrity was accepted");

  const std::array esp_proposal{
      ProposalView{.number = 1U,
                   .protocol_id = 3U,
                   .spi = {},
                   .first_transform = 0U,
                   .transform_count = 1U}};
  const std::array esp_transform{
      TransformView{.proposal_index = 0U, .type = 1U, .id = 20U,
                    .first_attribute = 0U, .attribute_count = 0U}};
  const NegotiationPolicy esp_policy{.protocol = ProposalProtocol::esp,
                                     .preferences = preferences};
  if (select_proposal(esp_proposal, esp_transform, {}, esp_policy, selected) !=
      NegotiationStatus::selected)
    throw std::runtime_error("IKEv2 ESP AEAD proposal was rejected");
}
