// Bounded IKEv2 SA proposal, transform attribute and Traffic Selector payload
// views. Parsing owns no negotiation policy and performs no allocation. The IKE
// SA owner supplies arrays sized by its release profile and later selects only
// algorithms and address ranges allowed by that configured profile.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ikev2 {

enum class ProposalProtocol : std::uint8_t { ike = 1U, ah = 2U, esp = 3U };
enum class TransformType : std::uint8_t {
  encryption = 1U,
  prf = 2U,
  integrity = 3U,
  diffie_hellman = 4U,
  extended_sequence_numbers = 5U
};

struct ProposalView {
  std::uint8_t number{};
  std::uint8_t protocol_id{};
  std::span<const std::uint8_t> spi;
  std::size_t first_transform{};
  std::size_t transform_count{};
};

struct TransformView {
  std::size_t proposal_index{};
  std::uint8_t type{};
  std::uint16_t id{};
  std::size_t first_attribute{};
  std::size_t attribute_count{};
};

struct TransformAttributeView {
  std::size_t transform_index{};
  std::uint16_t type{};
  bool basic{};
  std::uint16_t basic_value{};
  std::span<const std::uint8_t> variable_value;
};

enum class SaParseStatus : std::uint8_t {
  ok,
  truncated_proposal,
  invalid_proposal_header,
  invalid_proposal_length,
  invalid_proposal_chain,
  proposal_capacity_exhausted,
  truncated_transform,
  invalid_transform_header,
  invalid_transform_length,
  invalid_transform_chain,
  transform_count_mismatch,
  transform_capacity_exhausted,
  invalid_attribute_length,
  attribute_capacity_exhausted
};

struct SaParseResult {
  SaParseStatus status{SaParseStatus::truncated_proposal};
  std::size_t proposal_count{};
  std::size_t transform_count{};
  std::size_t attribute_count{};
};

[[nodiscard]] SaParseResult parse_sa_payload(
    std::span<const std::uint8_t> body, std::span<ProposalView> proposals,
    std::span<TransformView> transforms,
    std::span<TransformAttributeView> attributes) noexcept;

enum class TrafficSelectorType : std::uint8_t {
  ipv4_address_range = 7U,
  ipv6_address_range = 8U
};

struct TrafficSelectorView {
  std::uint8_t type{};
  std::uint8_t protocol_id{};
  std::uint16_t start_port{};
  std::uint16_t end_port{};
  std::span<const std::uint8_t> start_address;
  std::span<const std::uint8_t> end_address;
};

enum class TrafficSelectorParseStatus : std::uint8_t {
  ok,
  truncated_header,
  invalid_reserved,
  unsupported_type,
  invalid_length,
  invalid_port_range,
  invalid_address_range,
  count_mismatch,
  capacity_exhausted
};

struct TrafficSelectorParseResult {
  TrafficSelectorParseStatus status{
      TrafficSelectorParseStatus::truncated_header};
  std::size_t selector_count{};
};

[[nodiscard]] TrafficSelectorParseResult
parse_traffic_selectors(std::span<const std::uint8_t> body,
                        std::span<TrafficSelectorView> selectors) noexcept;

} // namespace router::ikev2
