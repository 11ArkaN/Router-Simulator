// RFC 7296 sections 3.3 and 3.13 nested payload validation. All transmitted
// length, count and last-substructure fields are cross-checked so negotiation
// cannot operate on a prefix of a malformed proposal or selector list.

#include "router/ikev2_payload.hpp"

#include <algorithm>

namespace router::ikev2 {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(bytes[offset] << 8U) |
         bytes[offset + 1U];
}

bool address_ordered(std::span<const std::uint8_t> first,
                     std::span<const std::uint8_t> last) noexcept {
  return !std::lexicographical_compare(last.begin(), last.end(), first.begin(),
                                       first.end());
}

SaParseResult failure(SaParseStatus status, std::size_t proposal_count,
                      std::size_t transform_count,
                      std::size_t attribute_count) noexcept {
  return {.status = status,
          .proposal_count = proposal_count,
          .transform_count = transform_count,
          .attribute_count = attribute_count};
}

} // namespace

SaParseResult parse_sa_payload(
    std::span<const std::uint8_t> body, std::span<ProposalView> proposals,
    std::span<TransformView> transforms,
    std::span<TransformAttributeView> attributes) noexcept {
  std::size_t proposal_offset{};
  std::size_t proposal_count{};
  std::size_t transform_count{};
  std::size_t attribute_count{};
  bool previous_requested_more{true};
  while (proposal_offset < body.size()) {
    if (!previous_requested_more)
      return failure(SaParseStatus::invalid_proposal_chain, proposal_count,
                     transform_count, attribute_count);
    if (body.size() - proposal_offset < 8U)
      return failure(SaParseStatus::truncated_proposal, proposal_count,
                     transform_count, attribute_count);
    if (proposal_count == proposals.size())
      return failure(SaParseStatus::proposal_capacity_exhausted, proposal_count,
                     transform_count, attribute_count);
    const auto last_or_more = body[proposal_offset];
    if ((last_or_more != 0U && last_or_more != 2U) ||
        body[proposal_offset + 1U] != 0U)
      return failure(SaParseStatus::invalid_proposal_header, proposal_count,
                     transform_count, attribute_count);
    const auto proposal_length = read_u16(body, proposal_offset + 2U);
    const auto spi_size = body[proposal_offset + 6U];
    const auto stated_transforms = body[proposal_offset + 7U];
    if (proposal_length < 8U + spi_size ||
        proposal_offset + proposal_length > body.size() ||
        stated_transforms == 0U)
      return failure(SaParseStatus::invalid_proposal_length, proposal_count,
                     transform_count, attribute_count);

    const auto proposal_end = proposal_offset + proposal_length;
    const auto this_proposal = proposal_count++;
    proposals[this_proposal] = {
        .number = body[proposal_offset + 4U],
        .protocol_id = body[proposal_offset + 5U],
        .spi = body.subspan(proposal_offset + 8U, spi_size),
        .first_transform = transform_count,
        .transform_count = 0U};

    auto transform_offset = proposal_offset + 8U + spi_size;
    bool transform_more{true};
    std::size_t parsed_in_proposal{};
    while (transform_offset < proposal_end) {
      if (!transform_more)
        return failure(SaParseStatus::invalid_transform_chain, proposal_count,
                       transform_count, attribute_count);
      if (proposal_end - transform_offset < 8U)
        return failure(SaParseStatus::truncated_transform, proposal_count,
                       transform_count, attribute_count);
      if (transform_count == transforms.size())
        return failure(SaParseStatus::transform_capacity_exhausted,
                       proposal_count, transform_count, attribute_count);
      const auto last_transform = body[transform_offset];
      if ((last_transform != 0U && last_transform != 3U) ||
          body[transform_offset + 1U] != 0U ||
          body[transform_offset + 5U] != 0U)
        return failure(SaParseStatus::invalid_transform_header, proposal_count,
                       transform_count, attribute_count);
      const auto transform_length = read_u16(body, transform_offset + 2U);
      if (transform_length < 8U ||
          transform_offset + transform_length > proposal_end)
        return failure(SaParseStatus::invalid_transform_length, proposal_count,
                       transform_count, attribute_count);

      const auto this_transform = transform_count++;
      transforms[this_transform] = {
          .proposal_index = this_proposal,
          .type = body[transform_offset + 4U],
          .id = read_u16(body, transform_offset + 6U),
          .first_attribute = attribute_count,
          .attribute_count = 0U};
      auto attribute_offset = transform_offset + 8U;
      const auto transform_end = transform_offset + transform_length;
      while (attribute_offset < transform_end) {
        if (transform_end - attribute_offset < 4U)
          return failure(SaParseStatus::invalid_attribute_length,
                         proposal_count, transform_count, attribute_count);
        if (attribute_count == attributes.size())
          return failure(SaParseStatus::attribute_capacity_exhausted,
                         proposal_count, transform_count, attribute_count);
        const auto encoded_type = read_u16(body, attribute_offset);
        const auto basic = (encoded_type & 0x8000U) != 0U;
        const auto type = static_cast<std::uint16_t>(encoded_type & 0x7fffU);
        const auto value_or_length = read_u16(body, attribute_offset + 2U);
        if (!basic && attribute_offset + 4U + value_or_length > transform_end)
          return failure(SaParseStatus::invalid_attribute_length,
                         proposal_count, transform_count, attribute_count);
        attributes[attribute_count++] = {
            .transform_index = this_transform,
            .type = type,
            .basic = basic,
            .basic_value =
                basic ? value_or_length : static_cast<std::uint16_t>(0U),
            .variable_value =
                basic ? std::span<const std::uint8_t>{}
                      : body.subspan(attribute_offset + 4U, value_or_length)};
        attribute_offset += basic ? 4U : 4U + value_or_length;
      }
      transforms[this_transform].attribute_count =
          attribute_count - transforms[this_transform].first_attribute;
      ++parsed_in_proposal;
      transform_offset = transform_end;
      transform_more = last_transform == 3U;
    }
    if (transform_more || parsed_in_proposal != stated_transforms)
      return failure(SaParseStatus::transform_count_mismatch, proposal_count,
                     transform_count, attribute_count);
    proposals[this_proposal].transform_count = parsed_in_proposal;
    proposal_offset = proposal_end;
    previous_requested_more = last_or_more == 2U;
  }
  if (proposal_count == 0U || previous_requested_more)
    return failure(SaParseStatus::invalid_proposal_chain, proposal_count,
                   transform_count, attribute_count);
  return failure(SaParseStatus::ok, proposal_count, transform_count,
                 attribute_count);
}

TrafficSelectorParseResult
parse_traffic_selectors(std::span<const std::uint8_t> body,
                        std::span<TrafficSelectorView> selectors) noexcept {
  if (body.size() < 4U)
    return {.status = TrafficSelectorParseStatus::truncated_header,
            .selector_count = 0U};
  if (body[1U] != 0U || body[2U] != 0U || body[3U] != 0U)
    return {.status = TrafficSelectorParseStatus::invalid_reserved,
            .selector_count = 0U};
  const auto stated_count = body[0U];
  std::size_t offset{4U};
  std::size_t count{};
  while (offset < body.size()) {
    if (count == selectors.size())
      return {.status = TrafficSelectorParseStatus::capacity_exhausted,
              .selector_count = count};
    if (body.size() - offset < 8U)
      return {.status = TrafficSelectorParseStatus::invalid_length,
              .selector_count = count};
    const auto type = body[offset];
    const auto address_octets =
        type == static_cast<std::uint8_t>(TrafficSelectorType::ipv4_address_range)
            ? 4U
        : type == static_cast<std::uint8_t>(
                     TrafficSelectorType::ipv6_address_range)
            ? 16U
            : 0U;
    if (address_octets == 0U)
      return {.status = TrafficSelectorParseStatus::unsupported_type,
              .selector_count = count};
    const auto length = read_u16(body, offset + 2U);
    if (length != 8U + address_octets * 2U || offset + length > body.size())
      return {.status = TrafficSelectorParseStatus::invalid_length,
              .selector_count = count};
    const auto start_port = read_u16(body, offset + 4U);
    const auto end_port = read_u16(body, offset + 6U);
    if (start_port > end_port)
      return {.status = TrafficSelectorParseStatus::invalid_port_range,
              .selector_count = count};
    const auto start_address = body.subspan(offset + 8U, address_octets);
    const auto end_address =
        body.subspan(offset + 8U + address_octets, address_octets);
    if (!address_ordered(start_address, end_address))
      return {.status = TrafficSelectorParseStatus::invalid_address_range,
              .selector_count = count};
    selectors[count++] = {.type = type,
                          .protocol_id = body[offset + 1U],
                          .start_port = start_port,
                          .end_port = end_port,
                          .start_address = start_address,
                          .end_address = end_address};
    offset += length;
  }
  if (count != stated_count)
    return {.status = TrafficSelectorParseStatus::count_mismatch,
            .selector_count = count};
  return {.status = TrafficSelectorParseStatus::ok, .selector_count = count};
}

} // namespace router::ikev2
