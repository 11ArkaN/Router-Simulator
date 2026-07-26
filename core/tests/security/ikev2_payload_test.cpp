// IKEv2 nested payload tests cross-check proposal, transform, attribute and
// Traffic Selector count and length fields against independently bounded views.

#include "router/ikev2_payload.hpp"

#include <array>
#include <stdexcept>

void ikev2_payload_tests() {
  using namespace router::ikev2;
  // One IKE proposal contains AES-GCM-16 with a basic Key Length attribute and
  // a second DH group 14 transform. Last/More values are part of the wire test.
  const std::array<std::uint8_t, 28> sa{
      0U, 0U, 0U, 28U, 1U, 1U, 0U, 2U,
      3U, 0U, 0U, 12U, 1U, 0U, 0U, 20U,
      0x80U, 14U, 0U, 128U,
      0U, 0U, 0U, 8U, 4U, 0U, 0U, 14U};
  std::array<ProposalView, 2> proposals{};
  std::array<TransformView, 4> transforms{};
  std::array<TransformAttributeView, 4> attributes{};
  const auto parsed = parse_sa_payload(sa, proposals, transforms, attributes);
  if (parsed.status != SaParseStatus::ok || parsed.proposal_count != 1U ||
      parsed.transform_count != 2U || parsed.attribute_count != 1U ||
      proposals[0].number != 1U || proposals[0].protocol_id != 1U ||
      proposals[0].transform_count != 2U || transforms[0].type != 1U ||
      transforms[0].id != 20U || transforms[0].attribute_count != 1U ||
      !attributes[0].basic || attributes[0].type != 14U ||
      attributes[0].basic_value != 128U || transforms[1].type != 4U ||
      transforms[1].id != 14U)
    throw std::runtime_error("IKEv2 SA proposal parsing failed");

  auto malformed_sa = sa;
  malformed_sa[7U] = 1U;
  if (parse_sa_payload(malformed_sa, proposals, transforms, attributes).status !=
      SaParseStatus::transform_count_mismatch)
    throw std::runtime_error("IKEv2 transform count mismatch was accepted");
  malformed_sa = sa;
  malformed_sa[20U] = 3U;
  if (parse_sa_payload(malformed_sa, proposals, transforms, attributes).status !=
      SaParseStatus::transform_count_mismatch)
    throw std::runtime_error("IKEv2 trailing More transform was accepted");

  std::array<std::uint8_t, 44> selectors{};
  selectors[0] = 1U;
  selectors[4] = static_cast<std::uint8_t>(
      TrafficSelectorType::ipv6_address_range);
  selectors[5] = 17U;
  selectors[6] = 0U;
  selectors[7] = 40U;
  selectors[8] = 0U;
  selectors[9] = 53U;
  selectors[10] = 0U;
  selectors[11] = 53U;
  // 2001:db8::1 through 2001:db8::ffff is an ordered IPv6 range.
  selectors[12] = 0x20U;
  selectors[13] = 0x01U;
  selectors[14] = 0x0dU;
  selectors[15] = 0xb8U;
  selectors[27] = 1U;
  selectors[28] = 0x20U;
  selectors[29] = 0x01U;
  selectors[30] = 0x0dU;
  selectors[31] = 0xb8U;
  selectors[42] = 0xffU;
  selectors[43] = 0xffU;
  std::array<TrafficSelectorView, 2> selector_views{};
  const auto traffic = parse_traffic_selectors(selectors, selector_views);
  if (traffic.status != TrafficSelectorParseStatus::ok ||
      traffic.selector_count != 1U || selector_views[0].protocol_id != 17U ||
      selector_views[0].start_port != 53U ||
      selector_views[0].end_port != 53U ||
      selector_views[0].start_address.size() != 16U ||
      selector_views[0].end_address[15] != 0xffU)
    throw std::runtime_error("IKEv2 IPv6 Traffic Selector parsing failed");

  auto reversed = selectors;
  reversed[12U] = 0x30U;
  if (parse_traffic_selectors(reversed, selector_views).status !=
      TrafficSelectorParseStatus::invalid_address_range)
    throw std::runtime_error("reversed IKEv2 address range was accepted");
  auto wrong_count = selectors;
  wrong_count[0] = 2U;
  if (parse_traffic_selectors(wrong_count, selector_views).status !=
      TrafficSelectorParseStatus::count_mismatch)
    throw std::runtime_error("IKEv2 Traffic Selector count mismatch was accepted");
}
