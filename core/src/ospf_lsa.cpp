// RFC 2328 Appendix A.4 and RFC 5340 Appendix A.4 LSA body parsing. Explicit
// network-order reads avoid packed structures, unaligned access and bit-field
// layout dependencies in native and WebAssembly builds.

#include "router/ospf_lsa.hpp"

#include <algorithm>

namespace router::packet::ospf::lsa {
namespace {

[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[offset]) << 8U |
      bytes[offset + 1U]);
}

[[nodiscard]] std::uint32_t read24(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
         bytes[offset + 2U];
}

[[nodiscard]] std::uint32_t read32(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

[[nodiscard]] std::optional<LsaHeaderView>
body_header(std::span<const std::uint8_t> encoded,
            std::uint8_t version) noexcept {
  const auto header = lsa_header(encoded, version);
  if (!header || header->length != encoded.size())
    return std::nullopt;
  return header;
}

[[nodiscard]] bool valid_router_link_type(std::uint8_t type) noexcept {
  return type >= static_cast<std::uint8_t>(RouterLinkType::point_to_point) &&
         type <= static_cast<std::uint8_t>(RouterLinkType::virtual_link);
}

[[nodiscard]] std::size_t padded_prefix_octets(std::uint8_t length) noexcept {
  // OSPFv3 pads every prefix to the next 32-bit boundary. The returned length
  // describes the wire field, not only the meaningful address octets.
  return ((static_cast<std::size_t>(length) + 31U) / 32U) * 4U;
}

[[nodiscard]] bool canonical_prefix(std::span<const std::uint8_t> bytes,
                                    std::uint8_t length,
                                    std::size_t padded_octets) noexcept {
  if (length > ip::ipv6_address_bits || bytes.size() < padded_octets)
    return false;
  const auto meaningful = (static_cast<std::size_t>(length) + 7U) / 8U;
  if (meaningful != 0U && length % 8U != 0U) {
    const auto host_mask =
        static_cast<std::uint8_t>((1U << (8U - length % 8U)) - 1U);
    if ((bytes[meaningful - 1U] & host_mask) != 0U)
      return false;
  }
  return std::all_of(bytes.begin() + meaningful,
                     bytes.begin() + padded_octets,
                     [](std::uint8_t value) { return value == 0U; });
}

} // namespace

std::optional<VersionTwoRouterView>
parse_version_two_router(std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  constexpr std::size_t fixed_body = 4U;
  const auto header = body_header(encoded, version_two);
  if (!header || header->type != 1U ||
      encoded.size() < body_offset + fixed_body)
    return std::nullopt;
  const auto flags = encoded[body_offset];
  VersionTwoRouterView view{
      .links = encoded.subspan(body_offset + fixed_body),
      .link_count = read16(encoded, body_offset + 2U),
      .area_border_router = (flags & 0x01U) != 0U,
      .autonomous_system_boundary_router = (flags & 0x02U) != 0U,
      .virtual_link_endpoint = (flags & 0x04U) != 0U};

  // Walk all variable TOS sections before publishing the view. This prevents a
  // caller from accepting the first links of a truncated Router-LSA.
  std::size_t offset{};
  for (std::size_t index{}; index < view.link_count; ++index) {
    const auto link = version_two_router_link(view, offset);
    if (!link)
      return std::nullopt;
    offset = link->next_offset;
  }
  if (offset != view.links.size())
    return std::nullopt;
  return view;
}

std::optional<VersionTwoRouterLink>
version_two_router_link(const VersionTwoRouterView &view,
                        std::size_t offset) noexcept {
  constexpr std::size_t fixed_octets = 12U;
  if (offset > view.links.size() ||
      view.links.size() - offset < fixed_octets)
    return std::nullopt;
  const auto type = view.links[offset + 8U];
  const auto tos_count = view.links[offset + 9U];
  const auto size = fixed_octets + static_cast<std::size_t>(tos_count) * 4U;
  if (!valid_router_link_type(type) || size > view.links.size() - offset)
    return std::nullopt;
  return VersionTwoRouterLink{
      .link_id = read32(view.links, offset),
      .link_data = read32(view.links, offset + 4U),
      .metric = read16(view.links, offset + 10U),
      .type = static_cast<RouterLinkType>(type),
      .tos_count = tos_count,
      .next_offset = offset + size};
}

std::optional<VersionTwoNetworkView>
parse_version_two_network(std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  const auto header = body_header(encoded, version_two);
  if (!header || header->type != 2U || encoded.size() < body_offset + 4U ||
      (encoded.size() - body_offset - 4U) % 4U != 0U)
    return std::nullopt;
  return VersionTwoNetworkView{
      .attached_routers = encoded.subspan(body_offset + 4U),
      .network_mask = read32(encoded, body_offset)};
}

std::optional<VersionTwoSummaryView>
parse_version_two_summary(std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  constexpr std::size_t base_body_octets = 8U;
  const auto header = body_header(encoded, version_two);
  if (!header || (header->type != 3U && header->type != 4U) ||
      encoded.size() < body_offset + base_body_octets ||
      (encoded.size() - body_offset - base_body_octets) % 4U != 0U)
    return std::nullopt;
  // The first metric octet is reserved for TOS zero. Nonzero reserved bits are
  // rejected instead of being reinterpreted as a metric above LSInfinity.
  if (encoded[body_offset + 4U] != 0U)
    return std::nullopt;
  return VersionTwoSummaryView{
      .network_mask = read32(encoded, body_offset),
      .metric = read24(encoded, body_offset + 5U),
      .autonomous_system_boundary_router = header->type == 4U};
}

std::optional<VersionTwoExternalView>
parse_version_two_external(std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  constexpr std::size_t base_body_octets = 16U;
  const auto header = body_header(encoded, version_two);
  if (!header || (header->type != 5U && header->type != 7U) ||
      encoded.size() < body_offset + base_body_octets ||
      (encoded.size() - body_offset - base_body_octets) % 12U != 0U)
    return std::nullopt;
  const auto metric_word = read32(encoded, body_offset + 4U);
  return VersionTwoExternalView{
      .network_mask = read32(encoded, body_offset),
      .metric = metric_word & 0x00ffffffU,
      .forwarding_address = read32(encoded, body_offset + 8U),
      .route_tag = read32(encoded, body_offset + 12U),
      .type_two_metric = (metric_word & 0x80000000U) != 0U,
      .nssa = header->type == 7U};
}

std::optional<std::uint32_t>
attached_router(const VersionTwoNetworkView &view,
                std::size_t index) noexcept {
  const auto offset = index * 4U;
  if (offset > view.attached_routers.size() ||
      view.attached_routers.size() - offset < 4U)
    return std::nullopt;
  return read32(view.attached_routers, offset);
}

std::optional<VersionThreeRouterView>
parse_version_three_router(std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  constexpr std::size_t fixed_body = 4U;
  constexpr std::size_t link_octets = 16U;
  const auto header = body_header(encoded, version_three);
  if (!header || (header->type & 0x1fffU) != 0x0001U ||
      encoded.size() < body_offset + fixed_body ||
      (encoded.size() - body_offset - fixed_body) % link_octets != 0U)
    return std::nullopt;
  return VersionThreeRouterView{
      .links = encoded.subspan(body_offset + fixed_body),
      .options = read24(encoded, body_offset + 1U),
      .flags = encoded[body_offset]};
}

std::optional<VersionThreeRouterLink>
version_three_router_link(const VersionThreeRouterView &view,
                          std::size_t index) noexcept {
  constexpr std::size_t link_octets = 16U;
  const auto offset = index * link_octets;
  if (offset > view.links.size() ||
      view.links.size() - offset < link_octets ||
      !valid_router_link_type(view.links[offset]) ||
      view.links[offset + 1U] != 0U)
    return std::nullopt;
  return VersionThreeRouterLink{
      .interface_id = read32(view.links, offset + 4U),
      .neighbor_interface_id = read32(view.links, offset + 8U),
      .neighbor_router_id = read32(view.links, offset + 12U),
      .metric = read16(view.links, offset + 2U),
      .type = static_cast<RouterLinkType>(view.links[offset])};
}

std::optional<VersionThreeNetworkView>
parse_version_three_network(std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  const auto header = body_header(encoded, version_three);
  if (!header || (header->type & 0x1fffU) != 0x0002U ||
      encoded.size() < body_offset + 4U ||
      (encoded.size() - body_offset - 4U) % 4U != 0U)
    return std::nullopt;
  return VersionThreeNetworkView{
      .attached_routers = encoded.subspan(body_offset + 4U),
      .options = read24(encoded, body_offset + 1U)};
}

std::optional<VersionThreeInterAreaPrefixView>
parse_version_three_inter_area_prefix(
    std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  const auto header = body_header(encoded, version_three);
  if (!header || (header->type & 0x1fffU) != 0x0003U ||
      encoded.size() < body_offset + 8U || encoded[body_offset] != 0U)
    return std::nullopt;
  const auto prefix =
      version_three_prefix(encoded.subspan(body_offset + 4U), 0U, false);
  if (!prefix || prefix->next_offset != encoded.size() - body_offset - 4U)
    return std::nullopt;
  return VersionThreeInterAreaPrefixView{
      .prefix = *prefix, .metric = read24(encoded, body_offset + 1U)};
}

std::optional<VersionThreeInterAreaRouterView>
parse_version_three_inter_area_router(
    std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  constexpr std::size_t body_octets = 12U;
  const auto header = body_header(encoded, version_three);
  if (!header || (header->type & 0x1fffU) != 0x0004U ||
      encoded.size() != body_offset + body_octets ||
      encoded[body_offset + 4U] != 0U)
    return std::nullopt;
  return VersionThreeInterAreaRouterView{
      .destination_router_id = read32(encoded, body_offset + 8U),
      .metric = read24(encoded, body_offset + 5U),
      .options = read24(encoded, body_offset + 1U)};
}

std::optional<VersionThreeExternalView>
parse_version_three_external(std::span<const std::uint8_t> encoded,
                             bool ipv4_address_family) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  const auto header = body_header(encoded, version_three);
  const auto function = header ? header->type & 0x1fffU : 0U;
  if (!header || (function != 0x0005U && function != 0x0007U) ||
      encoded.size() < body_offset + 8U)
    return std::nullopt;
  const auto flags_metric = read32(encoded, body_offset);
  const bool forwarding_present = (flags_metric & 0x40000000U) != 0U;
  const bool tag_present = (flags_metric & 0x20000000U) != 0U;
  auto prefix =
      version_three_prefix(encoded.subspan(body_offset + 4U), 0U, false,
                           false);
  if (!prefix || (ipv4_address_family && prefix->length > 32U))
    return std::nullopt;
  std::size_t offset = body_offset + 4U + prefix->next_offset;
  const auto forwarding_octets =
      forwarding_present ? (ipv4_address_family ? 4U : 16U) : 0U;
  if (forwarding_octets > encoded.size() - offset)
    return std::nullopt;
  const auto forwarding = encoded.subspan(offset, forwarding_octets);
  offset += forwarding_octets;
  std::optional<std::uint32_t> tag;
  if (tag_present) {
    if (encoded.size() - offset < 4U)
      return std::nullopt;
    tag = read32(encoded, offset);
    offset += 4U;
  }
  std::optional<std::uint32_t> reference;
  // A nonzero Referenced LS Type adds its Link State ID after optional fields.
  const auto referenced_type =
      read16(encoded.subspan(body_offset + 4U), 2U);
  if (referenced_type != 0U) {
    if (encoded.size() - offset < 4U)
      return std::nullopt;
    reference = read32(encoded, offset);
    offset += 4U;
  }
  if (offset != encoded.size())
    return std::nullopt;
  return VersionThreeExternalView{
      .prefix = *prefix,
      .forwarding_address = forwarding,
      .route_tag = tag,
      .referenced_link_state_id = reference,
      .metric = flags_metric & 0x00ffffffU,
      .type_two_metric = (flags_metric & 0x80000000U) != 0U,
      .nssa = function == 0x0007U};
}

std::optional<VersionThreeLinkView>
parse_version_three_link(std::span<const std::uint8_t> encoded,
                         bool ipv4_address_family) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  constexpr std::size_t fixed_body = 24U;
  const auto header = body_header(encoded, version_three);
  if (!header || (header->type & 0x1fffU) != 0x0008U ||
      encoded.size() < body_offset + fixed_body)
    return std::nullopt;
  VersionThreeLinkView view{
      .prefixes = encoded.subspan(body_offset + fixed_body),
      .options = read24(encoded, body_offset + 1U),
      .prefix_count = read32(encoded, body_offset + 20U),
      .router_priority = encoded[body_offset]};
  std::copy_n(encoded.begin() + body_offset + 4U,
              view.link_local_address.size(),
              view.link_local_address.begin());
  std::size_t offset{};
  for (std::size_t index{}; index < view.prefix_count; ++index) {
    const auto prefix = version_three_prefix(view.prefixes, offset, false);
    if (!prefix)
      return std::nullopt;
    offset = prefix->next_offset;
  }
  if (offset != view.prefixes.size())
    return std::nullopt;

  if (ipv4_address_family) {
    // RFC 5838 section 2.5 reuses the 128-bit Link-LSA field for an IPv4
    // Direct Interface Address. The address occupies the first 32 bits and
    // every remaining bit is zero. It is intentionally not passed through an
    // IPv6 link-local validator because it is an IPv4 forwarding next hop.
    if (std::all_of(view.link_local_address.begin(),
                    view.link_local_address.begin() + 4U,
                    [](std::uint8_t octet) { return octet == 0U; }) ||
        !std::all_of(view.link_local_address.begin() + 4U,
                     view.link_local_address.end(),
                     [](std::uint8_t octet) { return octet == 0U; }))
      return std::nullopt;
  } else if (!ip::is_link_local(view.link_local_address)) {
    return std::nullopt;
  }
  return view;
}

std::optional<std::uint32_t>
attached_router(const VersionThreeNetworkView &view,
                std::size_t index) noexcept {
  const auto offset = index * 4U;
  if (offset > view.attached_routers.size() ||
      view.attached_routers.size() - offset < 4U)
    return std::nullopt;
  return read32(view.attached_routers, offset);
}

std::optional<VersionThreePrefix>
version_three_prefix(std::span<const std::uint8_t> prefixes,
                     std::size_t offset, bool metric_present,
                     bool reserved_must_be_zero) noexcept {
  const std::size_t fixed = metric_present ? 4U : 4U;
  if (offset > prefixes.size() || prefixes.size() - offset < fixed)
    return std::nullopt;
  const auto length = prefixes[offset];
  const auto padded = padded_prefix_octets(length);
  const auto total = fixed + padded;
  if (length > ip::ipv6_address_bits || total > prefixes.size() - offset)
    return std::nullopt;
  const auto address = prefixes.subspan(offset + fixed, padded);
  if ((!metric_present && reserved_must_be_zero &&
       (prefixes[offset + 2U] != 0U || prefixes[offset + 3U] != 0U)) ||
      !canonical_prefix(address, length, padded))
    return std::nullopt;
  return VersionThreePrefix{
      .significant_octets =
          address.first((static_cast<std::size_t>(length) + 7U) / 8U),
      .metric = static_cast<std::uint16_t>(
          metric_present ? read16(prefixes, offset + 2U) : 0U),
      .length = length,
      .options = prefixes[offset + 1U],
      .next_offset = offset + total};
}

std::optional<VersionThreeIntraAreaPrefixView>
parse_version_three_intra_area_prefix(
    std::span<const std::uint8_t> encoded) noexcept {
  constexpr std::size_t body_offset = lsa_header_octets;
  constexpr std::size_t fixed_body = 12U;
  const auto header = body_header(encoded, version_three);
  if (!header || (header->type & 0x1fffU) != 0x0009U ||
      encoded.size() < body_offset + fixed_body)
    return std::nullopt;
  VersionThreeIntraAreaPrefixView view{
      .prefixes = encoded.subspan(body_offset + fixed_body),
      .referenced_link_state_id = read32(encoded, body_offset + 4U),
      .referenced_advertising_router = read32(encoded, body_offset + 8U),
      .prefix_count = read16(encoded, body_offset),
      .referenced_lsa_type = read16(encoded, body_offset + 2U)};
  std::size_t offset{};
  for (std::size_t index{}; index < view.prefix_count; ++index) {
    const auto prefix = version_three_prefix(view.prefixes, offset, true);
    if (!prefix)
      return std::nullopt;
    offset = prefix->next_offset;
  }
  if (offset != view.prefixes.size())
    return std::nullopt;
  return view;
}

std::optional<TlvView>
tlv(std::span<const std::uint8_t> body, std::size_t offset) noexcept {
  constexpr std::size_t header_octets = 4U;
  if (offset > body.size() || body.size() - offset < header_octets)
    return std::nullopt;
  const auto length = static_cast<std::size_t>(read16(body, offset + 2U));
  const auto padded = (length + 3U) & ~std::size_t{3U};
  if (padded > body.size() - offset - header_octets)
    return std::nullopt;
  return TlvView{
      .value = body.subspan(offset + header_octets, length),
      .type = read16(body, offset),
      .next_offset = offset + header_octets + padded};
}

std::optional<GraceLsaView>
parse_grace_lsa(std::span<const std::uint8_t> encoded,
                std::uint8_t version) noexcept {
  const auto header = body_header(encoded, version);
  if (!header)
    return std::nullopt;
  if (version == version_two) {
    if (header->type != version_two_link_opaque_type ||
        (header->link_state_id >> 24U) !=
            version_two_grace_opaque_type ||
        (header->link_state_id & 0x00ffffffU) != 0U)
      return std::nullopt;
  } else if (version == version_three) {
    if (header->type != version_three_grace_type)
      return std::nullopt;
  } else {
    return std::nullopt;
  }

  GraceLsaView result;
  bool period_seen{};
  bool reason_seen{};
  const auto body = encoded.subspan(lsa_header_octets);
  std::size_t offset{};
  while (offset < body.size()) {
    const auto item = tlv(body, offset);
    if (!item)
      return std::nullopt;
    if (item->type == 1U) {
      if (period_seen || item->value.size() != 4U)
        return std::nullopt;
      result.grace_period_seconds = read32(item->value, 0U);
      period_seen = true;
    } else if (item->type == 2U) {
      if (reason_seen || item->value.size() != 1U ||
          item->value[0U] >
              static_cast<std::uint8_t>(
                  GraceRestartReason::redundant_control_processor))
        return std::nullopt;
      result.reason =
          static_cast<GraceRestartReason>(item->value[0U]);
      reason_seen = true;
    } else if (item->type == 3U) {
      if (version != version_two || result.interface_address ||
          item->value.size() != 4U)
        return std::nullopt;
      result.interface_address = read32(item->value, 0U);
    }
    offset = item->next_offset;
  }
  if (!period_seen || !reason_seen ||
      result.grace_period_seconds == 0U ||
      result.grace_period_seconds > 1800U)
    return std::nullopt;
  return result;
}

std::optional<RouterInformationView>
parse_router_information_lsa(
    std::span<const std::uint8_t> encoded,
    std::uint8_t version) noexcept {
  const auto header = body_header(encoded, version);
  if (!header)
    return std::nullopt;
  std::uint32_t instance{};
  if (version == version_two) {
    const bool opaque_scope =
        header->type == 9U || header->type == 10U ||
        header->type == 11U;
    if (!opaque_scope ||
        (header->link_state_id >> 24U) !=
            version_two_router_information_opaque_type)
      return std::nullopt;
    instance = header->link_state_id & 0x00ffffffU;
  } else if (version == version_three) {
    // U=1 is normative for RI-LSAs. Function code 12 alone is insufficient
    // because a U=0 unknown instance must instead follow RFC 5340's
    // unsupported-LSA handling.
    if ((header->type & 0x1fffU) != 12U ||
        (header->type & 0x8000U) == 0U)
      return std::nullopt;
    instance = header->link_state_id;
  } else {
    return std::nullopt;
  }

  RouterInformationView result;
  const auto body = encoded.subspan(lsa_header_octets);
  std::size_t offset{};
  std::size_t ordinal{};
  while (offset < body.size()) {
    const auto item = tlv(body, offset);
    if (!item)
      return std::nullopt;
    if (item->type == 1U) {
      if (instance == 0U && ordinal != 0U)
        return std::nullopt;
      if (item->value.size() < 4U ||
          item->value.size() % 4U != 0U)
        return std::nullopt;
      if (result.informational_capabilities.empty())
        result.informational_capabilities = item->value;
    } else if (item->type == 2U) {
      if (instance != 0U || item->value.size() < 4U ||
          item->value.size() % 4U != 0U)
        return std::nullopt;
      if (result.functional_capabilities.empty())
        result.functional_capabilities = item->value;
    }
    offset = item->next_offset;
    ++ordinal;
  }
  return result;
}

std::optional<ip::Ipv6>
expand_prefix(const VersionThreePrefix &prefix) noexcept {
  if (prefix.length > ip::ipv6_address_bits ||
      prefix.significant_octets.size() !=
          (static_cast<std::size_t>(prefix.length) + 7U) / 8U)
    return std::nullopt;
  ip::Ipv6 result{};
  std::copy(prefix.significant_octets.begin(),
            prefix.significant_octets.end(), result.begin());
  return result;
}

} // namespace router::packet::ospf::lsa
