// OSPF LSA wire writers. All lengths are preflighted before bytes are exposed,
// and the common finalizer applies one canonical header and Fletcher checksum.

#include "router/ospf_lsa_builder.hpp"

#include "router/ospf_lsdb.hpp"

#include <algorithm>
#include <limits>

namespace router::packet::ospf::lsa {
namespace {

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write24(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] bool canonical(const PrefixInput &prefix) noexcept {
  return prefix.length <= ip::ipv6_address_bits &&
         ip::mask(prefix.network, prefix.length) == prefix.network;
}

[[nodiscard]] std::size_t prefix_octets(const PrefixInput &prefix) noexcept {
  return ((static_cast<std::size_t>(prefix.length) + 31U) / 32U) * 4U;
}

[[nodiscard]] std::optional<std::size_t>
prefixes_octets(std::span<const PrefixInput> prefixes,
                bool metric) noexcept {
  std::size_t total{};
  for (const auto &prefix : prefixes) {
    if (!canonical(prefix))
      return std::nullopt;
    const auto item = (metric ? 4U : 4U) + prefix_octets(prefix);
    if (total > std::numeric_limits<std::uint16_t>::max() - item)
      return std::nullopt;
    total += item;
  }
  return total;
}

void write_prefix(std::span<std::uint8_t> output, std::size_t offset,
                  const PrefixInput &prefix, bool metric) noexcept {
  output[offset] = prefix.length;
  output[offset + 1U] = prefix.options;
  write16(output, offset + 2U, metric ? prefix.metric : 0U);
  const auto octets = prefix_octets(prefix);
  std::copy_n(prefix.network.begin(), octets,
              output.begin() + static_cast<std::ptrdiff_t>(offset + 4U));
}

[[nodiscard]] std::optional<std::span<const std::uint8_t>>
finish(std::span<std::uint8_t> output, const OriginationHeader &header,
       std::size_t length) noexcept {
  if (length < ospf::lsa_header_octets || length > output.size() ||
      length > std::numeric_limits<std::uint16_t>::max() ||
      (header.version != ospf::version_two &&
       header.version != ospf::version_three))
    return std::nullopt;
  auto lsa = output.first(length);
  write16(lsa, 0U, header.age_seconds);
  if (header.version == ospf::version_two) {
    lsa[2U] = static_cast<std::uint8_t>(header.options);
    lsa[3U] = static_cast<std::uint8_t>(header.type);
  } else {
    write16(lsa, 2U, header.type);
  }
  write32(lsa, 4U, header.link_state_id);
  write32(lsa, 8U, header.advertising_router);
  write32(lsa, 12U, static_cast<std::uint32_t>(header.sequence_number));
  write16(lsa, 16U, 0U);
  write16(lsa, 18U, static_cast<std::uint16_t>(length));
  if (!router::ospf::update_lsa_checksum(lsa))
    return std::nullopt;
  return std::span<const std::uint8_t>{lsa};
}

} // namespace

std::optional<std::span<const std::uint8_t>>
encode_version_two_router_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::span<const VersionTwoRouterLinkInput> links, bool abr, bool asbr,
    bool virtual_link_endpoint) noexcept {
  const auto length = ospf::lsa_header_octets + 4U + links.size() * 12U;
  if (header.version != ospf::version_two || header.type != 1U ||
      links.size() > std::numeric_limits<std::uint16_t>::max() ||
      length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  bytes[20U] = static_cast<std::uint8_t>(
      (abr ? 0x01U : 0U) | (asbr ? 0x02U : 0U) |
      (virtual_link_endpoint ? 0x04U : 0U));
  write16(bytes, 22U, static_cast<std::uint16_t>(links.size()));
  for (std::size_t index{}; index < links.size(); ++index) {
    const auto offset = 24U + index * 12U;
    write32(bytes, offset, links[index].link_id);
    write32(bytes, offset + 4U, links[index].link_data);
    bytes[offset + 8U] = static_cast<std::uint8_t>(links[index].type);
    write16(bytes, offset + 10U, links[index].metric);
  }
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_two_network_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t network_mask,
    std::span<const std::uint32_t> attached_routers) noexcept {
  const auto length =
      ospf::lsa_header_octets + 4U + attached_routers.size() * 4U;
  if (header.version != ospf::version_two || header.type != 2U ||
      attached_routers.empty() || length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  write32(bytes, 20U, network_mask);
  for (std::size_t index{}; index < attached_routers.size(); ++index)
    write32(bytes, 24U + index * 4U, attached_routers[index]);
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_two_summary_lsa(std::span<std::uint8_t> output,
                               const OriginationHeader &header,
                               std::uint32_t network_mask,
                               std::uint32_t metric) noexcept {
  constexpr std::size_t length = ospf::lsa_header_octets + 8U;
  if (header.version != ospf::version_two ||
      (header.type != 3U && header.type != 4U) ||
      metric > 0x00ffffffU || output.size() < length)
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  write32(bytes, 20U, network_mask);
  write24(bytes, 25U, metric);
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_two_external_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t network_mask, std::uint32_t metric, bool type_two,
    std::uint32_t forwarding_address, std::uint32_t route_tag) noexcept {
  constexpr std::size_t length = ospf::lsa_header_octets + 16U;
  if (header.version != ospf::version_two ||
      (header.type != 5U && header.type != 7U) ||
      metric > 0x00ffffffU || output.size() < length)
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  write32(bytes, 20U, network_mask);
  bytes[24U] = type_two ? 0x80U : 0U;
  write24(bytes, 25U, metric);
  write32(bytes, 28U, forwarding_address);
  write32(bytes, 32U, route_tag);
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_three_router_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::span<const VersionThreeRouterLinkInput> links, std::uint8_t flags,
    std::uint32_t options) noexcept {
  const auto length = ospf::lsa_header_octets + 4U + links.size() * 16U;
  if (header.version != ospf::version_three ||
      (header.type & 0x1fffU) != 1U || length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  bytes[20U] = flags;
  write24(bytes, 21U, options);
  for (std::size_t index{}; index < links.size(); ++index) {
    const auto offset = 24U + index * 16U;
    bytes[offset] = static_cast<std::uint8_t>(links[index].type);
    write16(bytes, offset + 2U, links[index].metric);
    write32(bytes, offset + 4U, links[index].interface_id);
    write32(bytes, offset + 8U, links[index].neighbor_interface_id);
    write32(bytes, offset + 12U, links[index].neighbor_router_id);
  }
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_three_network_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t options,
    std::span<const std::uint32_t> attached_routers) noexcept {
  const auto length =
      ospf::lsa_header_octets + 4U + attached_routers.size() * 4U;
  if (header.version != ospf::version_three ||
      (header.type & 0x1fffU) != 2U || attached_routers.empty() ||
      length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  write24(bytes, 21U, options);
  for (std::size_t index{}; index < attached_routers.size(); ++index)
    write32(bytes, 24U + index * 4U, attached_routers[index]);
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_three_inter_area_prefix_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t metric, const PrefixInput &prefix) noexcept {
  // RFC 5340 section A.4.3 carries one prefix after the 24-bit metric. Unlike
  // Intra-Area-Prefix-LSA, this prefix descriptor has no separate metric field.
  const auto significant = prefix_octets(prefix);
  const auto length = ospf::lsa_header_octets + 8U + significant;
  if (header.version != ospf::version_three ||
      (header.type & 0x1fffU) != 3U || metric > 0x00ffffffU ||
      !canonical(prefix) || length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  write24(bytes, 21U, metric);
  write_prefix(bytes, 24U, prefix, false);
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_three_inter_area_router_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t options, std::uint32_t metric,
    std::uint32_t destination_router_id) noexcept {
  // RFC 5340 section A.4.4 uses fixed-width options, metric and destination
  // Router ID. Zero Router ID cannot identify an ASBR and is rejected before
  // bytes become eligible for LSDB installation.
  constexpr std::size_t length = ospf::lsa_header_octets + 12U;
  if (header.version != ospf::version_three ||
      (header.type & 0x1fffU) != 4U || options > 0x00ffffffU ||
      metric > 0x00ffffffU || destination_router_id == 0U ||
      output.size() < length)
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  write24(bytes, 21U, options);
  write24(bytes, 25U, metric);
  write32(bytes, 28U, destination_router_id);
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_three_external_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t metric, bool type_two, const PrefixInput &prefix,
    std::span<const std::uint8_t> forwarding_address,
    const std::optional<std::uint32_t> &route_tag,
    std::uint16_t referenced_lsa_type,
    const std::optional<std::uint32_t> &referenced_link_state_id) noexcept {
  // RFC 5340 sections A.4.5 and A.4.6 make the F, T and referenced-LSA fields
  // independently optional. Preflight the exact body so no truncated optional
  // value can escape if the interface MTU buffer is too small.
  const auto significant = prefix_octets(prefix);
  const auto optional_octets = forwarding_address.size() +
                               (route_tag ? 4U : 0U) +
                               (referenced_link_state_id ? 4U : 0U);
  const auto length =
      ospf::lsa_header_octets + 8U + significant + optional_octets;
  const auto function_code = header.type & 0x1fffU;
  if (header.version != ospf::version_three ||
      (function_code != 5U && function_code != 7U) ||
      metric > 0x00ffffffU || !canonical(prefix) ||
      (!forwarding_address.empty() && forwarding_address.size() != 4U &&
       forwarding_address.size() != 16U) ||
      ((referenced_lsa_type == 0U) !=
       !referenced_link_state_id.has_value()) ||
      length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  bytes[20U] = static_cast<std::uint8_t>(
      (type_two ? 0x80U : 0U) |
      (!forwarding_address.empty() ? 0x40U : 0U) |
      (route_tag ? 0x20U : 0U));
  write24(bytes, 21U, metric);
  bytes[24U] = prefix.length;
  bytes[25U] = prefix.options;
  write16(bytes, 26U, referenced_lsa_type);
  std::copy_n(prefix.network.begin(), significant, bytes.begin() + 28U);
  auto offset = 28U + significant;
  if (!forwarding_address.empty()) {
    std::copy(forwarding_address.begin(), forwarding_address.end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += forwarding_address.size();
  }
  if (route_tag) {
    write32(bytes, offset, *route_tag);
    offset += 4U;
  }
  if (referenced_link_state_id)
    write32(bytes, offset, *referenced_link_state_id);
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_three_link_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint8_t priority, std::uint32_t options,
    const ip::Ipv6 &link_local,
    std::span<const PrefixInput> prefixes) noexcept {
  const auto prefix_bytes = prefixes_octets(prefixes, false);
  if (!prefix_bytes || header.version != ospf::version_three ||
      (header.type & 0x1fffU) != 8U)
    return std::nullopt;
  const auto length = ospf::lsa_header_octets + 24U + *prefix_bytes;
  if (length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  bytes[20U] = priority;
  write24(bytes, 21U, options);
  std::copy(link_local.begin(), link_local.end(),
            bytes.begin() + 24U);
  write32(bytes, 40U, static_cast<std::uint32_t>(prefixes.size()));
  std::size_t offset = 44U;
  for (const auto &prefix : prefixes) {
    write_prefix(bytes, offset, prefix, false);
    offset += 4U + prefix_octets(prefix);
  }
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_version_three_intra_area_prefix_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint16_t referenced_type, std::uint32_t referenced_link_state_id,
    std::uint32_t referenced_advertising_router,
    std::span<const PrefixInput> prefixes) noexcept {
  const auto prefix_bytes = prefixes_octets(prefixes, true);
  if (!prefix_bytes || header.version != ospf::version_three ||
      (header.type & 0x1fffU) != 9U ||
      prefixes.size() > std::numeric_limits<std::uint16_t>::max())
    return std::nullopt;
  const auto length = ospf::lsa_header_octets + 12U + *prefix_bytes;
  if (length > output.size())
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  write16(bytes, 20U, static_cast<std::uint16_t>(prefixes.size()));
  write16(bytes, 22U, referenced_type);
  write32(bytes, 24U, referenced_link_state_id);
  write32(bytes, 28U, referenced_advertising_router);
  std::size_t offset = 32U;
  for (const auto &prefix : prefixes) {
    write_prefix(bytes, offset, prefix, true);
    offset += 4U + prefix_octets(prefix);
  }
  return finish(bytes, header, length);
}

std::optional<std::span<const std::uint8_t>>
encode_router_information_lsa(
    std::span<std::uint8_t> output,
    const OriginationHeader &header,
    std::uint32_t informational_capabilities) noexcept {
  constexpr std::size_t length = ospf::lsa_header_octets + 8U;
  const bool version_two_identity =
      header.version == ospf::version_two &&
      (header.type == 9U || header.type == 10U ||
       header.type == 11U) &&
      (header.link_state_id >> 24U) ==
          version_two_router_information_opaque_type;
  const bool version_three_identity =
      header.version == ospf::version_three &&
      (header.type & 0x1fffU) == 12U &&
      (header.type & 0x8000U) != 0U;
  if ((!version_two_identity && !version_three_identity) ||
      output.size() < length)
    return std::nullopt;
  auto bytes = output.first(length);
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{0U});
  // RFC 7770 section 2.4 assigns TLV type 1, requires a multiple-of-four
  // value and specifies that bit zero is the most significant bit.
  write16(bytes, 20U, 1U);
  write16(bytes, 22U, 4U);
  write32(bytes, 24U, informational_capabilities);
  return finish(bytes, header, length);
}

} // namespace router::packet::ospf::lsa
