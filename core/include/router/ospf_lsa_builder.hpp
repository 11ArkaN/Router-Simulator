// Allocation-free OSPF LSA origination. The instance owner supplies every
// semantic field and sequence number; this codec writes complete wire LSAs and
// their RFC Fletcher checksum without reading configuration or topology.

#pragma once

#include "router/ip_address.hpp"
#include "router/ospf_lsa.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::ospf::lsa {

struct OriginationHeader {
  std::uint32_t link_state_id{};
  std::uint32_t advertising_router{};
  std::int32_t sequence_number{};
  std::uint16_t age_seconds{};
  std::uint16_t type{};
  std::uint32_t options{};
  std::uint8_t version{};
};

struct VersionTwoRouterLinkInput {
  std::uint32_t link_id{};
  std::uint32_t link_data{};
  std::uint16_t metric{};
  RouterLinkType type{RouterLinkType::point_to_point};
};

struct VersionThreeRouterLinkInput {
  std::uint32_t interface_id{};
  std::uint32_t neighbor_interface_id{};
  std::uint32_t neighbor_router_id{};
  std::uint16_t metric{};
  RouterLinkType type{RouterLinkType::point_to_point};
};

struct PrefixInput {
  ip::Ipv6 network{};
  std::uint16_t metric{};
  std::uint8_t length{};
  std::uint8_t options{};
};

[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_two_router_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::span<const VersionTwoRouterLinkInput> links, bool abr, bool asbr,
    bool virtual_link_endpoint) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_two_network_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t network_mask,
    std::span<const std::uint32_t> attached_routers) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_two_summary_lsa(std::span<std::uint8_t> output,
                               const OriginationHeader &header,
                               std::uint32_t network_mask,
                               std::uint32_t metric) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_two_external_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t network_mask, std::uint32_t metric, bool type_two,
    std::uint32_t forwarding_address, std::uint32_t route_tag) noexcept;

[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three_router_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::span<const VersionThreeRouterLinkInput> links, std::uint8_t flags,
    std::uint32_t options) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three_network_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t options,
    std::span<const std::uint32_t> attached_routers) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three_inter_area_prefix_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t metric, const PrefixInput &prefix) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three_inter_area_router_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t options, std::uint32_t metric,
    std::uint32_t destination_router_id) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three_external_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t metric, bool type_two, const PrefixInput &prefix,
    std::span<const std::uint8_t> forwarding_address,
    const std::optional<std::uint32_t> &route_tag,
    std::uint16_t referenced_lsa_type,
    const std::optional<std::uint32_t> &referenced_link_state_id) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three_link_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint8_t priority, std::uint32_t options,
    const ip::Ipv6 &link_local,
    std::span<const PrefixInput> prefixes) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three_intra_area_prefix_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint16_t referenced_type, std::uint32_t referenced_link_state_id,
    std::uint32_t referenced_advertising_router,
    std::span<const PrefixInput> prefixes) noexcept;

// The base profile originates RI Instance 0 with the four-octet
// informational bitmap. The caller chooses the standards-defined flooding
// scope in OriginationHeader; this writer does not infer scope from topology.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_router_information_lsa(
    std::span<std::uint8_t> output, const OriginationHeader &header,
    std::uint32_t informational_capabilities) noexcept;

} // namespace router::packet::ospf::lsa
