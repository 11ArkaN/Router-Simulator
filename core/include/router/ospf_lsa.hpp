// Typed, allocation-free views over validated OSPFv2 and OSPFv3 LSA bodies.
// Views alias one immutable encoded LSA owned by a packet or LSDB record. They
// may be used only while that storage remains stable and never own protocol
// state, graph vertices or route candidates.

#pragma once

#include "router/ip_address.hpp"
#include "router/ospf_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::ospf::lsa {

// RFC 2328 Appendix A.4 and RFC 5340 Appendix A.4 assign these exact wire
// values. Naming them keeps topology, origination and route calculation from
// carrying disconnected numeric interpretations of the same LSA type.
inline constexpr std::uint16_t version_two_router_type = 1U;
inline constexpr std::uint16_t version_two_network_type = 2U;
inline constexpr std::uint16_t version_two_summary_network_type = 3U;
inline constexpr std::uint16_t version_two_summary_asbr_type = 4U;
inline constexpr std::uint16_t version_two_external_type = 5U;
inline constexpr std::uint16_t version_two_nssa_type = 7U;
inline constexpr std::uint16_t version_three_router_type = 0x2001U;
inline constexpr std::uint16_t version_three_network_type = 0x2002U;
inline constexpr std::uint16_t version_three_inter_area_prefix_type = 0x2003U;
inline constexpr std::uint16_t version_three_inter_area_router_type = 0x2004U;
inline constexpr std::uint16_t version_three_external_type = 0x4005U;
inline constexpr std::uint16_t version_three_nssa_type = 0x2007U;
inline constexpr std::uint16_t version_three_link_type = 0x0008U;
inline constexpr std::uint16_t version_three_intra_area_prefix_type = 0x2009U;
inline constexpr std::uint16_t version_two_link_opaque_type = 9U;
inline constexpr std::uint16_t version_two_area_opaque_type = 10U;
inline constexpr std::uint8_t version_two_grace_opaque_type = 3U;
inline constexpr std::uint8_t version_two_router_information_opaque_type = 4U;
inline constexpr std::uint16_t version_three_grace_type = 0x000bU;
// RFC 7770 section 2.2 requires the U bit, area flooding scope and function
// code 12 for the ordinary area-scoped RI-LSA originated by this profile.
inline constexpr std::uint16_t version_three_router_information_type =
    0xa00cU;

enum class RouterLinkType : std::uint8_t {
  point_to_point = 1U,
  transit_network = 2U,
  stub_network = 3U,
  virtual_link = 4U
};

struct VersionTwoRouterView {
  std::span<const std::uint8_t> links{};
  std::uint16_t link_count{};
  bool area_border_router{};
  bool autonomous_system_boundary_router{};
  bool virtual_link_endpoint{};
};

struct VersionTwoRouterLink {
  std::uint32_t link_id{};
  std::uint32_t link_data{};
  std::uint16_t metric{};
  RouterLinkType type{RouterLinkType::point_to_point};
  std::uint8_t tos_count{};
  std::size_t next_offset{};
};

struct VersionTwoNetworkView {
  std::span<const std::uint8_t> attached_routers{};
  std::uint32_t network_mask{};
};

struct VersionTwoSummaryView {
  std::uint32_t network_mask{};
  std::uint32_t metric{};
  bool autonomous_system_boundary_router{};
};

struct VersionTwoExternalView {
  std::uint32_t network_mask{};
  std::uint32_t metric{};
  std::uint32_t forwarding_address{};
  std::uint32_t route_tag{};
  bool type_two_metric{};
  bool nssa{};
};

struct VersionThreeRouterView {
  std::span<const std::uint8_t> links{};
  std::uint32_t options{};
  std::uint8_t flags{};
};

struct VersionThreeRouterLink {
  std::uint32_t interface_id{};
  std::uint32_t neighbor_interface_id{};
  std::uint32_t neighbor_router_id{};
  std::uint16_t metric{};
  RouterLinkType type{RouterLinkType::point_to_point};
};

struct VersionThreeNetworkView {
  std::span<const std::uint8_t> attached_routers{};
  std::uint32_t options{};
};

struct VersionThreePrefix {
  std::span<const std::uint8_t> significant_octets{};
  std::uint16_t metric{};
  std::uint8_t length{};
  std::uint8_t options{};
  std::size_t next_offset{};
};

struct VersionThreeInterAreaPrefixView {
  VersionThreePrefix prefix;
  std::uint32_t metric{};
};

struct VersionThreeInterAreaRouterView {
  std::uint32_t destination_router_id{};
  std::uint32_t metric{};
  std::uint32_t options{};
};

struct VersionThreeExternalView {
  VersionThreePrefix prefix;
  std::span<const std::uint8_t> forwarding_address{};
  std::optional<std::uint32_t> route_tag;
  std::optional<std::uint32_t> referenced_link_state_id;
  std::uint32_t metric{};
  bool type_two_metric{};
  bool nssa{};
};

struct VersionThreeLinkView {
  std::span<const std::uint8_t> prefixes{};
  ip::Ipv6 link_local_address{};
  std::uint32_t options{};
  std::uint32_t prefix_count{};
  std::uint8_t router_priority{};
};

struct VersionThreeIntraAreaPrefixView {
  std::span<const std::uint8_t> prefixes{};
  std::uint32_t referenced_link_state_id{};
  std::uint32_t referenced_advertising_router{};
  std::uint16_t prefix_count{};
  std::uint16_t referenced_lsa_type{};
};

struct TlvView {
  // value excludes four-octet alignment padding. next_offset points at the
  // following TLV and can therefore be used to walk unknown extensions
  // without copying or interpreting their bytes.
  std::span<const std::uint8_t> value{};
  std::uint16_t type{};
  std::size_t next_offset{};
};

enum class GraceRestartReason : std::uint8_t {
  unknown = 0U,
  software_restart = 1U,
  software_reload = 2U,
  redundant_control_processor = 3U
};

struct GraceLsaView {
  std::optional<std::uint32_t> interface_address;
  std::uint32_t grace_period_seconds{};
  GraceRestartReason reason{GraceRestartReason::unknown};
};

struct RouterInformationView {
  // The first four octets are the registry-defined base capability bitmap.
  // A longer standards-valid TLV remains visible so future registered bits
  // can be inspected without changing the generic RI codec.
  std::span<const std::uint8_t> informational_capabilities{};
  std::span<const std::uint8_t> functional_capabilities{};
};

[[nodiscard]] std::optional<VersionTwoRouterView>
parse_version_two_router(std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionTwoRouterLink>
version_two_router_link(const VersionTwoRouterView &view,
                        std::size_t offset) noexcept;

[[nodiscard]] std::optional<VersionTwoNetworkView>
parse_version_two_network(std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionTwoSummaryView>
parse_version_two_summary(std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionTwoExternalView>
parse_version_two_external(std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<std::uint32_t>
attached_router(const VersionTwoNetworkView &view,
                std::size_t index) noexcept;

[[nodiscard]] std::optional<VersionThreeRouterView>
parse_version_three_router(std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionThreeRouterLink>
version_three_router_link(const VersionThreeRouterView &view,
                          std::size_t index) noexcept;

[[nodiscard]] std::optional<VersionThreeNetworkView>
parse_version_three_network(std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionThreeInterAreaPrefixView>
parse_version_three_inter_area_prefix(
    std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionThreeInterAreaRouterView>
parse_version_three_inter_area_router(
    std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionThreeExternalView>
parse_version_three_external(std::span<const std::uint8_t> encoded,
                             bool ipv4_address_family) noexcept;
[[nodiscard]] std::optional<VersionThreeLinkView>
parse_version_three_link(std::span<const std::uint8_t> encoded,
                         bool ipv4_address_family = false) noexcept;
[[nodiscard]] std::optional<std::uint32_t>
attached_router(const VersionThreeNetworkView &view,
                std::size_t index) noexcept;

[[nodiscard]] std::optional<VersionThreeIntraAreaPrefixView>
parse_version_three_intra_area_prefix(
    std::span<const std::uint8_t> encoded) noexcept;
[[nodiscard]] std::optional<VersionThreePrefix>
version_three_prefix(std::span<const std::uint8_t> prefixes,
                     std::size_t offset, bool metric_present,
                     bool reserved_must_be_zero = true) noexcept;

// expand_prefix writes the significant wire octets into a canonical 128-bit
// value. Padding and host bits are verified by the parser, so the result is a
// stable key suitable for route calculation.
[[nodiscard]] std::optional<ip::Ipv6>
expand_prefix(const VersionThreePrefix &prefix) noexcept;

// RFC 3630 section 2.3.2 alignment is shared by Grace and Router Information
// LSAs. Unknown TLVs remain visible to their owning extension but cannot make
// the bounded walker step beyond the validated LSA body.
[[nodiscard]] std::optional<TlvView>
tlv(std::span<const std::uint8_t> body, std::size_t offset) noexcept;

// RFC 3623 Appendix A and RFC 5187 section 2 define the same required TLVs
// with version-specific LSA identities. Interface-address presence is checked
// later against the receiving network type because OSPFv3 omits it entirely.
[[nodiscard]] std::optional<GraceLsaView>
parse_grace_lsa(std::span<const std::uint8_t> encoded,
                std::uint8_t version) noexcept;

// RFC 7770 permits unknown TLVs and multiple RI instances. This parser checks
// only the wire identity and structural rules common to every instance. It
// enforces the ordering rule for the two base capability TLVs when present in
// Instance 0 and leaves extension interpretation to its owning subsystem.
[[nodiscard]] std::optional<RouterInformationView>
parse_router_information_lsa(std::span<const std::uint8_t> encoded,
                             std::uint8_t version) noexcept;

} // namespace router::packet::ospf::lsa
