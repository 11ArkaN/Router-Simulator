// Allocation-free OSPFv2 and OSPFv3 wire-format contracts. This module owns
// packet framing, checksum validation and bounded iteration over packet
// records. It does not own neighbors, interfaces, LSDB entries or timers.
// Those mutable objects belong to a control-plane OSPF process and may retain
// copied values only after this parser has validated their complete envelope.

#pragma once

#include "router/ip_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::ospf {

// RFC 2328 Appendix A.2 and RFC 5340 Appendix A.2 assign these wire bits.
// Keeping their semantic names here prevents configuration compilers from
// embedding unexplained numeric masks.
inline constexpr std::uint32_t option_external_routing_capability = 0x02U;
inline constexpr std::uint32_t option_nssa_capability = 0x08U;
// RFC 5250 section 3 assigns the O-bit in the OSPFv2 Options octet. Every
// production OSPFv2 instance advertises it because the process can store,
// flood and originate opaque LSAs.
inline constexpr std::uint32_t option_opaque_capability = 0x40U;
inline constexpr std::uint32_t option_ipv6_forwarding = 0x01U;
inline constexpr std::uint32_t option_ospfv3_router = 0x10U;
// RFC 5838 section 2.2 assigns the AF bit in the 24-bit OSPFv3 Options
// field. Every non-base address-family instance advertises it in Hello, DD
// and LSA options so a legacy peer cannot form an adjacency and silently
// black-hole the non-IPv6 address family.
inline constexpr std::uint32_t option_address_family = 0x100U;
// RFC 7166 and RFC 5613 assign adjacent bits in the 24-bit OSPFv3 Options
// field. They are decoded here because trailer placement depends on whether an
// LLS block follows the OSPF Packet Length.
inline constexpr std::uint32_t option_link_local_signaling = 0x200U;
inline constexpr std::uint32_t option_authentication_trailer = 0x400U;
// RFC 5838 section 2.7 allocates bit 3 only in an OSPFv3 Database
// Description packet. It says that the advertised AF MTU differs from the
// IPv6 transport MTU. OSPFv2 must continue treating the same bit as invalid.
inline constexpr std::uint8_t dd_ipv6_mtu_separate = 0x08U;

// IANA assigns IP protocol number 89 to both OSPFv2 and OSPFv3. Keeping the
// number at the codec boundary prevents forwarding and protocol shards from
// acquiring unrelated copies of a wire constant.
inline constexpr std::uint8_t ip_protocol = 89U;
inline constexpr std::uint8_t version_two = 2U;
inline constexpr std::uint8_t version_three = 3U;
inline constexpr std::size_t version_two_header_octets = 24U;
inline constexpr std::size_t version_three_header_octets = 16U;
inline constexpr std::size_t lsa_header_octets = 20U;
inline constexpr ip::Ipv4 all_spf_routers_v4{{224U, 0U, 0U, 5U}};
inline constexpr ip::Ipv4 all_dr_routers_v4{{224U, 0U, 0U, 6U}};
inline constexpr ip::Ipv6 all_spf_routers_v6{{
    0xffU, 0x02U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 5U}};
inline constexpr ip::Ipv6 all_dr_routers_v6{{
    0xffU, 0x02U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 6U}};
inline constexpr std::array<std::uint8_t, 6U> all_spf_routers_mac_v4{{
    0x01U, 0x00U, 0x5eU, 0x00U, 0x00U, 0x05U}};
inline constexpr std::array<std::uint8_t, 6U> all_dr_routers_mac_v4{{
    0x01U, 0x00U, 0x5eU, 0x00U, 0x00U, 0x06U}};
inline constexpr std::array<std::uint8_t, 6U> all_spf_routers_mac_v6{{
    0x33U, 0x33U, 0x00U, 0x00U, 0x00U, 0x05U}};
inline constexpr std::array<std::uint8_t, 6U> all_dr_routers_mac_v6{{
    0x33U, 0x33U, 0x00U, 0x00U, 0x00U, 0x06U}};

enum class PacketType : std::uint8_t {
  hello = 1U,
  database_description = 2U,
  link_state_request = 3U,
  link_state_update = 4U,
  link_state_acknowledgment = 5U
};

enum class AuthenticationType : std::uint16_t {
  none = 0U,
  simple_password = 1U,
  cryptographic = 2U
};

struct PacketView {
  // payload aliases the immutable input packet. A view must not outlive the
  // packet-pool handle whose bytes were parsed.
  std::span<const std::uint8_t> packet{};
  std::span<const std::uint8_t> payload{};
  // RFC 2328 cryptographic authentication and RFC 7166 both append bytes
  // outside the protocol Packet Length. The codec exposes that suffix
  // separately so body parsers cannot consume a digest as protocol records.
  std::span<const std::uint8_t> authentication_data{};
  std::span<const std::uint8_t> authentication_trailer{};
  std::span<const std::uint8_t> link_local_signaling_data{};
  std::uint32_t router_id{};
  std::uint32_t area_id{};
  std::uint16_t checksum{};
  std::uint16_t authentication_type{};
  std::array<std::uint8_t, 8U> authentication{};
  PacketType type{PacketType::hello};
  std::uint8_t version{};
  std::uint8_t instance_id{};
};

struct HelloView {
  // OSPFv2 carries the subnet mask. OSPFv3 carries the sending interface ID.
  // Both are retained because treating them as one field would hide the
  // per-subnet versus per-link protocol distinction.
  std::uint32_t network_mask{};
  std::uint32_t interface_id{};
  std::uint32_t designated_router{};
  std::uint32_t backup_designated_router{};
  std::span<const std::uint8_t> neighbors{};
  std::uint32_t dead_interval_seconds{};
  std::uint32_t options{};
  std::uint16_t hello_interval_seconds{};
  std::uint8_t router_priority{};
  std::uint8_t version{};
};

struct DatabaseDescriptionView {
  std::span<const std::uint8_t> lsa_headers{};
  std::uint32_t options{};
  std::uint32_t sequence_number{};
  std::uint16_t interface_mtu{};
  bool init{};
  bool more{};
  bool master{};
  bool ipv6_mtu_separate{};
  std::uint8_t version{};
};

struct LinkStateRequestView {
  // Entries are always twelve octets. request_entry copies one entry after
  // checking the index, so no unaligned pointer escapes into control state.
  std::span<const std::uint8_t> entries{};
  std::uint8_t version{};
};

struct LinkStateRequestEntry {
  std::uint32_t link_state_type{};
  std::uint32_t link_state_id{};
  std::uint32_t advertising_router{};

  // Value equality is used by packet fixtures and later by the neighbor
  // owner's request-list reconciliation. It compares only the three fields
  // that identify one requested LSA and retains no storage identity.
  bool operator==(const LinkStateRequestEntry &) const = default;
};

struct LinkStateUpdateView {
  // lsas contains the encoded advertisements after the four-octet count.
  // The parser walks every declared LSA before returning this view, preventing
  // an owner from accepting a valid prefix followed by truncated bytes.
  std::span<const std::uint8_t> lsas{};
  std::uint32_t advertisement_count{};
  std::uint8_t version{};
};

struct LinkStateAcknowledgmentView {
  std::span<const std::uint8_t> lsa_headers{};
  std::uint8_t version{};
};

struct LsaHeaderView {
  std::uint32_t link_state_id{};
  std::uint32_t advertising_router{};
  std::int32_t sequence_number{};
  std::uint16_t age_seconds{};
  std::uint16_t type{};
  std::uint16_t checksum{};
  std::uint16_t length{};
  std::uint32_t options{};
  std::uint8_t version{};
};

struct EncodedLsa {
  // The writer copies this complete immutable LSA before returning. Callers
  // may therefore point at separate LSDB records without coalescing them into
  // a synthetic packet buffer first.
  std::span<const std::uint8_t> bytes{};
};

// parse_packet validates the common header, exact Packet Length, packet type,
// version-specific reserved fields and the OSPFv2 authentication type range.
// Authentication digest verification is deliberately separate because a
// control owner must first select the configured key for the ingress
// interface. OSPFv3 checksum verification additionally needs the IPv6 source
// and destination pseudo-header supplied to verify_version_three_checksum.
[[nodiscard]] std::optional<PacketView>
parse_packet(std::span<const std::uint8_t> packet) noexcept;

[[nodiscard]] bool
verify_version_two_checksum(const PacketView &packet) noexcept;
[[nodiscard]] bool verify_version_three_checksum(
    const PacketView &packet, const ip::Ipv6 &source,
    const ip::Ipv6 &destination) noexcept;

// Encoders write a complete OSPF packet into caller-owned storage and return
// only the written prefix. Failure leaves no packet that a caller can enqueue.
// OSPFv2 cryptographic digests are appended by the authentication owner after
// it selects a key and sequence number; this common encoder handles null and
// simple-password packet checksums.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_two(std::span<std::uint8_t> output, PacketType type,
                   std::uint32_t router_id, std::uint32_t area_id,
                   AuthenticationType authentication_type,
                   std::span<const std::uint8_t, 8U> authentication,
                   std::span<const std::uint8_t> payload) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_version_three(std::span<std::uint8_t> output, PacketType type,
                     std::uint32_t router_id, std::uint32_t area_id,
                     std::uint8_t instance_id, const ip::Ipv6 &source,
                     const ip::Ipv6 &destination,
                     std::span<const std::uint8_t> payload) noexcept;

// Packet-body writers implement the version-specific fixed fields and exact
// record packing from RFC 2328 Appendix A.3 and RFC 5340 Appendix A.3. The
// common packet encoders above add the authenticated OSPF envelope afterward.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_database_description_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::uint16_t interface_mtu, std::uint32_t options,
    std::uint32_t sequence_number, bool init, bool more, bool master,
    std::span<const std::uint8_t> lsa_headers,
    bool ipv6_mtu_separate = false) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_link_state_request_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::span<const LinkStateRequestEntry> entries) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_link_state_update_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::span<const EncodedLsa> advertisements) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_link_state_acknowledgment_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::span<const std::uint8_t> lsa_headers) noexcept;

[[nodiscard]] std::optional<HelloView>
parse_hello(const PacketView &packet) noexcept;
[[nodiscard]] std::optional<DatabaseDescriptionView>
parse_database_description(const PacketView &packet) noexcept;
[[nodiscard]] std::optional<LinkStateRequestView>
parse_link_state_request(const PacketView &packet) noexcept;
[[nodiscard]] std::optional<LinkStateUpdateView>
parse_link_state_update(const PacketView &packet) noexcept;
[[nodiscard]] std::optional<LinkStateAcknowledgmentView>
parse_link_state_acknowledgment(const PacketView &packet) noexcept;

[[nodiscard]] std::optional<std::uint32_t>
hello_neighbor(const HelloView &hello, std::size_t index) noexcept;
[[nodiscard]] std::optional<LinkStateRequestEntry>
request_entry(const LinkStateRequestView &request,
              std::size_t index) noexcept;
[[nodiscard]] std::optional<LsaHeaderView>
lsa_header(std::span<const std::uint8_t> bytes, std::uint8_t version) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
update_lsa(const LinkStateUpdateView &update, std::size_t index) noexcept;
[[nodiscard]] std::optional<LsaHeaderView>
acknowledgment_header(const LinkStateAcknowledgmentView &acknowledgment,
                      std::size_t index) noexcept;

} // namespace router::packet::ospf
