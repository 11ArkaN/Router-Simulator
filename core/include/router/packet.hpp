// Byte-level Ethernet, ARP, IPv4, IPv6 and ICMP codecs. All functions own or
// return fixed-capacity values, perform no packet-path allocation and use only
// wire bytes as their protocol boundary. Routing and adjacency state belong to
// higher modules and are never hidden inside these parsing helpers.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/ip_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet {

inline constexpr std::uint16_t ethernet_header_octets = 14;
inline constexpr std::uint16_t ethernet_type_ipv4 = 0x0800;
inline constexpr std::uint16_t ethernet_type_arp = 0x0806;
inline constexpr std::uint16_t ethernet_type_ipv6 = 0x86dd;
// IEEE 802.1Q assigns 0x8100 to customer VLAN tags. IEEE 802.1ad provider
// bridging uses 0x88a8 for the outer service tag. The codec accepts at most the
// two tags needed by the SR OS null, dot1q and qinq SAP profiles; a third tag is
// payload from this parser's perspective and cannot accidentally select a SAP.
inline constexpr std::uint16_t ethernet_type_customer_vlan = 0x8100;
inline constexpr std::uint16_t ethernet_type_service_vlan = 0x88a8;
inline constexpr std::uint8_t maximum_service_vlan_tags = 2;
inline constexpr std::uint8_t vlan_tag_octets = 4;
// Protocol constants live at the codec boundary so forwarding, ND and future
// transport modules cannot acquire independent numeric copies. The SR OS port
// MTU profile includes the untagged Ethernet header, while RFC 8200 expresses
// the IPv6 minimum in network-layer octets.
inline constexpr std::uint16_t ipv6_header_octets = 40;
// RFC 791 requires every IPv4 destination to accept 576 octets and every
// internet module to forward or reassemble 68 octets. RFC 1191 uses the latter
// as the absolute Path MTU floor.
inline constexpr std::uint16_t ipv4_minimum_reassembly_octets = 68;
inline constexpr std::uint16_t ipv6_minimum_link_mtu = 1280;
inline constexpr std::uint16_t ipv6_minimum_ethernet_mtu =
    ethernet_header_octets + ipv6_minimum_link_mtu;
inline constexpr std::uint8_t ipv6_next_header_hop_by_hop = 0;
inline constexpr std::uint8_t ipv6_next_header_routing = 43;
inline constexpr std::uint8_t ipv6_next_header_fragment = 44;
inline constexpr std::uint8_t ipv6_next_header_tcp = 6;
inline constexpr std::uint8_t ipv6_next_header_udp = 17;
inline constexpr std::uint8_t ipv6_next_header_icmpv6 = 58;
inline constexpr std::uint8_t ipv6_next_header_esp = 50;
inline constexpr std::uint8_t ipv6_next_header_authentication = 51;
inline constexpr std::uint8_t ipv6_next_header_none = 59;
inline constexpr std::uint8_t ipv6_next_header_destination_options = 60;
inline constexpr std::uint8_t ipv6_fragment_header_octets = 8;
inline constexpr std::uint8_t ipv6_fragment_offset_unit_octets = 8;
inline constexpr std::uint16_t ethernet_minimum_without_fcs = 60;
// ICMPv6 assignments come from RFC 4443 and RFC 4861. Keeping them at the
// packet boundary prevents forwarding and control protocols from duplicating
// wire numbers that could accidentally diverge.
inline constexpr std::uint8_t icmpv6_destination_unreachable_type = 1;
inline constexpr std::uint8_t icmpv6_packet_too_big_type = 2;
inline constexpr std::uint8_t icmpv6_time_exceeded_type = 3;
inline constexpr std::uint8_t icmpv6_parameter_problem_type = 4;
inline constexpr std::uint8_t icmpv6_echo_request_type = 128;
inline constexpr std::uint8_t icmpv6_echo_reply_type = 129;
inline constexpr std::uint8_t icmpv6_informational_type_boundary = 128;
inline constexpr std::uint8_t icmpv6_destination_no_route_code = 0;
inline constexpr std::uint8_t icmpv6_destination_port_unreachable_code = 4;
inline constexpr std::uint8_t icmpv6_parameter_bad_header_code = 0;
inline constexpr std::uint8_t icmpv6_parameter_unknown_next_header_code = 1;
inline constexpr std::uint8_t icmpv6_parameter_unknown_option_code = 2;
inline constexpr std::size_t icmp_echo_header_octets = 8;
inline constexpr std::uint16_t minimum_network_ip_mtu =
    device_catalog::minimum_network_mtu - ethernet_header_octets;
inline constexpr std::uint16_t maximum_network_ip_mtu =
    device_catalog::maximum_network_mtu - ethernet_header_octets;
// The fixed envelope must admit every network MTU exposed by the release
// catalog. FCS is serialized by the link and omitted from the stored bytes.
// This keeps jumbo forwarding, capture and checkpoint storage on one bound.
inline constexpr std::size_t maximum_frame_octets =
    device_catalog::maximum_network_mtu;
// The ordinary IPv6 Payload Length field admits 65535 octets. A reassembled
// network packet may therefore be larger than every physical frame profile,
// even though each constituent fragment still fits Frame. Keeping this bound
// separate prevents transport code from confusing a link MTU with the IPv6
// datagram limit. RFC 2675 jumbograms are a distinct format and are not
// included in this ordinary-packet envelope.
inline constexpr std::size_t maximum_ipv6_payload_octets = 65535U;
inline constexpr std::size_t maximum_ethernet_ipv6_datagram_octets =
    ethernet_header_octets + ipv6_header_octets +
    maximum_ipv6_payload_octets;
// IPv4 Total Length includes its header and cannot exceed 65,535. The
// Ethernet prefix is outside that field but remains part of the source-owned
// byte image passed to the fragment streamer.
inline constexpr std::size_t maximum_ipv4_datagram_octets = 65535U;
inline constexpr std::size_t maximum_ethernet_ipv4_datagram_octets =
    ethernet_header_octets + maximum_ipv4_datagram_octets;

using Mac = std::array<std::uint8_t, 6>;
using Ipv4 = ip::Ipv4;
using Ipv6 = ip::Ipv6;

struct Frame {
  // The fixed Ethernet envelope avoids one heap allocation per frame. length
  // is the only portion placed on the wire and excludes the Ethernet FCS.
  // The envelope admits untagged, dot1q and QinQ frames including jumbo
  // payloads admitted by the selected SR OS port profile. Service ingress
  // strips tags only after exact SAP classification; physical capture keeps
  // the original tagged byte image.
  // Encoders write every byte below length, including Ethernet padding. The
  // remainder is intentionally not zero-initialized in stack Builders because
  // clearing a jumbo envelope for a 60 or 98 byte packet would dominate encoding.
  // Consumers are contractually restricted to view(), size() and indices below
  // length. PacketPool copies fixed slots for stable ownership after encoding.
  std::array<std::uint8_t, maximum_frame_octets> bytes;
  std::uint16_t length{};

  [[nodiscard]] std::size_t size() const noexcept { return length; }
  [[nodiscard]] std::uint8_t operator[](std::size_t index) const noexcept {
    return bytes[index];
  }
  [[nodiscard]] std::span<const std::uint8_t> view() const noexcept {
    return {bytes.data(), length};
  }
};

struct ArpView {
  // Views copy only semantic address fields. They never expose mutable pointers
  // into packet pool storage across component boundaries.
  std::uint16_t operation{};
  Mac sender_mac{};
  Ipv4 sender_ip{};
  Mac target_mac{};
  Ipv4 target_ip{};
};

struct Ipv4View {
  // This milestone returns only fields needed by forwarding and validation.
  // Additional protocol modules can extend the view without changing Frame.
  Ipv4 source{};
  Ipv4 destination{};
  std::uint8_t ttl{};
  std::uint8_t protocol{};
  std::uint16_t total_length{};
  std::uint16_t identification{};
  std::uint16_t fragment_offset{};
  std::uint8_t header_length{};
  bool dont_fragment{};
  bool more_fragments{};
};

struct Ipv6FragmentView {
  // RFC 8200 encodes the fragment offset in eight-octet units. Identification
  // belongs to the source and destination tuple and is required by the future
  // endpoint reassembly owner. Routers inspect but never modify these fields.
  std::uint32_t identification{};
  std::uint16_t offset{};
  bool more_fragments{};
};

struct Ipv6View {
  // payload_length covers bytes following the fixed forty-octet header. The
  // upper-layer offset points into Frame and follows every validated extension
  // header. It is intentionally an offset, not a borrowed pointer, so this
  // value can cross a bounded message ring without retaining packet storage.
  Ipv6 source{};
  Ipv6 destination{};
  std::uint32_t flow_label{};
  std::uint16_t payload_length{};
  std::uint16_t upper_layer_offset{};
  // The offset of the byte whose Next Header value names upper_layer_protocol
  // lets a source insert, and a destination remove, a Fragment Header without
  // guessing whether the predecessor was the fixed header or an extension.
  std::uint16_t upper_layer_next_header_offset{};
  std::uint16_t fragment_header_offset{};
  std::uint16_t fragment_previous_next_header_offset{};
  std::uint8_t traffic_class{};
  std::uint8_t next_header{};
  std::uint8_t upper_layer_protocol{};
  std::uint8_t hop_limit{};
  std::optional<Ipv6FragmentView> fragment{};
  // AH identifies an authenticated payload whose inner Next Header cannot be
  // trusted before an IPsec SA verifies it. Parsing may locate that payload
  // for transit forwarding, but local protocol dispatch keeps it opaque.
  bool authentication_header_present{};
};

struct FragmentBatch {
  // RFC 791 requires every non-final payload to end on an eight-octet boundary.
  // Compute the worst case from the generated MTU limits so expanding jumbo
  // support cannot silently retain an obsolete four-fragment ceiling.
  static constexpr std::size_t ipv4_header_octets = 20;
  static constexpr std::size_t minimum_fragment_payload =
      ((minimum_network_ip_mtu - ipv4_header_octets) / 8U) * 8U;
  static constexpr std::size_t maximum_fragment_count =
      (maximum_network_ip_mtu - ipv4_header_octets +
       minimum_fragment_payload - 1U) /
      minimum_fragment_payload;
  std::array<Frame, maximum_fragment_count> frames{};
  std::uint8_t count{};
};

struct EthernetView {
  Mac destination{};
  Mac source{};
  struct VlanTag {
    // PCP and DEI are preserved even though initial SAP selection keys only on
    // VID. Discarding them during ingress stripping would make an egress
    // round-trip silently rewrite priority and drop-eligibility semantics.
    std::uint16_t tpid{};
    std::uint16_t vlan_identifier{};
    std::uint8_t priority_code_point{};
    bool drop_eligible{};
    bool operator==(const VlanTag &) const = default;
  };
  std::array<VlanTag, maximum_service_vlan_tags> vlan_tags{};
  std::uint16_t ether_type{};
  std::uint16_t payload_offset{ethernet_header_octets};
  std::uint8_t vlan_tag_count{};
};

struct IcmpView {
  std::uint8_t type{};
  std::uint8_t code{};
  // Error messages interpret these four octets as a type-specific parameter.
  // Echo messages continue to expose the same bytes as identifier and
  // sequence, avoiding protocol-specific reparsing at each consumer.
  std::uint32_t parameter{};
  std::uint16_t identifier{};
  std::uint16_t sequence{};
  std::span<const std::uint8_t> data{};
};

struct Icmpv6View {
  // Echo fields are meaningful only for type 128 and 129. Returning them as
  // zero for other messages keeps the fixed view usable when error and ND
  // decoders are added without allocating a variant in the packet hot path.
  std::uint8_t type{};
  std::uint8_t code{};
  std::uint32_t parameter{};
  std::uint16_t identifier{};
  std::uint16_t sequence{};
  std::span<const std::uint8_t> data{};
};

std::uint16_t checksum(std::span<const std::uint8_t> bytes) noexcept;
// ICMPv6, UDP and TCP include an IPv6 pseudo-header in their checksum. The
// caller supplies exactly the upper-layer bytes and protocol number, allowing
// one implementation to serve all three protocols without fabricating a
// temporary forty-octet header.
std::uint16_t ipv6_upper_layer_checksum(
    Ipv6 source, Ipv6 destination, std::uint8_t next_header,
    std::span<const std::uint8_t> payload) noexcept;
// IPv4 UDP and TCP share the 96-bit pseudo-header. The caller must supply an
// upper-layer span no longer than the enclosing IPv4 Total Length permits.
std::uint16_t ipv4_upper_layer_checksum(
    Ipv4 source, Ipv4 destination, std::uint8_t protocol,
    std::span<const std::uint8_t> payload) noexcept;
// Writes one complete unfragmented Ethernet and IPv6 datagram into caller
// storage. `payload` may span the entire ordinary 16-bit IPv6 Payload Length
// domain, so output is a byte span rather than Frame. The source endpoint may
// subsequently pass this exact image to fragment_ipv6_datagram().
[[nodiscard]] std::optional<std::size_t> encode_ipv6_ethernet_datagram(
    std::span<std::uint8_t> output, Mac source_mac, Mac destination_mac,
    Ipv6 source, Ipv6 destination, std::uint8_t next_header,
    std::uint8_t hop_limit, std::span<const std::uint8_t> payload,
    std::uint8_t traffic_class = 0U,
    std::uint32_t flow_label = 0U) noexcept;
// Writes one complete source IPv4 datagram into caller-owned storage. The
// returned image can exceed Frame because only its MTU-sized fragments cross
// a port queue. IPv4 options are not generated by this overload, so the header
// is exactly 20 octets and the maximum upper-layer payload is 65,515 octets.
[[nodiscard]] std::optional<std::size_t> encode_ipv4_ethernet_datagram(
    std::span<std::uint8_t> output, Mac source_mac, Mac destination_mac,
    Ipv4 source, Ipv4 destination, std::uint8_t protocol,
    std::uint8_t ttl, std::uint16_t identification,
    std::span<const std::uint8_t> payload,
    bool dont_fragment = false) noexcept;
// Encoders return complete Ethernet frames so every inter-device exchange goes
// through a queue and LinkDirection instead of passing protocol objects.
Frame arp_request(Mac source_mac, Ipv4 source_ip, Ipv4 target_ip);
Frame arp_reply(Mac source_mac, Ipv4 source_ip, Mac target_mac, Ipv4 target_ip);
Frame icmp_echo(Mac source_mac, Mac target_mac, Ipv4 source_ip, Ipv4 target_ip,
                bool reply, std::uint16_t sequence,
                std::uint8_t ttl = device_catalog::default_ip_hop_limit,
                std::size_t payload_octets = 56,
                bool dont_fragment = false);
// Owner-provided encoders avoid returning a 9 KiB jumbo-capable value through
// an intermediate object for ordinary 60 to 98 byte control packets. They
// write exactly result.length bytes and perform no allocation.
void arp_request_into(Frame &result, Mac source_mac, Ipv4 source_ip,
                      Ipv4 target_ip) noexcept;
void arp_reply_into(Frame &result, Mac source_mac, Ipv4 source_ip,
                    Mac target_mac, Ipv4 target_ip) noexcept;
void icmp_echo_into(Frame &result, Mac source_mac, Mac target_mac,
                    Ipv4 source_ip, Ipv4 target_ip, bool reply,
                    std::uint16_t sequence,
                    std::uint8_t ttl = device_catalog::default_ip_hop_limit,
                    std::size_t payload_octets = 56,
                    bool dont_fragment = false) noexcept;
Frame icmpv6_echo(Mac source_mac, Mac target_mac, Ipv6 source_ip,
                  Ipv6 target_ip, bool reply, std::uint16_t sequence,
                  std::uint8_t hop_limit = device_catalog::default_ip_hop_limit,
                  std::size_t payload_octets = 56);
void icmpv6_echo_into(Frame &result, Mac source_mac, Mac target_mac,
                      Ipv6 source_ip, Ipv6 target_ip, bool reply,
                      std::uint16_t sequence,
                      std::uint8_t hop_limit = device_catalog::default_ip_hop_limit,
                      std::size_t payload_octets = 56) noexcept;
// Control-protocol encoders supply bytes following the ICMPv6 checksum. This
// shared helper owns the IPv6 envelope and pseudo-header checksum, preventing
// ND, MLD and future error-message modules from implementing subtly different
// checksum or payload-length rules.
void icmpv6_message_into(Frame &result, Mac source_mac, Mac target_mac,
                         Ipv6 source_ip, Ipv6 target_ip, std::uint8_t type,
                         std::uint8_t code,
                         std::span<const std::uint8_t> body,
                         std::uint8_t hop_limit) noexcept;
// Frame stays trivially copyable for shared SPSC storage. Hot owners must use
// this bounded copy when the source length is known, avoiding an unnecessary
// copy of the unused jumbo tail.
void copy_frame(Frame &destination, const Frame &source) noexcept;
std::optional<Frame> icmp_echo_reply(const Frame &request, Mac source_mac,
                                     Mac destination_mac) noexcept;
std::optional<Frame> icmpv6_echo_reply(const Frame &request, Mac source_mac,
                                       Mac destination_mac) noexcept;
std::optional<Frame> icmpv6_time_exceeded(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip) noexcept;
std::optional<Frame> icmpv6_packet_too_big(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip, std::uint32_t mtu) noexcept;
std::optional<Frame> icmpv6_destination_unreachable(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip, std::uint8_t code) noexcept;
// A reassembled local datagram can be larger than Frame. This overload quotes
// directly from the complete Ethernet plus IPv6 byte image while the emitted
// ICMPv6 error remains bounded by the IPv6 minimum MTU.
std::optional<Frame> icmpv6_destination_unreachable(
    std::span<const std::uint8_t> original, Mac source_mac,
    Mac destination_mac, Ipv6 source_ip, Ipv6 destination_ip,
    std::uint8_t code) noexcept;
std::optional<Frame> icmpv6_parameter_problem(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip, std::uint8_t code, std::uint32_t pointer) noexcept;
std::optional<Frame> icmp_time_exceeded(const Frame &original, Mac source_mac,
                                        Mac destination_mac, Ipv4 source_ip,
                                        Ipv4 destination_ip) noexcept;
std::optional<Frame> icmp_reassembly_time_exceeded(
    const Frame &first_fragment, Mac source_mac, Mac destination_mac,
    Ipv4 source_ip, Ipv4 destination_ip) noexcept;
// A forwarding router uses code 0 when no route, including no default route,
// exists for the destination. The invoking datagram is quoted from received
// wire bytes and the caller supplies the independently selected return path.
std::optional<Frame> icmp_network_unreachable(
    const Frame &original, Mac source_mac, Mac destination_mac,
    Ipv4 source_ip, Ipv4 destination_ip) noexcept;
// A local IPv4 endpoint uses code 2 when no transport owner implements the
// protocol number. Span input preserves the complete reassembled datagram for
// quotation without narrowing it to one physical Frame slot.
std::optional<Frame> icmp_protocol_unreachable(
    std::span<const std::uint8_t> original, Mac source_mac,
    Mac destination_mac, Ipv4 source_ip, Ipv4 destination_ip) noexcept;
std::optional<Frame> icmp_port_unreachable(
    std::span<const std::uint8_t> original, Mac source_mac,
    Mac destination_mac, Ipv4 source_ip, Ipv4 destination_ip) noexcept;
std::optional<Frame>
icmp_fragmentation_needed(const Frame &original, Mac source_mac,
                          Mac destination_mac, Ipv4 source_ip,
                          Ipv4 destination_ip, std::uint16_t mtu) noexcept;
// RFC 1812 permits only Host Redirect code 1 for the common non-TOS path.
// gateway identifies the better on-link next hop while original supplies the
// required IP header and first 64 data bits without consulting topology.
std::optional<Frame> icmp_host_redirect(
    const Frame &original, Mac source_mac, Mac destination_mac,
    Ipv4 source_ip, Ipv4 destination_ip, Ipv4 gateway) noexcept;
// LSRR and SSRR suppress Redirect generation. The parser walks the complete
// validated option area rather than looking only at a fixed early byte.
[[nodiscard]] bool ipv4_has_source_route(const Frame &frame,
                                         const Ipv4View &ipv4) noexcept;
std::optional<EthernetView>
parse_ethernet(std::span<const std::uint8_t> packet) noexcept;
std::optional<EthernetView> parse_ethernet(const Frame &frame) noexcept;
// Tag insertion and removal operate in place because the packet pool owns the
// complete frame slot. They are used only at the SAP boundary. A failed edit
// leaves the original bytes and length unchanged, which lets queue admission
// report MTU or capacity failure without publishing a partial wire frame.
[[nodiscard]] bool insert_vlan_tags(
    Frame &frame,
    std::span<const EthernetView::VlanTag> tags) noexcept;
[[nodiscard]] bool strip_vlan_tags(Frame &frame) noexcept;
// Untagged endpoint and routed-port receive filters accept their own unicast
// address and Ethernet broadcast. Promiscuous capture occurs at a separate tap.
[[nodiscard]] bool ethernet_for_local(Mac destination, Mac local) noexcept;
std::optional<ArpView> parse_arp(const Frame &frame) noexcept;
// Reassembled and source-owned IPv4 datagrams may exceed Frame. Both overloads
// validate the same version, IHL, Total Length and checksum contract.
std::optional<Ipv4View>
parse_ipv4(std::span<const std::uint8_t> packet) noexcept;
std::optional<Ipv4View> parse_ipv4(const Frame &frame) noexcept;
// ICMP errors quote a raw IPv4 header and at least eight following octets, not
// an Ethernet frame or necessarily the complete original Total Length. This
// parser validates that limited shape without weakening ordinary parse_ipv4.
std::optional<Ipv4View>
parse_ipv4_quote(std::span<const std::uint8_t> quote) noexcept;
// ICMP checksum covers the complete reassembled datagram. The span overload is
// therefore the authoritative parser; Frame delegates without copying.
std::optional<IcmpView>
parse_icmp(std::span<const std::uint8_t> packet) noexcept;
std::optional<IcmpView> parse_icmp(const Frame &frame) noexcept;
// The span overload serves destination reassembly, whose complete IPv6 packet
// can legitimately exceed one Frame. The Frame overload remains the hot link
// path and delegates without copying. Both inputs start at an Ethernet header.
std::optional<Ipv6View>
parse_ipv6(std::span<const std::uint8_t> packet) noexcept;
std::optional<Ipv6View> parse_ipv6(const Frame &frame) noexcept;
// ICMPv6 errors quote a raw IPv6 header followed by as much of the invoking
// packet as fits, without an Ethernet envelope. The returned upper-layer
// offsets are relative to that raw quote. At least the first eight bytes of the
// identified upper layer must be present, which is the RFC 4443 correlation
// boundary for UDP, TCP and Echo.
std::optional<Ipv6View>
parse_ipv6_quote(std::span<const std::uint8_t> quote) noexcept;
std::optional<Icmpv6View>
parse_icmpv6(std::span<const std::uint8_t> packet) noexcept;
std::optional<Icmpv6View> parse_icmpv6(const Frame &frame) noexcept;
// IPv6 multicast maps the low-order destination bits into the IEEE 802 group
// address 33:33:xx:xx:xx:xx. Membership filtering remains an endpoint or
// router responsibility and is not implied by producing this address.
[[nodiscard]] Mac ipv6_multicast_mac(Ipv6 destination) noexcept;
void rewrite_ethernet(Frame &frame, Mac source_mac,
                      Mac destination_mac) noexcept;
// Routing preserves the IP payload, replaces only the Ethernet adjacency,
// decrements TTL, and recalculates the IPv4 header checksum.
std::optional<Frame> route_ipv4(const Frame &ingress, Mac source_mac,
                                Mac destination_mac) noexcept;
[[nodiscard]] bool route_ipv4_into(Frame &egress, const Frame &ingress,
                                   Mac source_mac,
                                   Mac destination_mac) noexcept;
std::optional<Frame> route_ipv6(const Frame &ingress, Mac source_mac,
                                Mac destination_mac) noexcept;
[[nodiscard]] bool route_ipv6_into(Frame &egress, const Frame &ingress,
                                   Mac source_mac,
                                   Mac destination_mac) noexcept;
std::optional<FragmentBatch> fragment_ipv4(const Frame &routed,
                                           std::uint16_t mtu) noexcept;

using Ipv4FragmentSink = bool (*)(void *context,
                                  const Frame &fragment) noexcept;

// Fragments a router-forwarded datagram, including valid IPv4 options and an
// already fragmented input. The first fragment retains every input option;
// later fragments retain only options whose copied flag is set. Fragment
// Offset is accumulated from the invoking fragment and the incoming MF state
// is preserved. The sink owns each emitted value immediately and may reject a
// fragment to model egress backpressure. A rejection can follow earlier link
// admissions, which is valid router congestion behavior rather than a source
// transaction. The returned count is present only when the complete input was
// processed.
[[nodiscard]] std::optional<std::size_t> fragment_ipv4_forwarded(
    const Frame &packet, std::uint16_t mtu, void *context,
    Ipv4FragmentSink sink) noexcept;
using Ipv4FragmentAdmission = bool (*)(void *context,
                                       std::size_t fragments) noexcept;
// These source-only functions accept a complete Ethernet plus IPv4 byte image
// up to the 16-bit IPv4 Total Length limit. Count is used for whole-batch queue
// admission before the first fragment is emitted.
[[nodiscard]] std::optional<std::size_t>
ipv4_fragment_count(std::span<const std::uint8_t> packet,
                    std::uint16_t mtu) noexcept;
[[nodiscard]] std::optional<std::size_t> fragment_ipv4_datagram(
    std::span<const std::uint8_t> packet, std::uint16_t mtu,
    void *context, Ipv4FragmentSink sink) noexcept;

} // namespace router::packet
