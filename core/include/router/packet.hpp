// Byte-level Ethernet, ARP, IPv4 and ICMP codecs. All functions own or return
// fixed-capacity values, perform no packet-path allocation and use only wire
// bytes as their protocol boundary.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet {

// Untagged Ethernet carries a 1500-octet IP packet behind a 14-octet header.
// FCS is modeled by the link serializer and is not stored in captured Frame
// bytes. Capture and encoders share this bound to prevent snaplen drift.
inline constexpr std::size_t maximum_frame_octets = 1514;
inline constexpr std::uint16_t ethernet_header_octets = 14;

using Mac = std::array<std::uint8_t, 6>;
using Ipv4 = std::array<std::uint8_t, 4>;

struct Frame {
  // The fixed Ethernet envelope avoids one heap allocation per frame. length
  // is the only portion placed on the wire and excludes the Ethernet FCS.
  // The first milestone supports untagged Ethernet. 1514 captured octets equal
  // the IEEE 1518 octet frame after excluding the four octet FCS.
  // Encoders write every byte below length, including Ethernet padding. The
  // remainder is intentionally not zero-initialized in stack Builders because
  // clearing 1514 bytes for a 60 or 98 byte packet would dominate encoding.
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

struct FragmentBatch {
  // With the profile's minimum 512-byte MTU, a maximum untagged IPv4 packet
  // produces at most four fragments. Fixed storage prevents MTU handling from
  // allocating or hiding an overflow path in forwarding.
  std::array<Frame, 4> frames{};
  std::uint8_t count{};
};

struct EthernetView {
  Mac destination{};
  Mac source{};
  std::uint16_t ether_type{};
};

struct IcmpView {
  std::uint8_t type{};
  std::uint8_t code{};
  std::uint16_t identifier{};
  std::uint16_t sequence{};
  std::span<const std::uint8_t> data{};
};

std::uint16_t checksum(std::span<const std::uint8_t> bytes) noexcept;
// Encoders return complete Ethernet frames so every inter-device exchange goes
// through a queue and LinkDirection instead of passing protocol objects.
Frame arp_request(Mac source_mac, Ipv4 source_ip, Ipv4 target_ip);
Frame arp_reply(Mac source_mac, Ipv4 source_ip, Mac target_mac, Ipv4 target_ip);
Frame icmp_echo(Mac source_mac, Mac target_mac, Ipv4 source_ip, Ipv4 target_ip,
                bool reply, std::uint16_t sequence, std::uint8_t ttl = 64,
                std::size_t payload_octets = 56,
                bool dont_fragment = false);
std::optional<Frame> icmp_echo_reply(const Frame &request, Mac source_mac,
                                     Mac destination_mac) noexcept;
std::optional<Frame> icmp_time_exceeded(const Frame &original, Mac source_mac,
                                        Mac destination_mac, Ipv4 source_ip,
                                        Ipv4 destination_ip) noexcept;
std::optional<Frame>
icmp_fragmentation_needed(const Frame &original, Mac source_mac,
                          Mac destination_mac, Ipv4 source_ip,
                          Ipv4 destination_ip, std::uint16_t mtu) noexcept;
std::optional<EthernetView> parse_ethernet(const Frame &frame) noexcept;
// Untagged endpoint and routed-port receive filters accept their own unicast
// address and Ethernet broadcast. Promiscuous capture occurs at a separate tap.
[[nodiscard]] bool ethernet_for_local(Mac destination, Mac local) noexcept;
std::optional<ArpView> parse_arp(const Frame &frame) noexcept;
std::optional<Ipv4View> parse_ipv4(const Frame &frame) noexcept;
std::optional<IcmpView> parse_icmp(const Frame &frame) noexcept;
void rewrite_ethernet(Frame &frame, Mac source_mac,
                      Mac destination_mac) noexcept;
// Routing preserves the IP payload, replaces only the Ethernet adjacency,
// decrements TTL, and recalculates the IPv4 header checksum.
std::optional<Frame> route_ipv4(const Frame &ingress, Mac source_mac,
                                Mac destination_mac) noexcept;
std::optional<FragmentBatch> fragment_ipv4(const Frame &routed,
                                           std::uint16_t mtu) noexcept;

} // namespace router::packet
