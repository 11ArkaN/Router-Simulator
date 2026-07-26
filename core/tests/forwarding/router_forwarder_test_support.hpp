// Router forwarder tests drive only encoded frames through two local ports.
// They verify per-hop ARP, TTL, checksum and ICMP without topology shortcuts.


#pragma once
#include "router/dhcpv6_packet.hpp"
#include "router/dhcpv6_relay.hpp"
#include "router/ospf_packet.hpp"
#include "router/router_forwarder.hpp"
#include "router/udp_packet.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

namespace {

[[maybe_unused]] void require(bool condition, const char *message) {
  // The module runner retains the first packet-path contract failure.
  if (!condition)
    throw std::runtime_error(message);
}

struct Emitted {
  std::uint16_t port{};
  router::packet::Frame frame{};
};

[[maybe_unused]] bool collect(void *context, std::uint16_t port,
                              const router::packet::Frame &frame) {
  // Test storage copies wire bytes because the sink contract does not permit a
  // caller to retain the forwarder's temporary frame reference.
  static_cast<std::vector<Emitted> *>(context)->push_back({port, frame});
  return true;
}

[[maybe_unused]] bool admit_all(void *, std::uint16_t, std::size_t frames) {
  // The vector sink used by this module has no finite ring. Returning true for
  // a non-empty batch exercises the same preflight contract supplied by the
  // production SPSC owner without inventing per-fragment acceptance.
  return frames != 0U;
}

[[maybe_unused]] void count_punt(void *context, std::uint16_t,
                                 const router::packet::Frame &) {
  // The forwarding observer receives the original immutable wire frame.
  // Counting callbacks is sufficient here because packet and checksum codecs
  // have their own byte-exact suites; this regression owns only L2 multicast
  // admission before the OSPF SPSC boundary.
  ++*static_cast<std::size_t *>(context);
}

[[maybe_unused]] router::packet::Frame udp_ipv6_payload_frame(
    const router::packet::Mac &source_mac,
    const router::packet::Mac &destination_mac,
    const router::packet::Ipv6 &source, const router::packet::Ipv6 &destination,
    std::uint16_t source_port, std::uint16_t destination_port,
    std::span<const std::uint8_t> payload) {
  // This helper still constructs a wire packet. It does not inject UDP
  // metadata or a decoded DHCP object into the router application owner.
  using namespace router;
  packet::Frame frame{};
  std::array<std::uint8_t, packet::udp::maximum_datagram_octets> udp{};
  const auto encoded = packet::udp::encode_ipv6(
      udp, source, destination, source_port, destination_port, payload);
  if (!encoded)
    throw std::runtime_error("UDP IPv6 payload fixture encoding failed");
  const auto frame_octets = packet::encode_ipv6_ethernet_datagram(
      frame.bytes, source_mac, destination_mac, source, destination,
      packet::ipv6_next_header_udp, 64U,
      std::span<const std::uint8_t>{udp}.first(*encoded));
  if (!frame_octets || *frame_octets > frame.bytes.size())
    throw std::runtime_error("UDP IPv6 payload fixture exceeds one frame");
  frame.length = static_cast<std::uint16_t>(*frame_octets);
  return frame;
}

[[maybe_unused]] router::packet::Frame
udp_ipv6_frame(const router::packet::Mac &source_mac,
               const router::packet::Mac &destination_mac,
               const router::packet::Ipv6 &source,
               const router::packet::Ipv6 &destination) {
  constexpr std::array<std::uint8_t, 3> payload{0x41U, 0x42U, 0x43U};
  return udp_ipv6_payload_frame(source_mac, destination_mac, source,
                                destination, 49152U, 9999U, payload);
}

[[maybe_unused]] void append_u16(std::vector<std::uint8_t> &output,
                                 std::uint16_t value) {
  // DHCPv6 option headers are network byte order. Keeping the test writer
  // explicit makes nested IA payloads pass through the production parser
  // instead of constructing decoded lease records behind the packet path.
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

[[maybe_unused]] void
append_dhcpv6_option(std::vector<std::uint8_t> &output,
                     router::packet::dhcpv6::OptionCode code,
                     std::span<const std::uint8_t> body) {
  if (body.size() > 0xffffU)
    throw std::runtime_error("DHCPv6 nested option fixture is too large");
  append_u16(output, static_cast<std::uint16_t>(code));
  append_u16(output, static_cast<std::uint16_t>(body.size()));
  output.insert(output.end(), body.begin(), body.end());
}

[[maybe_unused]] bool
append_dhcpv6_association(router::packet::dhcpv6::Writer &message,
                          router::packet::dhcpv6::OptionCode code,
                          std::uint32_t iaid,
                          std::span<const std::uint8_t> nested = {}) {
  // IA_NA and IA_PD share the RFC 9915 IAID, T1 and T2 fixed header. This
  // helper is intentionally limited to those two codes so a future IA_TA
  // test cannot accidentally emit the wrong eight extra octets.
  if (code != router::packet::dhcpv6::OptionCode::ia_na &&
      code != router::packet::dhcpv6::OptionCode::ia_pd)
    return false;
  std::array<std::uint8_t, 512U> body{};
  const auto body_octets =
      router::packet::dhcpv6::encode_ia_na_or_pd(body, iaid, 30U, 50U, nested);
  return body_octets &&
         message.append(
             static_cast<std::uint16_t>(code),
             std::span<const std::uint8_t>{body}.first(*body_octets));
}

[[maybe_unused]] std::unique_ptr<router::lab::RouterForwarderCheckpoint>
snapshot(const router::lab::RouterForwarder &forwarder,
         router::lab::RouterForwarder::Clock::time_point now =
             router::lab::RouterForwarder::Clock::now()) {
  // Router checkpoints contain complete fixed-capacity FIB programs. Building
  // directly in heap-owned storage mirrors the runtime checkpoint arena and
  // prevents a test-only copy from consuming the bounded Wasm control stack.
  auto result = std::make_unique<router::lab::RouterForwarderCheckpoint>();
  forwarder.checkpoint(*result, now);
  return result;
}

} // namespace
