#include "router/packet.hpp"

#include <algorithm>

namespace router::packet {
namespace {

class Builder {
 public:
  // Builder owns one fixed Frame and is intentionally bounds-check free in the
  // hot path. Every encoder below has a compile-time maximum below 1514 bytes.
  void put(std::uint8_t value) noexcept { frame_.bytes[position_++] = value; }
  void put16(std::uint16_t value) noexcept {
    put(static_cast<std::uint8_t>(value >> 8));
    put(static_cast<std::uint8_t>(value));
  }
  void append(auto value) noexcept {
    for (const auto byte : value) put(byte);
  }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  void patch16(std::size_t offset, std::uint16_t value) noexcept {
    // Multi-byte wire fields use network byte order regardless of Wasm or native
    // host endianness.
    frame_.bytes[offset] = static_cast<std::uint8_t>(value >> 8);
    frame_.bytes[offset + 1] = static_cast<std::uint8_t>(value);
  }
  [[nodiscard]] std::span<const std::uint8_t> span(std::size_t offset,
                                                   std::size_t length) const noexcept {
    return {frame_.bytes.data() + offset, length};
  }
  Frame finish() noexcept {
    // Ethernet payloads shorter than 46 octets are padded before transmission.
    // The FCS belongs to link hardware and is not included in captured bytes.
    while (position_ < 60) put(0);
    frame_.length = static_cast<std::uint16_t>(position_);
    return frame_;
  }

 private:
  // Deliberate default-initialization leaves bytes beyond the eventual length
  // untouched. finish() writes padding through byte 59 and every encoder writes
  // its complete payload, so no uninitialized byte can enter view() or capture.
  Frame frame_;
  std::size_t position_{};
};

Builder ethernet(Mac destination, Mac source, std::uint16_t ether_type) {
  // Centralizing the L2 envelope prevents ARP and IPv4 encoders from diverging
  // in destination, source, and EtherType order.
  Builder out;
  out.append(destination);
  out.append(source);
  out.put16(ether_type);
  return out;
}

}  // namespace

std::uint16_t checksum(std::span<const std::uint8_t> bytes) noexcept {
  // RFC 1071 one's-complement addition is used by both initial IPv4 encoding
  // and forwarding-time checksum validation. Odd final bytes occupy the high
  // octet of the last 16-bit word.
  std::uint32_t sum = 0;
  for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
    sum += static_cast<std::uint16_t>((bytes[i] << 8) | bytes[i + 1]);
  }
  if (bytes.size() & 1U) sum += static_cast<std::uint16_t>(bytes.back() << 8);
  while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
  return static_cast<std::uint16_t>(~sum);
}

Frame arp_request(Mac source_mac, Ipv4 source_ip, Ipv4 target_ip) {
  // RFC 826 places the unknown target hardware address in the payload while the
  // Ethernet destination itself is broadcast.
  constexpr Mac broadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  constexpr Mac unknown{};
  auto out = ethernet(broadcast, source_mac, 0x0806);
  out.put16(1);       // Ethernet
  out.put16(0x0800);  // IPv4
  out.put(6);
  out.put(4);
  out.put16(1);
  out.append(source_mac);
  out.append(source_ip);
  out.append(unknown);
  out.append(target_ip);
  return out.finish();
}

Frame arp_reply(Mac source_mac, Ipv4 source_ip, Mac target_mac, Ipv4 target_ip) {
  // A reply is unicast to the requester and carries the same address tuple in
  // the ARP payload, allowing the receiver to learn from parsed wire bytes.
  auto out = ethernet(target_mac, source_mac, 0x0806);
  out.put16(1);
  out.put16(0x0800);
  out.put(6);
  out.put(4);
  out.put16(2);
  out.append(source_mac);
  out.append(source_ip);
  out.append(target_mac);
  out.append(target_ip);
  return out.finish();
}

Frame icmp_echo(Mac source_mac, Mac target_mac, Ipv4 source_ip, Ipv4 target_ip,
                bool reply, std::uint16_t sequence, std::uint8_t ttl) {
  // Source: ietf.icmp.rfc792 and nokia.sros.26_7.ping. A normal SR OS ping
  // reports 56 data bytes, so the encoded Echo payload has that exact length.
  constexpr std::array<std::uint8_t, 56> payload{
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53};
  auto out = ethernet(target_mac, source_mac, 0x0800);
  const auto ip_start = out.position();
  out.put(0x45);
  out.put(0);
  out.put16(84);
  out.put16(sequence);
  out.put16(0x4000);
  out.put(ttl);
  out.put(1);
  out.put16(0);
  out.append(source_ip);
  out.append(target_ip);

  const auto ip_checksum = checksum(out.span(ip_start, 20));
  out.patch16(ip_start + 10, ip_checksum);

  const auto icmp_start = out.position();
  out.put(static_cast<std::uint8_t>(reply ? 0 : 8));
  out.put(0);
  out.put16(0);
  out.put16(0x5253);
  out.put16(sequence);
  out.append(payload);
  const auto icmp_checksum = checksum(out.span(icmp_start, 64));
  out.patch16(icmp_start + 2, icmp_checksum);
  return out.finish();
}

std::optional<EthernetView> parse_ethernet(const Frame& frame) noexcept {
  if (frame.size() < 14) return std::nullopt;
  EthernetView view;
  std::copy_n(frame.bytes.begin(), 6, view.destination.begin());
  std::copy_n(frame.bytes.begin() + 6, 6, view.source.begin());
  view.ether_type = static_cast<std::uint16_t>(frame[12] << 8 | frame[13]);
  return view;
}

bool ethernet_for_local(Mac destination, Mac local) noexcept {
  constexpr Mac broadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  return destination == local || destination == broadcast;
}

std::optional<ArpView> parse_arp(const Frame& frame) noexcept {
  // Reject the complete fixed Ethernet/IPv4 shape before reading address fields.
  // This keeps malformed or truncated frames from becoming adjacency state.
  if (frame.size() < 42 || frame[12] != 0x08 || frame[13] != 0x06 ||
      frame[14] != 0 || frame[15] != 1 || frame[16] != 0x08 || frame[17] != 0 ||
      frame[18] != 6 || frame[19] != 4) {
    return std::nullopt;
  }
  ArpView view{.operation = static_cast<std::uint16_t>(frame[20] << 8 | frame[21])};
  std::copy_n(frame.bytes.begin() + 22, 6, view.sender_mac.begin());
  std::copy_n(frame.bytes.begin() + 28, 4, view.sender_ip.begin());
  std::copy_n(frame.bytes.begin() + 32, 6, view.target_mac.begin());
  std::copy_n(frame.bytes.begin() + 38, 4, view.target_ip.begin());
  return view;
}

std::optional<Ipv4View> parse_ipv4(const Frame& frame) noexcept {
  // Validation is deliberately stricter than a destination-only fast path. A
  // bad length or checksum must be dropped before it can influence FIB lookup.
  if (frame.size() < 34 || frame[12] != 0x08 || frame[13] != 0 ||
      frame[14] >> 4 != 4) {
    return std::nullopt;
  }
  const auto header_length = static_cast<std::size_t>(frame[14] & 0x0fU) * 4U;
  const auto total_length = static_cast<std::uint16_t>(frame[16] << 8 | frame[17]);
  if (header_length < 20 || 14 + header_length > frame.size() ||
      total_length < header_length || 14 + total_length > frame.size() ||
      checksum(frame.view().subspan(14, header_length)) != 0) {
    return std::nullopt;
  }
  Ipv4View view{.ttl = frame[22], .protocol = frame[23], .total_length = total_length};
  std::copy_n(frame.bytes.begin() + 26, 4, view.source.begin());
  std::copy_n(frame.bytes.begin() + 30, 4, view.destination.begin());
  return view;
}

std::optional<IcmpView> parse_icmp(const Frame& frame) noexcept {
  const auto ip = parse_ipv4(frame);
  if (!ip || ip->protocol != 1) return std::nullopt;
  const auto header_length = static_cast<std::size_t>(frame[14] & 0x0fU) * 4U;
  const auto icmp_length = static_cast<std::size_t>(ip->total_length) - header_length;
  const auto offset = 14U + header_length;
  if (icmp_length < 8 || checksum(frame.view().subspan(offset, icmp_length)) != 0) {
    return std::nullopt;
  }
  return IcmpView{
      .type = frame[offset],
      .code = frame[offset + 1],
      .identifier = static_cast<std::uint16_t>(frame[offset + 4] << 8 | frame[offset + 5]),
      .sequence = static_cast<std::uint16_t>(frame[offset + 6] << 8 | frame[offset + 7]),
      .data = frame.view().subspan(offset + 8, icmp_length - 8),
  };
}

void rewrite_ethernet(Frame& frame, Mac source_mac, Mac destination_mac) noexcept {
  std::copy(destination_mac.begin(), destination_mac.end(), frame.bytes.begin());
  std::copy(source_mac.begin(), source_mac.end(), frame.bytes.begin() + 6);
}

std::optional<Frame> icmp_echo_reply(const Frame& request, Mac source_mac,
                                     Mac destination_mac) noexcept {
  // Source: ietf.icmp.rfc792. Echo Reply preserves identifier, sequence and
  // data from the received request. It is never manufactured from out-of-band
  // parameters by the receiving endpoint.
  const auto ip = parse_ipv4(request);
  const auto icmp = parse_icmp(request);
  if (!ip || !icmp || icmp->type != 8 || icmp->code != 0) return std::nullopt;
  Frame reply = request;
  rewrite_ethernet(reply, source_mac, destination_mac);
  std::copy(ip->destination.begin(), ip->destination.end(), reply.bytes.begin() + 26);
  std::copy(ip->source.begin(), ip->source.end(), reply.bytes.begin() + 30);
  const auto header_length = static_cast<std::size_t>(reply[14] & 0x0fU) * 4U;
  // Echo Reply is a newly originated IPv4 datagram. It preserves ICMP data but
  // does not inherit the request's remaining hop count. The milestone endpoint
  // profile originates IPv4 with TTL 64, after which a transit router may
  // independently decrement it according to RFC 1812.
  reply.bytes[22] = 64;
  reply.bytes[24] = 0;
  reply.bytes[25] = 0;
  const auto ip_checksum = checksum(reply.view().subspan(14, header_length));
  reply.bytes[24] = static_cast<std::uint8_t>(ip_checksum >> 8);
  reply.bytes[25] = static_cast<std::uint8_t>(ip_checksum);
  const auto icmp_offset = 14U + header_length;
  const auto icmp_length = static_cast<std::size_t>(ip->total_length) - header_length;
  reply.bytes[icmp_offset] = 0;
  reply.bytes[icmp_offset + 2] = 0;
  reply.bytes[icmp_offset + 3] = 0;
  const auto icmp_checksum = checksum(reply.view().subspan(icmp_offset, icmp_length));
  reply.bytes[icmp_offset + 2] = static_cast<std::uint8_t>(icmp_checksum >> 8);
  reply.bytes[icmp_offset + 3] = static_cast<std::uint8_t>(icmp_checksum);
  return reply;
}

std::optional<Frame> icmp_time_exceeded(const Frame& original, Mac source_mac,
                                        Mac destination_mac, Ipv4 source_ip,
                                        Ipv4 destination_ip) noexcept {
  // Source: ietf.icmp.rfc792 and ietf.ipv4.router_requirements.rfc1812. The
  // payload quotes the original IPv4 header and its first eight data octets.
  const auto original_ip = parse_ipv4(original);
  if (!original_ip) return std::nullopt;
  const auto original_header = static_cast<std::size_t>(original[14] & 0x0fU) * 4U;
  const auto quoted = std::min<std::size_t>(original_ip->total_length,
                                            original_header + 8U);
  auto out = ethernet(destination_mac, source_mac, 0x0800);
  const auto ip_start = out.position();
  out.put(0x45);
  out.put(0);
  out.put16(static_cast<std::uint16_t>(20U + 8U + quoted));
  out.put16(0);
  out.put16(0);
  out.put(64);
  out.put(1);
  out.put16(0);
  out.append(source_ip);
  out.append(destination_ip);
  out.patch16(ip_start + 10, checksum(out.span(ip_start, 20)));
  const auto icmp_start = out.position();
  out.put(11);
  out.put(0);
  out.put16(0);
  out.put16(0);
  out.put16(0);
  for (std::size_t i = 0; i < quoted; ++i) out.put(original[14 + i]);
  out.patch16(icmp_start + 2, checksum(out.span(icmp_start, 8U + quoted)));
  return out.finish();
}

std::optional<Frame> route_ipv4(const Frame& ingress, Mac source_mac,
                                Mac destination_mac) noexcept {
  // Source: ietf.ipv4.router_requirements.rfc1812. The forwarding caller must
  // turn ttl <= 1 into ICMP Time Exceeded before invoking this rewrite.
  const auto parsed = parse_ipv4(ingress);
  if (!parsed || parsed->ttl <= 1) return std::nullopt;
  // Preserve the original IP packet and payload. A router changes only the
  // Ethernet adjacency and IPv4 hop fields for this basic forwarding path.
  Frame egress = ingress;
  rewrite_ethernet(egress, source_mac, destination_mac);
  const auto header_length = static_cast<std::size_t>(egress[14] & 0x0fU) * 4U;
  --egress.bytes[22];
  egress.bytes[24] = 0;
  egress.bytes[25] = 0;
  const auto updated = checksum(egress.view().subspan(14, header_length));
  egress.bytes[24] = static_cast<std::uint8_t>(updated >> 8);
  egress.bytes[25] = static_cast<std::uint8_t>(updated);
  return egress;
}

}  // namespace router::packet
