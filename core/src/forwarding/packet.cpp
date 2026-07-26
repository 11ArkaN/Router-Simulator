// Standards-backed byte codecs for the first IPv4 forwarding milestone. This
// module never owns routing state, timers or queues and never communicates a
// protocol object between devices.

#include "router/packet.hpp"

#include <algorithm>

namespace router::packet {
namespace {

class Builder {
public:
  explicit Builder(Frame &frame) noexcept : frame_(frame) {}
  // Builder owns one fixed Frame and is intentionally bounds-check free in the
  // hot path. Every encoder clamps its payload to the generated frame bound.
  void put(std::uint8_t value) noexcept { frame_.bytes[position_++] = value; }
  void put16(std::uint16_t value) noexcept {
    put(static_cast<std::uint8_t>(value >> 8));
    put(static_cast<std::uint8_t>(value));
  }
  void append(auto value) noexcept {
    for (const auto byte : value)
      put(byte);
  }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  void patch16(std::size_t offset, std::uint16_t value) noexcept {
    // Multi-byte wire fields use network byte order regardless of Wasm or
    // native host endianness.
    frame_.bytes[offset] = static_cast<std::uint8_t>(value >> 8);
    frame_.bytes[offset + 1] = static_cast<std::uint8_t>(value);
  }
  [[nodiscard]] std::span<const std::uint8_t>
  span(std::size_t offset, std::size_t length) const noexcept {
    return {frame_.bytes.data() + offset, length};
  }
  void finish() noexcept {
    // Ethernet payloads shorter than 46 octets are padded before transmission.
    // The FCS belongs to link hardware and is not included in captured bytes.
    while (position_ < 60)
      put(0);
    frame_.length = static_cast<std::uint16_t>(position_);
  }

private:
  // Deliberate default-initialization leaves bytes beyond the eventual length
  // untouched. finish() writes padding through byte 59 and every encoder writes
  // its complete payload, so no uninitialized byte can enter view() or capture.
  Frame &frame_;
  std::size_t position_{};
};

// IEEE 802.3 fixes destination before source on the wire. Keeping that order in
// the helper makes a byte-by-byte comparison with the header direct.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
Builder ethernet(Frame &frame, Mac destination, Mac source,
                 std::uint16_t ether_type) {
  // Centralizing the L2 envelope prevents ARP and IPv4 encoders from diverging
  // in destination, source, and EtherType order.
  Builder out{frame};
  out.append(destination);
  out.append(source);
  out.put16(ether_type);
  return out;
}

} // namespace

std::uint16_t checksum(std::span<const std::uint8_t> bytes) noexcept {
  // RFC 1071 one's-complement addition is used by both initial IPv4 encoding
  // and forwarding-time checksum validation. Odd final bytes occupy the high
  // octet of the last 16-bit word.
  std::uint32_t sum = 0;
  for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
    sum += static_cast<std::uint16_t>((bytes[i] << 8) | bytes[i + 1]);
  }
  if (bytes.size() & 1U)
    sum += static_cast<std::uint16_t>(bytes.back() << 8);
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return static_cast<std::uint16_t>(~sum);
}

std::uint16_t ipv6_upper_layer_checksum(
    Ipv6 source, Ipv6 destination, std::uint8_t next_header,
    std::span<const std::uint8_t> payload) noexcept {
  // RFC 8200 section 8.1 extends the ordinary one's-complement checksum with
  // source, destination, a 32-bit upper-layer length and a 32-bit next-header
  // field. Accumulating directly avoids a temporary pseudo-header allocation
  // on every ICMPv6, UDP or TCP packet.
  std::uint32_t sum{};
  const auto add_words = [&sum](std::span<const std::uint8_t> bytes) {
    for (std::size_t index = 0; index + 1U < bytes.size(); index += 2U) {
      sum += static_cast<std::uint16_t>((bytes[index] << 8U) |
                                        bytes[index + 1U]);
    }
    if ((bytes.size() & 1U) != 0)
      sum += static_cast<std::uint16_t>(bytes.back() << 8U);
  };
  add_words(source);
  add_words(destination);
  const auto length = static_cast<std::uint32_t>(payload.size());
  sum += static_cast<std::uint16_t>(length >> 16U);
  sum += static_cast<std::uint16_t>(length);
  // Three zero octets precede Next Header, so only its low-order word adds a
  // value. Writing this explicitly makes host byte order irrelevant.
  sum += next_header;
  add_words(payload);
  while ((sum >> 16U) != 0)
    sum = (sum & 0xffffU) + (sum >> 16U);
  return static_cast<std::uint16_t>(~sum);
}

std::uint16_t ipv4_upper_layer_checksum(
    Ipv4 source, Ipv4 destination, std::uint8_t protocol,
    std::span<const std::uint8_t> payload) noexcept {
  // RFC 9293 and RFC 768 use the same IPv4 source, destination, zero,
  // protocol and 16-bit upper-layer length pseudo-header. Accumulating each
  // region separately avoids a temporary pseudo-packet allocation.
  std::uint32_t sum{};
  const auto add = [&sum](std::span<const std::uint8_t> bytes) {
    for (std::size_t index = 0U; index + 1U < bytes.size(); index += 2U)
      sum += static_cast<std::uint16_t>(
          (static_cast<std::uint16_t>(bytes[index]) << 8U) |
          bytes[index + 1U]);
    if ((bytes.size() & 1U) != 0U)
      sum += static_cast<std::uint16_t>(bytes.back() << 8U);
  };
  add(source);
  add(destination);
  sum += protocol;
  sum += static_cast<std::uint16_t>(payload.size());
  add(payload);
  while ((sum >> 16U) != 0U)
    sum = (sum & 0xffffU) + (sum >> 16U);
  return static_cast<std::uint16_t>(~sum);
}

std::optional<std::size_t> encode_ipv6_ethernet_datagram(
    std::span<std::uint8_t> output, Mac source_mac, Mac destination_mac,
    Ipv6 source, Ipv6 destination, std::uint8_t next_header,
    std::uint8_t hop_limit, std::span<const std::uint8_t> payload,
    std::uint8_t traffic_class, std::uint32_t flow_label) noexcept {
  if (payload.size() > maximum_ipv6_payload_octets ||
      flow_label > 0x000fffffU)
    return std::nullopt;
  const auto packet_octets = static_cast<std::size_t>(ethernet_header_octets) +
                             ipv6_header_octets + payload.size();
  const auto wire_octets =
      std::max<std::size_t>(packet_octets, ethernet_minimum_without_fcs);
  if (output.size() < wire_octets)
    return std::nullopt;

  // Version, Traffic Class and Flow Label share the first network-order word.
  // Constructing that word explicitly avoids relying on native bit-field
  // layout, which differs between the Windows validation build and Wasm.
  std::copy(destination_mac.begin(), destination_mac.end(), output.begin());
  std::copy(source_mac.begin(), source_mac.end(), output.begin() + 6U);
  output[12U] = static_cast<std::uint8_t>(ethernet_type_ipv6 >> 8U);
  output[13U] = static_cast<std::uint8_t>(ethernet_type_ipv6);
  const auto first_word = 0x60000000U |
                          (static_cast<std::uint32_t>(traffic_class) << 20U) |
                          flow_label;
  output[14U] = static_cast<std::uint8_t>(first_word >> 24U);
  output[15U] = static_cast<std::uint8_t>(first_word >> 16U);
  output[16U] = static_cast<std::uint8_t>(first_word >> 8U);
  output[17U] = static_cast<std::uint8_t>(first_word);
  output[18U] = static_cast<std::uint8_t>(payload.size() >> 8U);
  output[19U] = static_cast<std::uint8_t>(payload.size());
  output[20U] = next_header;
  output[21U] = hop_limit;
  std::copy(source.begin(), source.end(), output.begin() + 22U);
  std::copy(destination.begin(), destination.end(), output.begin() + 38U);
  std::copy(payload.begin(), payload.end(), output.begin() + 54U);
  std::fill(output.begin() + static_cast<std::ptrdiff_t>(packet_octets),
            output.begin() + static_cast<std::ptrdiff_t>(wire_octets),
            std::uint8_t{0});
  return wire_octets;
}

std::optional<std::size_t> encode_ipv4_ethernet_datagram(
    std::span<std::uint8_t> output, Mac source_mac, Mac destination_mac,
    Ipv4 source, Ipv4 destination, std::uint8_t protocol,
    std::uint8_t ttl, std::uint16_t identification,
    std::span<const std::uint8_t> payload, bool dont_fragment) noexcept {
  constexpr std::size_t ipv4_header_octets = 20U;
  if (ttl == 0U ||
      payload.size() > maximum_ipv4_datagram_octets - ipv4_header_octets)
    return std::nullopt;
  const auto total_length = ipv4_header_octets + payload.size();
  const auto packet_octets = ethernet_header_octets + total_length;
  const auto wire_octets =
      std::max<std::size_t>(packet_octets, ethernet_minimum_without_fcs);
  if (output.size() < wire_octets)
    return std::nullopt;

  std::copy(destination_mac.begin(), destination_mac.end(), output.begin());
  std::copy(source_mac.begin(), source_mac.end(), output.begin() + 6U);
  output[12U] = static_cast<std::uint8_t>(ethernet_type_ipv4 >> 8U);
  output[13U] = static_cast<std::uint8_t>(ethernet_type_ipv4);
  output[14U] = 0x45U;
  output[15U] = 0U;
  output[16U] = static_cast<std::uint8_t>(total_length >> 8U);
  output[17U] = static_cast<std::uint8_t>(total_length);
  output[18U] = static_cast<std::uint8_t>(identification >> 8U);
  output[19U] = static_cast<std::uint8_t>(identification);
  output[20U] = dont_fragment ? 0x40U : 0U;
  output[21U] = 0U;
  output[22U] = ttl;
  output[23U] = protocol;
  output[24U] = 0U;
  output[25U] = 0U;
  std::copy(source.begin(), source.end(), output.begin() + 26U);
  std::copy(destination.begin(), destination.end(), output.begin() + 30U);
  const auto header_checksum =
      checksum(output.subspan(ethernet_header_octets, ipv4_header_octets));
  output[24U] = static_cast<std::uint8_t>(header_checksum >> 8U);
  output[25U] = static_cast<std::uint8_t>(header_checksum);
  std::copy(payload.begin(), payload.end(), output.begin() + 34U);
  std::fill(output.begin() + static_cast<std::ptrdiff_t>(packet_octets),
            output.begin() + static_cast<std::ptrdiff_t>(wire_octets),
            std::uint8_t{0});
  return wire_octets;
}

// RFC 826 names the sender tuple before the target tuple. The same order at the
// API boundary makes the encoder's append sequence auditable against the RFC.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void copy_frame(Frame &destination, const Frame &source) noexcept {
  // length is validated by every decoder before bytes are consumed. Copying
  // only the live prefix retains a trivial shared-memory Frame layout while
  // avoiding 9 KiB traffic for the common 60 to 98 byte packet.
  std::copy_n(source.bytes.begin(), source.length, destination.bytes.begin());
  destination.length = source.length;
}

void arp_request_into(Frame &result, Mac source_mac, Ipv4 source_ip,
                      Ipv4 target_ip) noexcept {
  // RFC 826 places the unknown target hardware address in the payload while the
  // Ethernet destination itself is broadcast.
  constexpr Mac broadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  constexpr Mac unknown{};
  auto out = ethernet(result, broadcast, source_mac, 0x0806);
  out.put16(1);      // Ethernet
  out.put16(0x0800); // IPv4
  out.put(6);
  out.put(4);
  out.put16(1);
  out.append(source_mac);
  out.append(source_ip);
  out.append(unknown);
  out.append(target_ip);
  out.finish();
}

Frame arp_request(Mac source_mac, Ipv4 source_ip, Ipv4 target_ip) {
  Frame result;
  arp_request_into(result, source_mac, source_ip, target_ip);
  return result;
}

void arp_reply_into(Frame &result, Mac source_mac, Ipv4 source_ip,
                    Mac target_mac, Ipv4 target_ip) noexcept {
  // A reply is unicast to the requester and carries the same address tuple in
  // the ARP payload, allowing the receiver to learn from parsed wire bytes.
  auto out = ethernet(result, target_mac, source_mac, 0x0806);
  out.put16(1);
  out.put16(0x0800);
  out.put(6);
  out.put(4);
  out.put16(2);
  out.append(source_mac);
  out.append(source_ip);
  out.append(target_mac);
  out.append(target_ip);
  out.finish();
}

Frame arp_reply(Mac source_mac, Ipv4 source_ip, Mac target_mac,
                Ipv4 target_ip) {
  Frame result;
  arp_reply_into(result, source_mac, source_ip, target_mac, target_ip);
  return result;
}

// Source and destination fields intentionally follow packet traversal order.
// sequence then TTL mirrors the varying ICMP field before the IP hop limit.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
void icmp_echo_into(Frame &result, Mac source_mac, Mac target_mac,
                    Ipv4 source_ip, Ipv4 target_ip, bool reply,
                    std::uint16_t sequence, std::uint8_t ttl,
                    std::size_t payload_octets, bool dont_fragment) noexcept {
  // Source: ietf.icmp.rfc792 and nokia.sros.26_7.ping. A normal SR OS ping
  // reports 56 data bytes, so the encoded Echo payload has that exact length.
  constexpr std::array<std::uint8_t, 56> pattern{
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54,
      0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54,
      0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53};
  payload_octets = std::min(payload_octets, maximum_frame_octets - 42U);
  auto out = ethernet(result, target_mac, source_mac, 0x0800);
  const auto ip_start = out.position();
  out.put(0x45);
  out.put(0);
  out.put16(static_cast<std::uint16_t>(28U + payload_octets));
  out.put16(sequence);
  // The operational ping option controls DF. Normal ping remains fragmentable;
  // setting DF without an explicit command would make configured MTU behave
  // differently from SR OS and RFC 1812.
  out.put16(dont_fragment ? 0x4000U : 0U);
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
  for (std::size_t index = 0; index < payload_octets; ++index)
    out.put(pattern[index % pattern.size()]);
  const auto icmp_checksum = checksum(out.span(icmp_start, 8U + payload_octets));
  out.patch16(icmp_start + 2, icmp_checksum);
  out.finish();
}

Frame icmp_echo(Mac source_mac, Mac target_mac, Ipv4 source_ip, Ipv4 target_ip,
                bool reply, std::uint16_t sequence, std::uint8_t ttl,
                std::size_t payload_octets, bool dont_fragment) {
  Frame result;
  icmp_echo_into(result, source_mac, target_mac, source_ip, target_ip, reply,
                 sequence, ttl, payload_octets, dont_fragment);
  return result;
}

void icmpv6_echo_into(Frame &result, Mac source_mac, Mac target_mac,
                      Ipv6 source_ip, Ipv6 target_ip, bool reply,
                      std::uint16_t sequence, std::uint8_t hop_limit,
                      std::size_t payload_octets) noexcept {
  // RFC 4443 defines Echo Request 128 and Echo Reply 129. The identifier and
  // sequence fields deliberately match the IPv4 encoder so one future ping
  // operation can correlate both families without a UI-only identity.
  constexpr std::array<std::uint8_t, 56> pattern{
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54,
      0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54,
      0x45, 0x52, 0x2d, 0x53, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53,
      0x52, 0x4f, 0x55, 0x54, 0x45, 0x52, 0x2d, 0x53};
  payload_octets = std::min(payload_octets, maximum_frame_octets - 62U);
  auto out = ethernet(result, target_mac, source_mac, 0x86dd);
  // Version, traffic class and flow label form one 32-bit field. A normal ping
  // begins with traffic class and flow label zero until its CLI options expose
  // documented values.
  out.put(0x60);
  out.put(0);
  out.put16(0);
  out.put16(static_cast<std::uint16_t>(8U + payload_octets));
  out.put(ipv6_next_header_icmpv6);
  out.put(hop_limit);
  out.append(source_ip);
  out.append(target_ip);
  const auto icmp_start = out.position();
  out.put(reply ? icmpv6_echo_reply_type : icmpv6_echo_request_type);
  out.put(0);
  out.put16(0);
  out.put16(0x5253);
  out.put16(sequence);
  for (std::size_t index = 0; index < payload_octets; ++index)
    out.put(pattern[index % pattern.size()]);
  const auto icmp_length = 8U + payload_octets;
  out.patch16(icmp_start + 2U,
              ipv6_upper_layer_checksum(source_ip, target_ip,
                                        ipv6_next_header_icmpv6,
                                        out.span(icmp_start, icmp_length)));
  out.finish();
}

void icmpv6_message_into(Frame &result, Mac source_mac, Mac target_mac,
                         Ipv6 source_ip, Ipv6 target_ip, std::uint8_t type,
                         std::uint8_t code,
                         std::span<const std::uint8_t> body,
                         std::uint8_t hop_limit) noexcept {
  // The caller owns semantic validation of its message body. This layer clamps
  // only the physical frame bound and guarantees a complete, checksummed IPv6
  // packet. Control messages larger than one modeled frame must use their own
  // protocol segmentation rather than being silently truncated here.
  const auto maximum_body = maximum_frame_octets - 58U;
  if (body.size() > maximum_body) {
    result.length = 0;
    return;
  }
  auto out = ethernet(result, target_mac, source_mac, 0x86dd);
  out.put(0x60);
  out.put(0);
  out.put16(0);
  out.put16(static_cast<std::uint16_t>(4U + body.size()));
  out.put(ipv6_next_header_icmpv6);
  out.put(hop_limit);
  out.append(source_ip);
  out.append(target_ip);
  const auto icmp_start = out.position();
  out.put(type);
  out.put(code);
  out.put16(0);
  out.append(body);
  out.patch16(icmp_start + 2U,
              ipv6_upper_layer_checksum(
                  source_ip, target_ip, ipv6_next_header_icmpv6,
                  out.span(icmp_start, 4U + body.size())));
  out.finish();
}

Frame icmpv6_echo(Mac source_mac, Mac target_mac, Ipv6 source_ip,
                  Ipv6 target_ip, bool reply, std::uint16_t sequence,
                  std::uint8_t hop_limit, std::size_t payload_octets) {
  Frame result;
  icmpv6_echo_into(result, source_mac, target_mac, source_ip, target_ip, reply,
                   sequence, hop_limit, payload_octets);
  return result;
}
// NOLINTEND(bugprone-easily-swappable-parameters)

std::optional<EthernetView>
parse_ethernet(std::span<const std::uint8_t> packet) noexcept {
  // Sources: ieee.802_3.ethernet_frame_timing and ieee.802_1q.vlan_tagging.
  // Captured frames exclude preamble and FCS. VLAN tags are part of the MAC
  // client frame and appear between Source Address and the final EtherType.
  if (packet.size() < 14U)
    return std::nullopt;
  EthernetView view;
  std::copy_n(packet.begin(), 6U, view.destination.begin());
  std::copy_n(packet.begin() + 6U, 6U, view.source.begin());
  std::size_t offset = 12U;
  auto type = static_cast<std::uint16_t>(packet[offset] << 8U |
                                         packet[offset + 1U]);
  while ((type == ethernet_type_customer_vlan ||
          type == ethernet_type_service_vlan) &&
         view.vlan_tag_count < maximum_service_vlan_tags) {
    // TPID, TCI and the following EtherType require six bytes from the current
    // offset. Rejecting the entire frame prevents a truncated tag from being
    // reinterpreted as an untagged service payload.
    if (offset + 6U > packet.size())
      return std::nullopt;
    const auto control = static_cast<std::uint16_t>(
        packet[offset + 2U] << 8U | packet[offset + 3U]);
    view.vlan_tags[view.vlan_tag_count++] = EthernetView::VlanTag{
        .tpid = type,
        .vlan_identifier = static_cast<std::uint16_t>(control & 0x0fffU),
        .priority_code_point = static_cast<std::uint8_t>(control >> 13U),
        .drop_eligible = (control & 0x1000U) != 0U};
    offset += vlan_tag_octets;
    type = static_cast<std::uint16_t>(packet[offset] << 8U |
                                      packet[offset + 1U]);
  }
  view.ether_type = type;
  view.payload_offset = static_cast<std::uint16_t>(offset + 2U);
  return view;
}

std::optional<EthernetView> parse_ethernet(const Frame &frame) noexcept {
  return parse_ethernet(frame.view());
}

bool insert_vlan_tags(
    Frame &frame,
    std::span<const EthernetView::VlanTag> tags) noexcept {
  if (tags.empty())
    return true;
  const auto added = tags.size() * vlan_tag_octets;
  if (tags.size() > maximum_service_vlan_tags ||
      frame.length < ethernet_header_octets ||
      frame.length + added > frame.bytes.size())
    return false;
  for (const auto &tag : tags)
    // A port profile may select a provider TPID other than the two values the
    // generic parser recognizes without port context. IEEE 802.3 reserves
    // values below 1536 as length fields, so accepting every EtherType above
    // that boundary keeps insertion profile-driven without accepting lengths.
    if (tag.tpid < 0x0600U || tag.vlan_identifier == 0x0fffU ||
        tag.priority_code_point > 7U)
      return false;

  // Move the original EtherType and payload as one overlapping range. Writing
  // every TCI only after the capacity and semantic checks above supplies the
  // promised all-or-nothing failure behavior.
  std::move_backward(frame.bytes.begin() + 12U,
                     frame.bytes.begin() + frame.length,
                     frame.bytes.begin() + frame.length + added);
  std::size_t offset = 12U;
  for (const auto &tag : tags) {
    const auto control = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(tag.priority_code_point) << 13U) |
        (tag.drop_eligible ? 0x1000U : 0U) | tag.vlan_identifier);
    frame.bytes[offset] = static_cast<std::uint8_t>(tag.tpid >> 8U);
    frame.bytes[offset + 1U] = static_cast<std::uint8_t>(tag.tpid);
    frame.bytes[offset + 2U] = static_cast<std::uint8_t>(control >> 8U);
    frame.bytes[offset + 3U] = static_cast<std::uint8_t>(control);
    offset += vlan_tag_octets;
  }
  frame.length = static_cast<std::uint16_t>(frame.length + added);
  return true;
}

bool strip_vlan_tags(Frame &frame) noexcept {
  const auto view = parse_ethernet(frame);
  if (!view)
    return false;
  if (!view->vlan_tag_count)
    return true;
  const auto removed = static_cast<std::size_t>(view->vlan_tag_count) *
                       vlan_tag_octets;
  const auto inner_type_offset = 12U + removed;
  // Copying toward a lower address is overlap-safe with std::move. The move
  // begins at the inner EtherType so the resulting frame is a complete
  // untagged Ethernet frame accepted by the shared IP and ARP codecs.
  std::move(frame.bytes.begin() + inner_type_offset,
            frame.bytes.begin() + frame.length,
            frame.bytes.begin() + 12U);
  frame.length = static_cast<std::uint16_t>(frame.length - removed);
  return true;
}

bool ethernet_for_local(Mac destination, Mac local) noexcept {
  // The first milestone has no multicast membership or promiscuous receive
  // mode. A port accepts only its station address and the broadcast address.
  constexpr Mac broadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  return destination == local || destination == broadcast;
}

std::optional<ArpView> parse_arp(const Frame &frame) noexcept {
  // Reject the complete fixed Ethernet/IPv4 shape before reading address
  // fields. This keeps malformed or truncated frames from becoming adjacency
  // state.
  if (frame.size() < 42 || frame[12] != 0x08 || frame[13] != 0x06 ||
      frame[14] != 0 || frame[15] != 1 || frame[16] != 0x08 || frame[17] != 0 ||
      frame[18] != 6 || frame[19] != 4) {
    return std::nullopt;
  }
  ArpView view{.operation =
                   static_cast<std::uint16_t>(frame[20] << 8 | frame[21])};
  std::copy_n(frame.bytes.begin() + 22, 6, view.sender_mac.begin());
  std::copy_n(frame.bytes.begin() + 28, 4, view.sender_ip.begin());
  std::copy_n(frame.bytes.begin() + 32, 6, view.target_mac.begin());
  std::copy_n(frame.bytes.begin() + 38, 4, view.target_ip.begin());
  return view;
}

std::optional<Ipv4View>
parse_ipv4(std::span<const std::uint8_t> packet) noexcept {
  // Validation is deliberately stricter than a destination-only fast path. A
  // bad length or checksum must be dropped before it can influence FIB lookup.
  if (packet.size() < 34U || packet[12U] != 0x08U || packet[13U] != 0U ||
      packet[14U] >> 4U != 4U) {
    return std::nullopt;
  }
  const auto header_length =
      static_cast<std::size_t>(packet[14U] & 0x0fU) * 4U;
  const auto total_length =
      static_cast<std::uint16_t>(packet[16U] << 8U | packet[17U]);
  if (header_length < 20U || 14U + header_length > packet.size() ||
      static_cast<std::size_t>(total_length) < header_length ||
      14U + static_cast<std::size_t>(total_length) > packet.size() ||
      checksum(packet.subspan(14U, header_length)) != 0U) {
    return std::nullopt;
  }
  Ipv4View view{
      .ttl = packet[22U],
      .protocol = packet[23U],
      .total_length = total_length,
      .identification =
          static_cast<std::uint16_t>(packet[18U] << 8U | packet[19U]),
      .fragment_offset = static_cast<std::uint16_t>(
          ((packet[20U] & 0x1fU) << 8U) | packet[21U]),
      .header_length = static_cast<std::uint8_t>(header_length),
      .dont_fragment = (packet[20U] & 0x40U) != 0,
      .more_fragments = (packet[20U] & 0x20U) != 0};
  std::copy_n(packet.begin() + 26U, 4U, view.source.begin());
  std::copy_n(packet.begin() + 30U, 4U, view.destination.begin());
  return view;
}

std::optional<Ipv4View> parse_ipv4(const Frame &frame) noexcept {
  return parse_ipv4(frame.view());
}

std::optional<Ipv4View>
parse_ipv4_quote(std::span<const std::uint8_t> quote) noexcept {
  if (quote.size() < 28U || (quote[0U] >> 4U) != 4U)
    return std::nullopt;
  const auto header_length =
      static_cast<std::size_t>(quote[0U] & 0x0fU) * 4U;
  const auto total_length =
      static_cast<std::uint16_t>(quote[2U] << 8U | quote[3U]);
  if (header_length < 20U || header_length > 60U ||
      header_length + 8U > quote.size() || total_length < header_length + 8U ||
      checksum(quote.first(header_length)) != 0U)
    return std::nullopt;
  Ipv4View view{
      .ttl = quote[8U],
      .protocol = quote[9U],
      .total_length = total_length,
      .identification =
          static_cast<std::uint16_t>(quote[4U] << 8U | quote[5U]),
      .fragment_offset = static_cast<std::uint16_t>(
          ((quote[6U] & 0x1fU) << 8U) | quote[7U]),
      .header_length = static_cast<std::uint8_t>(header_length),
      .dont_fragment = (quote[6U] & 0x40U) != 0U,
      .more_fragments = (quote[6U] & 0x20U) != 0U};
  std::copy_n(quote.begin() + 12U, 4U, view.source.begin());
  std::copy_n(quote.begin() + 16U, 4U, view.destination.begin());
  return view;
}

std::optional<Ipv6View>
parse_ipv6(std::span<const std::uint8_t> packet) noexcept {
  // The minimum captured shape is Ethernet plus the fixed forty-octet IPv6
  // header. Ethernet padding is allowed after the declared payload but is not
  // exposed to upper-layer parsers.
  if (packet.size() < 54U || packet[12] != 0x86 || packet[13] != 0xdd ||
      (packet[14] >> 4U) != 6U)
    return std::nullopt;
  const auto payload_length =
      static_cast<std::uint16_t>((packet[18] << 8U) | packet[19]);
  // A zero payload length can denote an RFC 2675 jumbogram only when a Jumbo
  // Payload option supplies a length over 65535. The modeled Ethernet profiles
  // cannot carry one, so accepting zero with trailing bytes would reinterpret
  // malformed input as a normal packet.
  if (payload_length == 0U || 54U + payload_length > packet.size())
    return std::nullopt;

  Ipv6View view{
      .flow_label = static_cast<std::uint32_t>(((packet[15] & 0x0fU) << 16U) |
                                               (packet[16] << 8U) | packet[17]),
      .payload_length = payload_length,
      .upper_layer_offset = 54,
      .upper_layer_next_header_offset = 20,
      .traffic_class = static_cast<std::uint8_t>(((packet[14] & 0x0fU) << 4U) |
                                                 (packet[15] >> 4U)),
      .next_header = packet[20],
      .upper_layer_protocol = packet[20],
      .hop_limit = packet[21]};
  std::copy_n(packet.begin() + 22, 16, view.source.begin());
  std::copy_n(packet.begin() + 38, 16, view.destination.begin());

  const auto packet_end = 54U + static_cast<std::size_t>(payload_length);
  std::size_t offset = 54U;
  auto current = view.next_header;
  std::size_t current_next_header_offset = 20U;
  bool fragment_seen{};
  for (;;) {
    std::size_t extension_length{};
    if (current == 0U || current == 43U || current == 60U) {
      // Hop-by-Hop Options is legal only immediately after the fixed header.
      // Routing and Destination Options share the same Hdr Ext Len encoding.
      if ((current == 0U && offset != 54U) || offset + 2U > packet_end)
        return std::nullopt;
      extension_length =
          (static_cast<std::size_t>(packet[offset + 1U]) + 1U) * 8U;
    } else if (current == 44U) {
      if (fragment_seen || offset + 8U > packet_end)
        return std::nullopt;
      fragment_seen = true;
      view.fragment_previous_next_header_offset =
          static_cast<std::uint16_t>(current_next_header_offset);
      const auto field = static_cast<std::uint16_t>(
          (packet[offset + 2U] << 8U) | packet[offset + 3U]);
      view.fragment = Ipv6FragmentView{
          .identification =
              static_cast<std::uint32_t>(packet[offset + 4U]) << 24U |
              static_cast<std::uint32_t>(packet[offset + 5U]) << 16U |
              static_cast<std::uint32_t>(packet[offset + 6U]) << 8U |
              packet[offset + 7U],
          .offset = static_cast<std::uint16_t>((field >> 3U) & 0x1fffU),
           .more_fragments = (field & 1U) != 0};
      view.fragment_header_offset = static_cast<std::uint16_t>(offset);
      extension_length = 8U;
    } else if (current == 51U) {
      // AH Payload Len counts 32-bit words minus two, unlike the option-header
      // length measured in eight-octet units. RFC 4302 section 2.2 also
      // requires an IPv6 AH to be a multiple of eight octets. The mandatory
      // fixed fields consume twelve octets, which makes sixteen octets the
      // smallest representable IPv6 AH. Rejecting the shorter encodings here
      // prevents a forged Next Header byte from exposing unauthenticated data
      // to an upper-layer parser.
      if (offset + 2U > packet_end)
        return std::nullopt;
      extension_length =
          (static_cast<std::size_t>(packet[offset + 1U]) + 2U) * 4U;
      if (extension_length < 16U || (extension_length & 7U) != 0U)
        return std::nullopt;
      view.authentication_header_present = true;
    } else {
      break;
    }
    if (extension_length == 0U || offset + extension_length > packet_end)
      return std::nullopt;
    current_next_header_offset = offset;
    current = packet[offset];
    offset += extension_length;
    // A non-first fragment begins at an arbitrary point in the Fragmentable
    // Part. Its first payload octets must never be interpreted as another
    // extension header merely because Fragment.NextHeader has that value.
    if (view.fragment && view.fragment->offset != 0U)
      break;
  }
  view.upper_layer_protocol = current;
  view.upper_layer_offset = static_cast<std::uint16_t>(offset);
  view.upper_layer_next_header_offset =
      static_cast<std::uint16_t>(current_next_header_offset);
  return view;
}

std::optional<Ipv6View> parse_ipv6(const Frame &frame) noexcept {
  // Frame::view exposes exactly the bytes retained by the link packet pool.
  // The shared parser also serves a larger destination-reassembly buffer.
  return parse_ipv6(frame.view());
}

std::optional<Ipv6View>
parse_ipv6_quote(std::span<const std::uint8_t> quote) noexcept {
  // An ICMPv6 error must include the invoking fixed header and enough payload
  // to identify the upper-layer transaction. Payload Length describes the
  // original packet, so unlike parse_ipv6() the quote need not retain all of
  // those bytes.
  if (quote.size() < ipv6_header_octets + 8U ||
      (quote[0U] >> 4U) != 6U)
    return std::nullopt;
  const auto payload_length =
      static_cast<std::uint16_t>((quote[4U] << 8U) | quote[5U]);
  if (payload_length < 8U)
    return std::nullopt;

  Ipv6View view{
      .flow_label = static_cast<std::uint32_t>(((quote[1U] & 0x0fU) << 16U) |
                                               (quote[2U] << 8U) | quote[3U]),
      .payload_length = payload_length,
      .upper_layer_offset = ipv6_header_octets,
      .upper_layer_next_header_offset = 6U,
      .traffic_class = static_cast<std::uint8_t>(
          ((quote[0U] & 0x0fU) << 4U) | (quote[1U] >> 4U)),
      .next_header = quote[6U],
      .upper_layer_protocol = quote[6U],
      .hop_limit = quote[7U]};
  std::copy_n(quote.begin() + 8U, 16U, view.source.begin());
  std::copy_n(quote.begin() + 24U, 16U, view.destination.begin());

  const auto original_end = ipv6_header_octets +
                            static_cast<std::size_t>(payload_length);
  const auto quoted_end = std::min(original_end, quote.size());
  std::size_t offset = ipv6_header_octets;
  auto current = view.next_header;
  std::size_t current_next_header_offset = 6U;
  bool fragment_seen{};
  for (;;) {
    std::size_t extension_length{};
    if (current == 0U || current == 43U || current == 60U) {
      if ((current == 0U && offset != ipv6_header_octets) ||
          offset + 2U > quoted_end)
        return std::nullopt;
      extension_length =
          (static_cast<std::size_t>(quote[offset + 1U]) + 1U) * 8U;
    } else if (current == 44U) {
      if (fragment_seen || offset + 8U > quoted_end)
        return std::nullopt;
      fragment_seen = true;
      view.fragment_previous_next_header_offset =
          static_cast<std::uint16_t>(current_next_header_offset);
      const auto field = static_cast<std::uint16_t>(
          (quote[offset + 2U] << 8U) | quote[offset + 3U]);
      view.fragment = Ipv6FragmentView{
          .identification =
              static_cast<std::uint32_t>(quote[offset + 4U]) << 24U |
              static_cast<std::uint32_t>(quote[offset + 5U]) << 16U |
              static_cast<std::uint32_t>(quote[offset + 6U]) << 8U |
              quote[offset + 7U],
          .offset = static_cast<std::uint16_t>((field >> 3U) & 0x1fffU),
          .more_fragments = (field & 1U) != 0U};
      view.fragment_header_offset = static_cast<std::uint16_t>(offset);
      extension_length = 8U;
    } else if (current == 51U) {
      if (offset + 2U > quoted_end)
        return std::nullopt;
      extension_length =
          (static_cast<std::size_t>(quote[offset + 1U]) + 2U) * 4U;
      if (extension_length < 16U || (extension_length & 7U) != 0U)
        return std::nullopt;
      view.authentication_header_present = true;
    } else {
      break;
    }
    if (!extension_length || offset + extension_length > quoted_end)
      return std::nullopt;
    current_next_header_offset = offset;
    current = quote[offset];
    offset += extension_length;
    // A non-first fragment quotes fragment data, not an upper-layer header.
    // Return no correlation view instead of interpreting arbitrary bytes.
    if (view.fragment && view.fragment->offset != 0U)
      return std::nullopt;
  }
  if (offset + 8U > quoted_end)
    return std::nullopt;
  view.upper_layer_protocol = current;
  view.upper_layer_offset = static_cast<std::uint16_t>(offset);
  view.upper_layer_next_header_offset =
      static_cast<std::uint16_t>(current_next_header_offset);
  return view;
}

std::optional<IcmpView>
parse_icmp(std::span<const std::uint8_t> packet) noexcept {
  const auto ip = parse_ipv4(packet);
  // ICMP checksum spans the complete reassembled message. Individual IPv4
  // fragments are valid IPv4 but cannot be parsed as ICMP until EndpointStack
  // has reassembled them.
  if (!ip || ip->protocol != 1 || ip->fragment_offset || ip->more_fragments)
    return std::nullopt;
  const auto header_length = static_cast<std::size_t>(packet[14] & 0x0fU) * 4U;
  const auto icmp_length =
      static_cast<std::size_t>(ip->total_length) - header_length;
  const auto offset = 14U + header_length;
  if (icmp_length < 8 ||
      checksum(packet.subspan(offset, icmp_length)) != 0) {
    return std::nullopt;
  }
  return IcmpView{
      .type = packet[offset],
      .code = packet[offset + 1],
      .parameter = static_cast<std::uint32_t>(packet[offset + 4]) << 24U |
                   static_cast<std::uint32_t>(packet[offset + 5]) << 16U |
                   static_cast<std::uint32_t>(packet[offset + 6]) << 8U |
                   packet[offset + 7],
      .identifier = static_cast<std::uint16_t>(packet[offset + 4] << 8 |
                                               packet[offset + 5]),
      .sequence = static_cast<std::uint16_t>(packet[offset + 6] << 8 |
                                             packet[offset + 7]),
      .data = packet.subspan(offset + 8, icmp_length - 8),
  };
}

std::optional<IcmpView> parse_icmp(const Frame &frame) noexcept {
  return parse_icmp(frame.view());
}

std::optional<Icmpv6View>
parse_icmpv6(std::span<const std::uint8_t> packet) noexcept {
  const auto ipv6 = parse_ipv6(packet);
  // Non-first fragments cannot contain the beginning of an ICMPv6 message.
  // First fragments with M=1 also require endpoint reassembly before checksum
  // validation because the checksum covers the complete original message.
  if (!ipv6 || ipv6->authentication_header_present ||
      ipv6->upper_layer_protocol != ipv6_next_header_icmpv6 ||
      (ipv6->fragment &&
       (ipv6->fragment->offset != 0U || ipv6->fragment->more_fragments)))
    return std::nullopt;
  const auto packet_end = 54U + static_cast<std::size_t>(ipv6->payload_length);
  const auto offset = static_cast<std::size_t>(ipv6->upper_layer_offset);
  if (offset + 8U > packet_end)
    return std::nullopt;
  const auto icmp_length = packet_end - offset;
  const auto bytes = packet.subspan(offset, icmp_length);
  if (ipv6_upper_layer_checksum(ipv6->source, ipv6->destination,
                                ipv6_next_header_icmpv6, bytes) !=
      0U)
    return std::nullopt;
  return Icmpv6View{
      .type = packet[offset],
      .code = packet[offset + 1U],
      .parameter = static_cast<std::uint32_t>(packet[offset + 4U]) << 24U |
                   static_cast<std::uint32_t>(packet[offset + 5U]) << 16U |
                   static_cast<std::uint32_t>(packet[offset + 6U]) << 8U |
                   packet[offset + 7U],
      .identifier = static_cast<std::uint16_t>((packet[offset + 4U] << 8U) |
                                               packet[offset + 5U]),
      .sequence = static_cast<std::uint16_t>((packet[offset + 6U] << 8U) |
                                             packet[offset + 7U]),
      .data = packet.subspan(offset + 8U, icmp_length - 8U)};
}

std::optional<Icmpv6View> parse_icmpv6(const Frame &frame) noexcept {
  return parse_icmpv6(frame.view());
}

Mac ipv6_multicast_mac(Ipv6 destination) noexcept {
  // RFC 2464 maps the low-order 32 IPv6 bits after the fixed 33:33 prefix. The
  // caller must separately verify multicast membership before delivery.
  return Mac{0x33, 0x33, destination[12], destination[13], destination[14],
             destination[15]};
}

void rewrite_ethernet(Frame &frame, Mac source_mac,
                      Mac destination_mac) noexcept {
  // Routing changes only the per-hop L2 envelope. IP bytes, including source,
  // destination and payload, remain owned by the IPv4 forwarding operation.
  std::copy(destination_mac.begin(), destination_mac.end(),
            frame.bytes.begin());
  std::copy(source_mac.begin(), source_mac.end(), frame.bytes.begin() + 6);
}

std::optional<Frame> icmp_echo_reply(const Frame &request, Mac source_mac,
                                     Mac destination_mac) noexcept {
  // Source: ietf.icmp.rfc792. Echo Reply preserves identifier, sequence and
  // data from the received request. It is never manufactured from out-of-band
  // parameters by the receiving endpoint.
  const auto ip = parse_ipv4(request);
  const auto icmp = parse_icmp(request);
  if (!ip || !icmp || icmp->type != 8 || icmp->code != 0)
    return std::nullopt;
  Frame reply;
  copy_frame(reply, request);
  rewrite_ethernet(reply, source_mac, destination_mac);
  std::copy(ip->destination.begin(), ip->destination.end(),
            reply.bytes.begin() + 26);
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
  const auto icmp_length =
      static_cast<std::size_t>(ip->total_length) - header_length;
  reply.bytes[icmp_offset] = 0;
  reply.bytes[icmp_offset + 2] = 0;
  reply.bytes[icmp_offset + 3] = 0;
  const auto icmp_checksum =
      checksum(reply.view().subspan(icmp_offset, icmp_length));
  reply.bytes[icmp_offset + 2] = static_cast<std::uint8_t>(icmp_checksum >> 8);
  reply.bytes[icmp_offset + 3] = static_cast<std::uint8_t>(icmp_checksum);
  return reply;
}

namespace {

std::optional<Frame> icmpv6_error(std::span<const std::uint8_t> original,
                                  Mac source_mac,
                                  Mac destination_mac, Ipv6 source_ip,
                                  Ipv6 destination_ip, std::uint8_t type,
                                  std::uint8_t code,
                                  std::uint32_t parameter) noexcept {
  const auto original_ip = parse_ipv6(original);
  if (!original_ip)
    return std::nullopt;
  // RFC 4443 requires the complete invoking packet without exceeding the IPv6
  // minimum MTU. The named codec constants keep this envelope tied to the
  // same network-layer MTU contract used by forwarding.
  constexpr std::size_t icmpv6_error_header_octets = 8U;
  constexpr std::size_t maximum_quote =
      ipv6_minimum_link_mtu - ipv6_header_octets -
      icmpv6_error_header_octets;
  const auto original_octets =
      ipv6_header_octets +
      static_cast<std::size_t>(original_ip->payload_length);
  const auto quoted = std::min(original_octets, maximum_quote);
  std::array<std::uint8_t, 4U + maximum_quote> body{};
  body[0] = static_cast<std::uint8_t>(parameter >> 24U);
  body[1] = static_cast<std::uint8_t>(parameter >> 16U);
  body[2] = static_cast<std::uint8_t>(parameter >> 8U);
  body[3] = static_cast<std::uint8_t>(parameter);
  std::copy_n(original.begin() + ethernet_header_octets, quoted,
              body.begin() + 4);
  Frame result;
  icmpv6_message_into(
      result, source_mac, destination_mac, source_ip, destination_ip, type,
      code, std::span<const std::uint8_t>{body.data(), 4U + quoted},
      device_catalog::default_ip_hop_limit);
  return result.length ? std::optional<Frame>{result} : std::nullopt;
}

std::optional<Frame> icmpv4_error(
    std::span<const std::uint8_t> original, Mac source_mac,
    Mac destination_mac, Ipv4 source_ip, Ipv4 destination_ip,
    std::uint8_t type, std::uint8_t code) noexcept {
  const auto original_ip = parse_ipv4(original);
  if (!original_ip)
    return std::nullopt;
  // RFC 792 requires the original header plus its first 64 data bits. Fragment
  // zero is therefore sufficient for both transit expiry and reassembly expiry.
  const auto quoted = std::min<std::size_t>(
      original_ip->total_length,
      static_cast<std::size_t>(original_ip->header_length) + 8U);
  Frame result;
  auto out = ethernet(result, destination_mac, source_mac, ethernet_type_ipv4);
  const auto ip_start = out.position();
  out.put(0x45U);
  out.put(0U);
  out.put16(static_cast<std::uint16_t>(20U + 8U + quoted));
  out.put16(0U);
  out.put16(0U);
  out.put(device_catalog::default_ip_hop_limit);
  out.put(1U);
  out.put16(0U);
  out.append(source_ip);
  out.append(destination_ip);
  out.patch16(ip_start + 10U, checksum(out.span(ip_start, 20U)));
  const auto icmp_start = out.position();
  out.put(type);
  out.put(code);
  out.put16(0U);
  out.put16(0U);
  out.put16(0U);
  for (std::size_t index = 0U; index < quoted; ++index)
    out.put(original[ethernet_header_octets + index]);
  out.patch16(icmp_start + 2U,
              checksum(out.span(icmp_start, 8U + quoted)));
  out.finish();
  return result;
}

} // namespace

std::optional<Frame> icmpv6_time_exceeded(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip) noexcept {
  // Type 3 code 0 reports Hop Limit exhaustion in transit. The unused field is
  // transmitted as zero and the received invoking packet is quoted verbatim.
  return icmpv6_error(original.view(), source_mac, destination_mac, source_ip,
                      destination_ip, icmpv6_time_exceeded_type, 0, 0);
}

std::optional<Frame> icmpv6_packet_too_big(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip, std::uint32_t mtu) noexcept {
  // Type 2 always uses code zero and carries the next-hop MTU as a full 32-bit
  // value. The forwarding owner supplies the actual IPv6 MTU after removing
  // the Ethernet envelope from its port MTU.
  return icmpv6_error(original.view(), source_mac, destination_mac, source_ip,
                       destination_ip, icmpv6_packet_too_big_type, 0, mtu);
}

std::optional<Frame> icmpv6_destination_unreachable(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip, std::uint8_t code) noexcept {
  return icmpv6_destination_unreachable(
      original.view(), source_mac, destination_mac, source_ip,
      destination_ip, code);
}

std::optional<Frame> icmpv6_destination_unreachable(
    std::span<const std::uint8_t> original, Mac source_mac,
    Mac destination_mac, Ipv6 source_ip, Ipv6 destination_ip,
    std::uint8_t code) noexcept {
  // RFC 4443 currently assigns codes zero through six. Unknown codes are not
  // emitted by this codec because doing so would fabricate an unregistered
  // diagnostic even when a caller passes an invalid control value.
  if (code > 6U)
    return std::nullopt;
  return icmpv6_error(original, source_mac, destination_mac, source_ip,
                      destination_ip, icmpv6_destination_unreachable_type,
                      code, 0U);
}

std::optional<Frame> icmpv6_parameter_problem(
    const Frame &original, Mac source_mac, Mac destination_mac, Ipv6 source_ip,
    Ipv6 destination_ip, std::uint8_t code, std::uint32_t pointer) noexcept {
  // Codes zero through two cover erroneous header fields, unrecognized Next
  // Header and unrecognized options. The pointer is relative to the IPv6
  // header, as required on the wire, not to the Ethernet frame.
  if (code > 2U)
    return std::nullopt;
  return icmpv6_error(original.view(), source_mac, destination_mac, source_ip,
                      destination_ip, icmpv6_parameter_problem_type, code,
                      pointer);
}

std::optional<Frame> icmpv6_echo_reply(const Frame &request, Mac source_mac,
                                       Mac destination_mac) noexcept {
  // RFC 4443 requires an Echo Reply to preserve request data, identifier and
  // sequence while reversing IPv6 addresses. Constructing from received wire
  // bytes proves there is no direct object exchange between endpoints.
  const auto ipv6 = parse_ipv6(request);
  const auto icmp = parse_icmpv6(request);
  if (!ipv6 || !icmp || icmp->type != icmpv6_echo_request_type ||
      icmp->code != 0U)
    return std::nullopt;
  Frame reply;
  copy_frame(reply, request);
  rewrite_ethernet(reply, source_mac, destination_mac);
  std::copy(ipv6->destination.begin(), ipv6->destination.end(),
            reply.bytes.begin() + 22);
  std::copy(ipv6->source.begin(), ipv6->source.end(),
            reply.bytes.begin() + 38);
  // A reply is newly originated and therefore starts with the endpoint's
  // default hop limit instead of inheriting the request's remaining value.
  reply.bytes[21] = device_catalog::default_ip_hop_limit;
  const auto offset = static_cast<std::size_t>(ipv6->upper_layer_offset);
  const auto icmp_length = 54U + ipv6->payload_length - offset;
  reply.bytes[offset] = icmpv6_echo_reply_type;
  reply.bytes[offset + 2U] = 0;
  reply.bytes[offset + 3U] = 0;
  const auto updated = ipv6_upper_layer_checksum(
      ipv6->destination, ipv6->source, ipv6_next_header_icmpv6,
      reply.view().subspan(offset, icmp_length));
  reply.bytes[offset + 2U] = static_cast<std::uint8_t>(updated >> 8U);
  reply.bytes[offset + 3U] = static_cast<std::uint8_t>(updated);
  return reply;
}

// The generated error uses source then destination consistently for both L2
// and L3. Reversing the IPv4 order here would create an invalid reply path.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
std::optional<Frame> icmp_time_exceeded(const Frame &original, Mac source_mac,
                                        Mac destination_mac, Ipv4 source_ip,
                                        Ipv4 destination_ip) noexcept {
  // Code zero reports TTL expiry while a router forwards the datagram.
  return icmpv4_error(original.view(), source_mac, destination_mac, source_ip,
                      destination_ip, 11U, 0U);
}

std::optional<Frame> icmp_reassembly_time_exceeded(
    const Frame &first_fragment, Mac source_mac, Mac destination_mac,
    Ipv4 source_ip, Ipv4 destination_ip) noexcept {
  // Code one is emitted only by a destination whose fixed reassembly timer
  // expired after receiving fragment zero, as required by RFC 1122 section 3.3.2.
  return icmpv4_error(first_fragment.view(), source_mac, destination_mac,
                      source_ip, destination_ip, 11U, 1U);
}

std::optional<Frame> icmp_network_unreachable(
    const Frame &original, Mac source_mac, Mac destination_mac,
    Ipv4 source_ip, Ipv4 destination_ip) noexcept {
  // RFC 1812 sections 4.3.3.1 and 5.2.7.1 require type 3 code 0 when a
  // forwarding router has no route to the destination. Reusing the common
  // error encoder preserves the original IP header and first 64 data bits.
  return icmpv4_error(original.view(), source_mac, destination_mac, source_ip,
                      destination_ip, 3U, 0U);
}

std::optional<Frame> icmp_protocol_unreachable(
    std::span<const std::uint8_t> original, Mac source_mac,
    Mac destination_mac, Ipv4 source_ip, Ipv4 destination_ip) noexcept {
  // RFC 792 and RFC 1812 assign code 2 to an otherwise valid local datagram
  // whose IP Protocol value has no receiving transport implementation.
  return icmpv4_error(original, source_mac, destination_mac, source_ip,
                      destination_ip, 3U, 2U);
}

std::optional<Frame> icmp_port_unreachable(
    std::span<const std::uint8_t> original, Mac source_mac,
    Mac destination_mac, Ipv4 source_ip, Ipv4 destination_ip) noexcept {
  // RFC 792 assigns Destination Unreachable code 3 to a closed destination
  // port. A span lets a full reassembled UDP datagram be quoted directly.
  return icmpv4_error(original, source_mac, destination_mac, source_ip,
                      destination_ip, 3U, 3U);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

std::optional<Frame>
icmp_fragmentation_needed(const Frame &original, Mac source_mac,
                          Mac destination_mac, Ipv4 source_ip,
                          Ipv4 destination_ip, std::uint16_t mtu) noexcept {
  // RFC 792 type 3 code 4 plus RFC 1191 require the next-hop MTU in the low
  // 16 bits of the formerly unused field. The quoted bytes are the original
  // IPv4 header and at least its first eight payload octets.
  const auto original_ip = parse_ipv4(original);
  if (!original_ip)
    return std::nullopt;
  const auto quoted = std::min<std::size_t>(
      original_ip->total_length,
      static_cast<std::size_t>(original_ip->header_length) + 8U);
  Frame result;
  auto out = ethernet(result, destination_mac, source_mac, 0x0800);
  const auto ip_start = out.position();
  out.put(0x45);
  out.put(0);
  out.put16(static_cast<std::uint16_t>(28U + quoted));
  out.put16(0);
  out.put16(0);
  out.put(64);
  out.put(1);
  out.put16(0);
  out.append(source_ip);
  out.append(destination_ip);
  out.patch16(ip_start + 10, checksum(out.span(ip_start, 20)));
  const auto icmp_start = out.position();
  out.put(3);
  out.put(4);
  out.put16(0);
  out.put16(0);
  out.put16(mtu);
  for (std::size_t index = 0; index < quoted; ++index)
    out.put(original[14U + index]);
  out.patch16(icmp_start + 2, checksum(out.span(icmp_start, 8U + quoted)));
  out.finish();
  return result;
}

std::optional<Frame> icmp_host_redirect(
    const Frame &original, Mac source_mac, Mac destination_mac,
    Ipv4 source_ip, Ipv4 destination_ip, Ipv4 gateway) noexcept {
  const auto original_ip = parse_ipv4(original);
  if (!original_ip)
    return std::nullopt;
  const auto quoted = std::min<std::size_t>(
      original_ip->total_length,
      static_cast<std::size_t>(original_ip->header_length) + 8U);
  Frame result;
  auto out = ethernet(result, destination_mac, source_mac, ethernet_type_ipv4);
  const auto ip_start = out.position();
  out.put(0x45U);
  out.put(0U);
  out.put16(static_cast<std::uint16_t>(28U + quoted));
  out.put16(0U);
  out.put16(0U);
  out.put(device_catalog::default_ip_hop_limit);
  out.put(1U);
  out.put16(0U);
  out.append(source_ip);
  out.append(destination_ip);
  out.patch16(ip_start + 10U, checksum(out.span(ip_start, 20U)));
  const auto icmp_start = out.position();
  out.put(5U);
  out.put(1U);
  out.put16(0U);
  out.append(gateway);
  for (std::size_t index = 0U; index < quoted; ++index)
    out.put(original.bytes[ethernet_header_octets + index]);
  out.patch16(icmp_start + 2U,
              checksum(out.span(icmp_start, 8U + quoted)));
  out.finish();
  return result.length ? std::optional<Frame>{result} : std::nullopt;
}

bool ipv4_has_source_route(const Frame &frame,
                           const Ipv4View &ipv4) noexcept {
  std::size_t offset = 20U;
  while (offset < ipv4.header_length) {
    const auto type = frame.bytes[ethernet_header_octets + offset];
    if (type == 0U)
      return false;
    if (type == 1U) {
      ++offset;
      continue;
    }
    if (offset + 2U > ipv4.header_length)
      return false;
    const auto length = static_cast<std::size_t>(
        frame.bytes[ethernet_header_octets + offset + 1U]);
    if (length < 2U || offset + length > ipv4.header_length)
      return false;
    // Option numbers 3 and 9 are LSRR and SSRR. The copied and class bits are
    // part of their complete wire type values 131 and 137 respectively.
    if (type == 131U || type == 137U)
      return true;
    offset += length;
  }
  return false;
}

bool route_ipv4_into(Frame &egress, const Frame &ingress, Mac source_mac,
                     Mac destination_mac) noexcept {
  // Source: ietf.ipv4.router_requirements.rfc1812. The forwarding caller must
  // turn ttl <= 1 into ICMP Time Exceeded before invoking this rewrite.
  const auto parsed = parse_ipv4(ingress);
  if (!parsed || parsed->ttl <= 1)
    return false;
  // Preserve the original IP packet and payload. A router changes only the
  // Ethernet adjacency and IPv4 hop fields for this basic forwarding path.
  copy_frame(egress, ingress);
  rewrite_ethernet(egress, source_mac, destination_mac);
  const auto header_length =
      static_cast<std::size_t>(egress[14] & 0x0fU) * 4U;
  --egress.bytes[22];
  egress.bytes[24] = 0;
  egress.bytes[25] = 0;
  const auto updated = checksum(egress.view().subspan(14, header_length));
  egress.bytes[24] = static_cast<std::uint8_t>(updated >> 8);
  egress.bytes[25] = static_cast<std::uint8_t>(updated);
  return true;
}

std::optional<Frame> route_ipv4(const Frame &ingress, Mac source_mac,
                                Mac destination_mac) noexcept {
  std::optional<Frame> result{std::in_place};
  if (!route_ipv4_into(*result, ingress, source_mac, destination_mac))
    return std::nullopt;
  return result;
}

bool route_ipv6_into(Frame &egress, const Frame &ingress, Mac source_mac,
                     Mac destination_mac) noexcept {
  // RFC 8200 routers decrement Hop Limit exactly once and discard a packet
  // whose value would reach zero. Unlike IPv4 there is no header checksum to
  // update, so the complete payload and extension chain remain byte-identical.
  const auto parsed = parse_ipv6(ingress);
  if (!parsed || parsed->hop_limit <= 1U)
    return false;
  copy_frame(egress, ingress);
  rewrite_ethernet(egress, source_mac, destination_mac);
  --egress.bytes[21];
  return true;
}

std::optional<Frame> route_ipv6(const Frame &ingress, Mac source_mac,
                                Mac destination_mac) noexcept {
  std::optional<Frame> result{std::in_place};
  if (!route_ipv6_into(*result, ingress, source_mac, destination_mac))
    return std::nullopt;
  return result;
}

std::optional<FragmentBatch> fragment_ipv4(const Frame &routed,
                                           std::uint16_t mtu) noexcept {
  // RFC 791 fragment offsets count eight-octet units. All non-final payloads
  // therefore use the largest multiple of eight that fits the egress MTU.
  // The caller has already decremented TTL exactly once in route_ipv4().
  const auto ip = parse_ipv4(routed);
  if (!ip || ip->dont_fragment || ip->fragment_offset ||
      ip->total_length <= mtu || mtu <= ip->header_length)
    return std::nullopt;
  const auto fragment_payload =
      static_cast<std::size_t>((mtu - ip->header_length) & ~7U);
  const auto payload_length =
      static_cast<std::size_t>(ip->total_length - ip->header_length);
  if (!fragment_payload)
    return std::nullopt;
  FragmentBatch result;
  for (std::size_t offset = 0; offset < payload_length;
       offset += fragment_payload) {
    if (result.count == result.frames.size())
      return std::nullopt;
    const auto length = std::min(fragment_payload, payload_length - offset);
    Frame fragment{};
    std::copy_n(routed.bytes.begin(), 14U + ip->header_length,
                fragment.bytes.begin());
    std::copy_n(routed.bytes.begin() + 14U + ip->header_length + offset,
                length,
                fragment.bytes.begin() + 14U + ip->header_length);
    const auto total = static_cast<std::uint16_t>(ip->header_length + length);
    fragment.bytes[16] = static_cast<std::uint8_t>(total >> 8);
    fragment.bytes[17] = static_cast<std::uint8_t>(total);
    const auto more = offset + length < payload_length || ip->more_fragments;
    const auto fragment_field = static_cast<std::uint16_t>(
        (more ? 0x2000U : 0U) | (offset / 8U));
    fragment.bytes[20] = static_cast<std::uint8_t>(fragment_field >> 8);
    fragment.bytes[21] = static_cast<std::uint8_t>(fragment_field);
    fragment.bytes[24] = 0;
    fragment.bytes[25] = 0;
    const auto header_checksum = checksum(std::span<const std::uint8_t>(
        fragment.bytes.data() + 14U, ip->header_length));
    fragment.bytes[24] = static_cast<std::uint8_t>(header_checksum >> 8);
    fragment.bytes[25] = static_cast<std::uint8_t>(header_checksum);
    fragment.length = static_cast<std::uint16_t>(14U + total);
    while (fragment.length < 60U)
      fragment.bytes[fragment.length++] = 0;
    result.frames[result.count++] = fragment;
  }
  return result.count ? std::optional<FragmentBatch>{result} : std::nullopt;
}

std::optional<std::size_t> fragment_ipv4_forwarded(
    const Frame &input, std::uint16_t mtu, void *context,
    Ipv4FragmentSink sink) noexcept {
  const auto ip = parse_ipv4(input);
  if (!ip || !sink || ip->dont_fragment || ip->total_length <= mtu ||
      mtu > maximum_network_ip_mtu)
    return std::nullopt;

  const auto input_header = static_cast<std::size_t>(ip->header_length);
  const auto input_payload =
      static_cast<std::size_t>(ip->total_length) - input_header;
  // Every fragment that advertises another fragment must end on the eight-byte
  // unit used by Fragment Offset. Rejecting an invalid invoking fragment here
  // prevents offset drift when a smaller downstream MTU requires refragmenting
  // it again.
  if (ip->more_fragments && (input_payload % 8U) != 0U)
    return std::nullopt;

  // RFC 791 option type bit 7 is the copied flag. Walk the complete option
  // area without interpreting individual option bodies, but validate their
  // universal type-length envelope. EOL terminates the list and the newly
  // generated header uses zero padding to its next 32-bit boundary.
  std::array<std::uint8_t, 40U> copied_options{};
  std::size_t copied_octets{};
  std::size_t option_offset = 20U;
  while (option_offset < input_header) {
    const auto type = input.bytes[ethernet_header_octets + option_offset];
    if (type == 0U)
      break;
    if (type == 1U) {
      ++option_offset;
      continue;
    }
    if (option_offset + 2U > input_header)
      return std::nullopt;
    const auto length = static_cast<std::size_t>(
        input.bytes[ethernet_header_octets + option_offset + 1U]);
    if (length < 2U || option_offset + length > input_header)
      return std::nullopt;
    if ((type & 0x80U) != 0U) {
      if (copied_octets + length > copied_options.size())
        return std::nullopt;
      std::copy_n(input.bytes.begin() +
                      static_cast<std::ptrdiff_t>(ethernet_header_octets +
                                                  option_offset),
                  length,
                  copied_options.begin() +
                      static_cast<std::ptrdiff_t>(copied_octets));
      copied_octets += length;
    }
    option_offset += length;
  }
  const auto copied_header = static_cast<std::size_t>(
      20U + ((copied_octets + 3U) & ~std::size_t{3U}));

  std::size_t emitted{};
  for (std::size_t payload_offset = 0U; payload_offset < input_payload;) {
    // Only fragment zero of the original datagram keeps non-copied options.
    // Refragmenting a nonzero fragment always uses the copied option image.
    const bool original_fragment_zero =
        ip->fragment_offset == 0U && payload_offset == 0U;
    const auto output_header =
        original_fragment_zero ? input_header : copied_header;
    if (mtu <= output_header)
      return std::nullopt;
    const auto available = static_cast<std::size_t>(mtu) - output_header;
    const auto remaining = input_payload - payload_offset;
    const bool must_leave_more = remaining > available || ip->more_fragments;
    const auto payload_octets = must_leave_more
                                    ? std::min(remaining, available & ~7U)
                                    : remaining;
    if (payload_octets == 0U)
      return std::nullopt;

    Frame fragment;
    std::copy_n(input.bytes.begin(), ethernet_header_octets + 20U,
                fragment.bytes.begin());
    if (original_fragment_zero) {
      std::copy_n(input.bytes.begin() +
                      static_cast<std::ptrdiff_t>(ethernet_header_octets + 20U),
                  input_header - 20U,
                  fragment.bytes.begin() +
                      static_cast<std::ptrdiff_t>(ethernet_header_octets +
                                                  20U));
    } else {
      std::copy_n(copied_options.begin(), copied_octets,
                  fragment.bytes.begin() +
                      static_cast<std::ptrdiff_t>(ethernet_header_octets +
                                                  20U));
      std::fill(fragment.bytes.begin() +
                    static_cast<std::ptrdiff_t>(ethernet_header_octets + 20U +
                                                copied_octets),
                fragment.bytes.begin() +
                    static_cast<std::ptrdiff_t>(ethernet_header_octets +
                                                copied_header),
                std::uint8_t{0U});
    }
    fragment.bytes[ethernet_header_octets] = static_cast<std::uint8_t>(
        0x40U | static_cast<std::uint8_t>(output_header / 4U));
    const auto total = static_cast<std::uint16_t>(output_header +
                                                  payload_octets);
    fragment.bytes[16U] = static_cast<std::uint8_t>(total >> 8U);
    fragment.bytes[17U] = static_cast<std::uint8_t>(total);
    const bool more = payload_offset + payload_octets < input_payload ||
                      ip->more_fragments;
    const auto offset_units = static_cast<std::uint32_t>(ip->fragment_offset) +
                              payload_offset / 8U;
    if (offset_units > 0x1fffU)
      return std::nullopt;
    const auto fragment_field = static_cast<std::uint16_t>(
        (more ? 0x2000U : 0U) | offset_units);
    fragment.bytes[20U] = static_cast<std::uint8_t>(fragment_field >> 8U);
    fragment.bytes[21U] = static_cast<std::uint8_t>(fragment_field);
    std::copy_n(input.bytes.begin() +
                    static_cast<std::ptrdiff_t>(ethernet_header_octets +
                                                input_header + payload_offset),
                payload_octets,
                fragment.bytes.begin() +
                    static_cast<std::ptrdiff_t>(ethernet_header_octets +
                                                output_header));
    fragment.bytes[24U] = 0U;
    fragment.bytes[25U] = 0U;
    const auto header_checksum = checksum(std::span<const std::uint8_t>(
        fragment.bytes.data() + ethernet_header_octets, output_header));
    fragment.bytes[24U] = static_cast<std::uint8_t>(header_checksum >> 8U);
    fragment.bytes[25U] = static_cast<std::uint8_t>(header_checksum);
    const auto unpadded = ethernet_header_octets + total;
    fragment.length = static_cast<std::uint16_t>(std::max<std::size_t>(
        unpadded, ethernet_minimum_without_fcs));
    std::fill(fragment.bytes.begin() + static_cast<std::ptrdiff_t>(unpadded),
              fragment.bytes.begin() +
                  static_cast<std::ptrdiff_t>(fragment.length),
              std::uint8_t{0U});
    if (!sink(context, fragment))
      return std::nullopt;
    ++emitted;
    payload_offset += payload_octets;
  }
  return emitted ? std::optional<std::size_t>{emitted} : std::nullopt;
}

std::optional<std::size_t>
ipv4_fragment_count(std::span<const std::uint8_t> packet,
                    std::uint16_t mtu) noexcept {
  // This path is intentionally limited to a source-created datagram with the
  // fixed twenty-octet header emitted by encode_ipv4_ethernet_datagram(). An
  // intermediate router may need to copy only IPv4 options whose copied flag
  // is set, so treating an arbitrary option-bearing packet as this simple
  // layout would silently violate RFC 791.
  const auto ip = parse_ipv4(packet);
  if (!ip || ip->header_length != 20U || ip->dont_fragment ||
      ip->fragment_offset != 0U || ip->more_fragments ||
      ip->total_length <= mtu || mtu <= ip->header_length ||
      mtu > maximum_network_ip_mtu) {
    return std::nullopt;
  }

  // Every fragment except the last carries the largest possible payload that
  // is an exact multiple of the eight-octet Fragment Offset unit. Computing
  // the count before emission lets a bounded egress owner reserve the entire
  // batch, preventing half a UDP datagram from entering the modeled link.
  const auto fragment_payload =
      static_cast<std::size_t>((mtu - ip->header_length) & ~7U);
  if (fragment_payload == 0U)
    return std::nullopt;
  const auto payload_length =
      static_cast<std::size_t>(ip->total_length - ip->header_length);
  return (payload_length + fragment_payload - 1U) / fragment_payload;
}

std::optional<std::size_t> fragment_ipv4_datagram(
    std::span<const std::uint8_t> packet, std::uint16_t mtu,
    void *context, Ipv4FragmentSink sink) noexcept {
  const auto count = ipv4_fragment_count(packet, mtu);
  const auto ip = parse_ipv4(packet);
  if (!count || !ip || sink == nullptr)
    return std::nullopt;

  const auto header_length = static_cast<std::size_t>(ip->header_length);
  const auto payload_length =
      static_cast<std::size_t>(ip->total_length - ip->header_length);
  const auto fragment_payload =
      static_cast<std::size_t>((mtu - ip->header_length) & ~7U);
  std::size_t emitted{};
  for (std::size_t offset = 0U; offset < payload_length;
       offset += fragment_payload) {
    const auto length = std::min(fragment_payload, payload_length - offset);
    Frame fragment;

    // The Ethernet header and fixed IPv4 header are copied for every emitted
    // packet. Payload bytes are copied directly from the source-owned 65 KiB
    // image, so no Frame-sized truncation or temporary fragment batch exists.
    std::copy_n(packet.begin(), ethernet_header_octets + header_length,
                fragment.bytes.begin());
    std::copy_n(packet.begin() + ethernet_header_octets + header_length +
                    static_cast<std::ptrdiff_t>(offset),
                length,
                fragment.bytes.begin() + ethernet_header_octets +
                    static_cast<std::ptrdiff_t>(header_length));

    const auto total = static_cast<std::uint16_t>(header_length + length);
    fragment.bytes[16U] = static_cast<std::uint8_t>(total >> 8U);
    fragment.bytes[17U] = static_cast<std::uint8_t>(total);
    const auto more = offset + length < payload_length;
    const auto fragment_field = static_cast<std::uint16_t>(
        (more ? 0x2000U : 0U) | (offset / 8U));
    fragment.bytes[20U] = static_cast<std::uint8_t>(fragment_field >> 8U);
    fragment.bytes[21U] = static_cast<std::uint8_t>(fragment_field);
    fragment.bytes[24U] = 0U;
    fragment.bytes[25U] = 0U;
    const auto header_checksum = checksum(std::span<const std::uint8_t>(
        fragment.bytes.data() + ethernet_header_octets, header_length));
    fragment.bytes[24U] = static_cast<std::uint8_t>(header_checksum >> 8U);
    fragment.bytes[25U] = static_cast<std::uint8_t>(header_checksum);

    const auto unpadded_length = ethernet_header_octets + total;
    fragment.length = static_cast<std::uint16_t>(std::max<std::size_t>(
        unpadded_length, ethernet_minimum_without_fcs));
    std::fill(fragment.bytes.begin() +
                  static_cast<std::ptrdiff_t>(unpadded_length),
              fragment.bytes.begin() +
                   static_cast<std::ptrdiff_t>(fragment.length),
              std::uint8_t{0});

    // Sink rejection represents an ownership or capacity failure. Returning
    // no count makes it impossible for the caller to mistake a partial batch
    // for a successful IPv4 send.
    if (!sink(context, fragment))
      return std::nullopt;
    ++emitted;
  }
  return emitted == *count ? std::optional<std::size_t>{emitted}
                           : std::nullopt;
}

} // namespace router::packet
