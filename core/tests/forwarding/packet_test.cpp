// Wire-codec conformance tests validate lengths, checksums, routing rewrites,
// MTU errors, fragmentation and parser safety independently of device state.

#include "router/packet.hpp"
#include "router/generated_profile.hpp"

#include <stdexcept>
#include <vector>

void ipv4_forwarded_fragmentation_tests() {
  using namespace router::packet;
  const Mac source{0x02, 0, 0, 0, 0, 1};
  const Mac target{0x02, 0, 0, 0, 0, 2};
  const Ipv4 source_ip{192, 0, 2, 1};
  const Ipv4 target_ip{192, 0, 2, 2};

  // Forwarding fragmentation has a different option contract than source
  // fragmentation. Add one non-copied Record Route-shaped option and one
  // copied option, then prove that only fragment zero retains the former.
  // Refragment a nonzero result again to verify that offsets accumulate from
  // the invoking fragment rather than restarting at zero. This suite is kept
  // outside packet_tests so its Frame locals do not extend that already broad
  // WebAssembly test stack frame.
  const auto unmodified = icmp_echo(source, target, source_ip, target_ip,
                                    false, 91U, 64U, 1000U, false);
  const auto routed = route_ipv4(unmodified, target, source);
  if (!routed)
    throw std::runtime_error("IPv4 option fixture could not be routed");
  auto option_datagram = *routed;
  const auto option_input = parse_ipv4(option_datagram);
  if (!option_input)
    throw std::runtime_error("IPv4 option fixture was not parseable");
  constexpr std::size_t added_option_octets = 8U;
  const auto original_payload_begin =
      ethernet_header_octets + option_input->header_length;
  const auto original_packet_end =
      ethernet_header_octets + option_input->total_length;
  std::move_backward(
      option_datagram.bytes.begin() +
          static_cast<std::ptrdiff_t>(original_payload_begin),
      option_datagram.bytes.begin() +
          static_cast<std::ptrdiff_t>(original_packet_end),
      option_datagram.bytes.begin() +
          static_cast<std::ptrdiff_t>(original_packet_end +
                                      added_option_octets));
  option_datagram.bytes[14U] = 0x47U;
  option_datagram.bytes[34U] = 7U;
  option_datagram.bytes[35U] = 4U;
  option_datagram.bytes[36U] = 4U;
  option_datagram.bytes[37U] = 0U;
  option_datagram.bytes[38U] = 130U;
  option_datagram.bytes[39U] = 4U;
  option_datagram.bytes[40U] = 0xaaU;
  option_datagram.bytes[41U] = 0xbbU;
  const auto option_total = static_cast<std::uint16_t>(
      option_input->total_length + added_option_octets);
  option_datagram.bytes[16U] = static_cast<std::uint8_t>(option_total >> 8U);
  option_datagram.bytes[17U] = static_cast<std::uint8_t>(option_total);
  option_datagram.bytes[24U] = 0U;
  option_datagram.bytes[25U] = 0U;
  const auto option_checksum = checksum(
      option_datagram.view().subspan(ethernet_header_octets, 28U));
  option_datagram.bytes[24U] =
      static_cast<std::uint8_t>(option_checksum >> 8U);
  option_datagram.bytes[25U] = static_cast<std::uint8_t>(option_checksum);
  option_datagram.length = static_cast<std::uint16_t>(
      option_datagram.length + added_option_octets);

  std::vector<Frame> option_fragments;
  const auto collect_forwarded = +[](void *opaque,
                                     const Frame &fragment) noexcept {
    static_cast<std::vector<Frame> *>(opaque)->push_back(fragment);
    return true;
  };
  const auto option_fragment_count = fragment_ipv4_forwarded(
      option_datagram, 100U, &option_fragments, collect_forwarded);
  if (!option_fragment_count || option_fragments.size() < 3U ||
      *option_fragment_count != option_fragments.size())
    throw std::runtime_error("option-bearing IPv4 datagram did not fragment");
  std::uint16_t option_expected_offset{};
  for (std::size_t index = 0U; index < option_fragments.size(); ++index) {
    const auto view = parse_ipv4(option_fragments[index]);
    const auto expected_header = index == 0U ? 28U : 24U;
    if (!view || view->header_length != expected_header ||
        view->fragment_offset != option_expected_offset ||
        option_fragments[index].bytes[34U] !=
            static_cast<std::uint8_t>(index == 0U ? 7U : 130U))
      throw std::runtime_error(
          "IPv4 copied-option or fragment-offset semantics diverged");
    option_expected_offset = static_cast<std::uint16_t>(
        option_expected_offset +
        (view->total_length - view->header_length) / 8U);
  }

  std::vector<Frame> refragmented;
  const auto invoking = parse_ipv4(option_fragments[1U]);
  const auto refragment_count =
      invoking ? fragment_ipv4_forwarded(option_fragments[1U], 60U,
                                         &refragmented, collect_forwarded)
               : std::nullopt;
  if (!invoking || !refragment_count || refragmented.size() < 2U ||
      parse_ipv4(refragmented.front())->fragment_offset !=
          invoking->fragment_offset ||
      parse_ipv4(refragmented.back())->fragment_offset <=
          invoking->fragment_offset)
    throw std::runtime_error(
        "downstream IPv4 refragmentation restarted the incoming offset");
}

void packet_tests() {
  using namespace router::packet;
  const Mac source{0x02, 0, 0, 0, 0, 1};
  const Mac target{0x02, 0, 0, 0, 0, 2};
  const Ipv4 source_ip{192, 0, 2, 1};
  const Ipv4 target_ip{192, 0, 2, 2};

  // IPv6 Echo uses the RFC 4443 pseudo-header checksum and a 40-octet fixed
  // header. The ordinary 56-octet ping data therefore produces 118 captured
  // octets without Ethernet padding.
  const auto source_ipv6 = router::ip::parse_ipv6("2001:db8:1::1");
  const auto target_ipv6 = router::ip::parse_ipv6("2001:db8:1::2");
  if (!source_ipv6 || !target_ipv6)
    throw std::runtime_error("IPv6 packet test address setup failed");
  const auto echo6 = icmpv6_echo(
      source, target, *source_ipv6, *target_ipv6, false, 7, 64,
      router::profile::default_ping_payload_octets);
  const auto parsed_ipv6 = parse_ipv6(echo6);
  const auto parsed_icmpv6 = parse_icmpv6(echo6);
  if (echo6.size() != 118U || !parsed_ipv6 || !parsed_icmpv6 ||
      parsed_ipv6->source != *source_ipv6 ||
      parsed_ipv6->destination != *target_ipv6 ||
      parsed_ipv6->hop_limit != 64U ||
      parsed_ipv6->upper_layer_protocol != 58U ||
      parsed_icmpv6->type != 128U || parsed_icmpv6->sequence != 7U ||
      parsed_icmpv6->data.size() !=
          router::profile::default_ping_payload_octets) {
    throw std::runtime_error("IPv6 or ICMPv6 Echo encoding failed");
  }

  const auto reply6 = icmpv6_echo_reply(echo6, target, source);
  const auto reply6_ip = reply6 ? parse_ipv6(*reply6) : std::nullopt;
  const auto reply6_icmp = reply6 ? parse_icmpv6(*reply6) : std::nullopt;
  if (!reply6 || !reply6_ip || !reply6_icmp ||
      reply6_ip->source != *target_ipv6 ||
      reply6_ip->destination != *source_ipv6 ||
      reply6_icmp->type != 129U || reply6_icmp->sequence != 7U ||
      reply6_icmp->data.size() != parsed_icmpv6->data.size()) {
    throw std::runtime_error("ICMPv6 Echo Reply did not preserve wire state");
  }

  const auto routed6 = route_ipv6(echo6, target, source);
  if (!routed6 || (*routed6)[21] != 63U || !parse_icmpv6(*routed6) ||
      !std::equal(routed6->bytes.begin() + 54,
                  routed6->bytes.begin() + routed6->length,
                  echo6.bytes.begin() + 54)) {
    throw std::runtime_error("IPv6 forwarding modified upper-layer bytes");
  }
  const auto expiring6 =
      icmpv6_echo(source, target, *source_ipv6, *target_ipv6, false, 8, 1);
  if (route_ipv6(expiring6, target, source)) {
    throw std::runtime_error("IPv6 Hop Limit zero transition was forwarded");
  }
  const auto exceeded6 = icmpv6_time_exceeded(
      expiring6, target, source, *target_ipv6, *source_ipv6);
  const auto exceeded6_icmp =
      exceeded6 ? parse_icmpv6(*exceeded6) : std::nullopt;
  if (!exceeded6 || !exceeded6_icmp || exceeded6_icmp->type != 3U ||
      exceeded6_icmp->code != 0U || exceeded6_icmp->parameter != 0U ||
      exceeded6_icmp->data.size() < 40U) {
    throw std::runtime_error("IPv6 Hop Limit error encoding failed");
  }
  const auto too_big6 = icmpv6_packet_too_big(
      echo6, target, source, *target_ipv6, *source_ipv6, 1280);
  const auto too_big6_icmp = too_big6 ? parse_icmpv6(*too_big6) : std::nullopt;
  if (!too_big6 || !too_big6_icmp || too_big6_icmp->type != 2U ||
      too_big6_icmp->code != 0U || too_big6_icmp->parameter != 1280U ||
      too_big6_icmp->data.size() < 40U) {
    throw std::runtime_error("IPv6 Packet Too Big encoding failed");
  }
  const auto quoted_ipv6 = parse_ipv6_quote(too_big6_icmp->data);
  if (!quoted_ipv6 || quoted_ipv6->source != *source_ipv6 ||
      quoted_ipv6->destination != *target_ipv6 ||
      quoted_ipv6->upper_layer_protocol != ipv6_next_header_icmpv6 ||
      quoted_ipv6->upper_layer_offset != ipv6_header_octets ||
      parse_ipv6_quote(too_big6_icmp->data.first(
          ipv6_header_octets + 7U))) {
    throw std::runtime_error(
        "ICMPv6 quote parser lost the invoking upper-layer boundary");
  }
  const auto unreachable6 = icmpv6_destination_unreachable(
      echo6, target, source, *target_ipv6, *source_ipv6,
      icmpv6_destination_no_route_code);
  const auto unreachable6_icmp =
      unreachable6 ? parse_icmpv6(*unreachable6) : std::nullopt;
  if (!unreachable6_icmp ||
      unreachable6_icmp->type != icmpv6_destination_unreachable_type ||
      unreachable6_icmp->code != 0U ||
      icmpv6_destination_unreachable(echo6, target, source, *target_ipv6,
                                     *source_ipv6, 7U)) {
    throw std::runtime_error("IPv6 Destination Unreachable encoding failed");
  }
  const auto parameter6 = icmpv6_parameter_problem(
      echo6, target, source, *target_ipv6, *source_ipv6,
      icmpv6_parameter_unknown_next_header_code, 6U);
  const auto parameter6_icmp =
      parameter6 ? parse_icmpv6(*parameter6) : std::nullopt;
  if (!parameter6_icmp ||
      parameter6_icmp->type != icmpv6_parameter_problem_type ||
      parameter6_icmp->code != 1U || parameter6_icmp->parameter != 6U ||
      icmpv6_parameter_problem(echo6, target, source, *target_ipv6,
                               *source_ipv6, 3U, 0U)) {
    throw std::runtime_error("IPv6 Parameter Problem encoding failed");
  }

  const auto multicast = router::ip::parse_ipv6("ff02::1:ff34:5678");
  if (!multicast ||
      ipv6_multicast_mac(*multicast) !=
          Mac{0x33, 0x33, 0xff, 0x34, 0x56, 0x78}) {
    throw std::runtime_error("IPv6 Ethernet multicast mapping failed");
  }

  // The generic source encoder uses a span because the largest ordinary IPv6
  // datagram is larger than a physical Frame. Verify both the shared header
  // word and the independent 16-bit payload domain before fragmentation.
  std::vector<std::uint8_t> maximum_payload(maximum_ipv6_payload_octets,
                                            0x3cU);
  std::vector<std::uint8_t> encoded_datagram(
      maximum_ethernet_ipv6_datagram_octets);
  const auto encoded_octets = encode_ipv6_ethernet_datagram(
      encoded_datagram, source, target, *source_ipv6, *target_ipv6,
      ipv6_next_header_udp, 37U, maximum_payload, 0xa5U, 0x54321U);
  const auto encoded_view = encoded_octets
                                ? parse_ipv6(std::span<const std::uint8_t>{
                                      encoded_datagram.data(), *encoded_octets})
                                : std::nullopt;
  if (!encoded_octets ||
      *encoded_octets != maximum_ethernet_ipv6_datagram_octets ||
      !encoded_view || encoded_view->payload_length != 65535U ||
      encoded_view->traffic_class != 0xa5U ||
      encoded_view->flow_label != 0x54321U ||
      encoded_view->hop_limit != 37U ||
      encoded_datagram.back() != 0x3cU ||
      encode_ipv6_ethernet_datagram(
          encoded_datagram, source, target, *source_ipv6, *target_ipv6,
          ipv6_next_header_udp, 1U, {}, 0U, 0x100000U)) {
    throw std::runtime_error(
        "full-size IPv6 datagram encoding truncated or corrupted its header");
  }

  // Insert one eight-octet Hop-by-Hop header before the original ICMPv6 bytes.
  // ICMPv6 checksum length excludes extension bytes, so a correct parser still
  // validates the unchanged upper-layer message at its new offset.
  auto extended6 = echo6;
  std::move_backward(extended6.bytes.begin() + 54,
                     extended6.bytes.begin() + extended6.length,
                     extended6.bytes.begin() + extended6.length + 8);
  extended6.length = static_cast<std::uint16_t>(extended6.length + 8U);
  extended6.bytes[18] = 0;
  extended6.bytes[19] = 72;
  extended6.bytes[20] = 0;
  extended6.bytes[54] = 58;
  extended6.bytes[55] = 0;
  std::fill(extended6.bytes.begin() + 56, extended6.bytes.begin() + 62,
            std::uint8_t{0});
  const auto extended_view = parse_ipv6(extended6);
  if (!extended_view || extended_view->upper_layer_offset != 62U ||
      extended_view->upper_layer_protocol != 58U || !parse_icmpv6(extended6)) {
    throw std::runtime_error("IPv6 extension-header traversal failed");
  }
  auto malformed_extension = extended6;
  malformed_extension.bytes[55] = 255;
  if (parse_ipv6(malformed_extension)) {
    throw std::runtime_error("Truncated IPv6 extension header was accepted");
  }

  // RFC 4302 gives AH a different length encoding from the RFC 8200 option
  // headers. Build a minimum aligned IPv6 AH with a nonzero SPI and sequence
  // number, then prove that structural traversal never makes its inner ICMPv6
  // payload eligible for authentication-free local delivery.
  auto authenticated6 = echo6;
  std::move_backward(authenticated6.bytes.begin() + 54,
                     authenticated6.bytes.begin() + authenticated6.length,
                     authenticated6.bytes.begin() +
                         authenticated6.length + 16U);
  authenticated6.length =
      static_cast<std::uint16_t>(authenticated6.length + 16U);
  authenticated6.bytes[18] = 0U;
  authenticated6.bytes[19] = 80U;
  authenticated6.bytes[20] = ipv6_next_header_authentication;
  authenticated6.bytes[54] = ipv6_next_header_icmpv6;
  authenticated6.bytes[55] = 2U;
  authenticated6.bytes[56] = 0U;
  authenticated6.bytes[57] = 0U;
  authenticated6.bytes[58] = 0x01U;
  authenticated6.bytes[59] = 0x02U;
  authenticated6.bytes[60] = 0x03U;
  authenticated6.bytes[61] = 0x04U;
  authenticated6.bytes[62] = 0U;
  authenticated6.bytes[63] = 0U;
  authenticated6.bytes[64] = 0U;
  authenticated6.bytes[65] = 1U;
  std::fill(authenticated6.bytes.begin() + 66,
            authenticated6.bytes.begin() + 70, std::uint8_t{0});
  const auto authenticated_view = parse_ipv6(authenticated6);
  if (!authenticated_view ||
      !authenticated_view->authentication_header_present ||
      authenticated_view->upper_layer_protocol != ipv6_next_header_icmpv6 ||
      authenticated_view->upper_layer_offset != 70U ||
      parse_icmpv6(authenticated6)) {
    throw std::runtime_error(
        "IPv6 AH traversal exposed an unauthenticated inner payload");
  }

  // Payload Len values zero and one describe 8- and 12-octet headers. Neither
  // is a valid IPv6 AH because the mandatory fields and alignment requirements
  // cannot both be satisfied. They must fail before any SPI lookup is tried.
  auto undersized_ah = authenticated6;
  undersized_ah.bytes[55] = 0U;
  if (parse_ipv6(undersized_ah)) {
    throw std::runtime_error("undersized IPv6 AH was accepted");
  }
  undersized_ah.bytes[55] = 1U;
  if (parse_ipv6(undersized_ah)) {
    throw std::runtime_error("misaligned IPv6 AH was accepted");
  }

  const auto arp = arp_request(source, source_ip, target_ip);
  if (arp.size() != 60 || arp[12] != 0x08 || arp[13] != 0x06) {
    throw std::runtime_error("ARP request encoding failed");
  }
  // A dot1q and QinQ SAP changes only the Ethernet envelope. The routed packet
  // must regain its exact original byte image after ingress classification
  // strips the service tags. PCP and DEI are verified because retaining only
  // VID would corrupt frames that later return through the same attachment.
  auto tagged_arp = arp;
  const std::array<EthernetView::VlanTag, 2> service_tags{{
      {.tpid = ethernet_type_service_vlan,
       .vlan_identifier = 200U,
       .priority_code_point = 5U,
       .drop_eligible = true},
      {.tpid = ethernet_type_customer_vlan,
       .vlan_identifier = 37U,
       .priority_code_point = 2U,
       .drop_eligible = false}}};
  if (!insert_vlan_tags(tagged_arp, service_tags))
    throw std::runtime_error("QinQ insertion rejected a valid tag stack");
  const auto tagged_view = parse_ethernet(tagged_arp);
  if (!tagged_view || tagged_view->ether_type != ethernet_type_arp ||
      tagged_view->payload_offset != 22U || tagged_view->vlan_tag_count != 2U ||
      tagged_view->vlan_tags[0] != service_tags[0] ||
      tagged_view->vlan_tags[1] != service_tags[1] ||
      !strip_vlan_tags(tagged_arp) || tagged_arp.length != arp.length ||
      !std::equal(tagged_arp.bytes.begin(),
                  tagged_arp.bytes.begin() + tagged_arp.length,
                  arp.bytes.begin()))
    throw std::runtime_error("QinQ parse or lossless ingress stripping failed");

  auto invalid_tag = service_tags[0];
  invalid_tag.vlan_identifier = 0x0fffU;
  auto unchanged_arp = arp;
  if (insert_vlan_tags(unchanged_arp,
                       std::span<const EthernetView::VlanTag>{&invalid_tag,
                                                              1U}) ||
      unchanged_arp.length != arp.length ||
      !std::equal(unchanged_arp.bytes.begin(),
                  unchanged_arp.bytes.begin() + unchanged_arp.length,
                  arp.bytes.begin()))
    throw std::runtime_error("reserved VID modified the Ethernet frame");
  if (arp[14] != 0 || arp[15] != 1 || arp[18] != 6 || arp[19] != 4 ||
      arp[20] != 0 || arp[21] != 1 || arp[32] != 0 || arp[37] != 0) {
    throw std::runtime_error("ARP header or request opcode is invalid");
  }

  // RFC 792 defines an eight-octet Echo header followed by arbitrary data.
  // The pinned SR OS command profile uses 56 data octets, producing 64 ICMP
  // octets and an unpadded 98-octet captured Ethernet frame.
  const auto echo = icmp_echo(
      source, target, source_ip, target_ip, false, 1, 64,
      router::profile::default_ping_payload_octets, false);
  if (echo.size() != 98 || checksum(echo.view().subspan(14, 20)) != 0 ||
      checksum(echo.view().subspan(34, 64)) != 0 || echo[22] != 64 ||
      echo[23] != 1 || echo[34] != 8) {
    throw std::runtime_error("IPv4 or ICMP encoding failed");
  }
  const auto parsed_arp = parse_arp(arp);
  const auto parsed_ip = parse_ipv4(echo);
  const auto parsed_icmp = parse_icmp(echo);
  if (!parsed_arp || parsed_arp->operation != 1 ||
      parsed_arp->sender_ip != source_ip || !parsed_ip ||
      parsed_ip->source != source_ip || parsed_ip->destination != target_ip ||
      !parsed_icmp || parsed_icmp->type != 8 ||
      parsed_icmp->data.size() !=
          router::profile::default_ping_payload_octets) {
    throw std::runtime_error("Packet parser did not preserve protocol fields");
  }
  // Parsing and destination acceptance are separate responsibilities. Preserve
  // a rewritten destination exactly so the receiving port can reject a frame
  // addressed to another station before IPv4 forwarding.
  auto wrong_l2 = echo;
  const Mac stranger{0x02, 0, 0, 0, 0, 0xee};
  rewrite_ethernet(wrong_l2, source, stranger);
  const auto wrong_l2_view = parse_ethernet(wrong_l2);
  if (!wrong_l2_view || wrong_l2_view->destination != stranger ||
      ethernet_for_local(wrong_l2_view->destination, target) ||
      !ethernet_for_local(Mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, target)) {
    throw std::runtime_error(
        "Ethernet destination rewrite or parsing is invalid");
  }
  const auto routed = route_ipv4(echo, target, source);
  if (!routed || (*routed)[22] != 63 ||
      checksum(routed->view().subspan(14, 20)) != 0 ||
      !std::equal(routed->bytes.begin() + 34, routed->bytes.begin() + 98,
                  echo.bytes.begin() + 34)) {
    throw std::runtime_error(
        "IPv4 forwarding rewrite changed payload or checksum");
  }

  // The receiver must derive a reply from the request bytes. These checks make
  // a separately fabricated response fail if it loses the payload, identifier,
  // sequence, address reversal, or checksum update required by RFC 792.
  const auto reply = icmp_echo_reply(echo, target, source);
  const auto reply_ip = reply ? parse_ipv4(*reply) : std::nullopt;
  const auto reply_icmp = reply ? parse_icmp(*reply) : std::nullopt;
  if (!reply || !reply_ip || !reply_icmp || reply_ip->source != target_ip ||
      reply_ip->destination != source_ip || reply_icmp->type != 0 ||
      reply_icmp->sequence != 1 ||
      reply_icmp->data.size() !=
          router::profile::default_ping_payload_octets ||
      !std::equal(reply_icmp->data.begin(), reply_icmp->data.end(),
                  parsed_icmp->data.begin())) {
    throw std::runtime_error(
        "ICMP Echo Reply was not derived from the received request");
  }

  // RFC 1812 requires a router to return Time Exceeded when forwarding would
  // decrement TTL to zero. The ICMP payload must quote enough of the original
  // datagram to identify the failed probe.
  const auto expiring =
      icmp_echo(source, target, source_ip, target_ip, false, 9, 1,
                router::profile::default_ping_payload_octets, false);
  const auto exceeded =
      icmp_time_exceeded(expiring, target, source, target_ip, source_ip);
  const auto exceeded_icmp = exceeded ? parse_icmp(*exceeded) : std::nullopt;
  if (!exceeded || !exceeded_icmp || exceeded_icmp->type != 11 ||
      exceeded_icmp->code != 0 || exceeded_icmp->data.size() < 28) {
    throw std::runtime_error(
        "TTL expiry did not produce a valid ICMP Time Exceeded packet");
  }
  const auto reassembly_exceeded = icmp_reassembly_time_exceeded(
      expiring, target, source, target_ip, source_ip);
  const auto reassembly_exceeded_icmp =
      reassembly_exceeded ? parse_icmp(*reassembly_exceeded) : std::nullopt;
  if (!reassembly_exceeded_icmp ||
      reassembly_exceeded_icmp->type != 11U ||
      reassembly_exceeded_icmp->code != 1U ||
      reassembly_exceeded_icmp->data.size() < 28U) {
    throw std::runtime_error(
        "IPv4 reassembly timeout did not encode ICMP Time Exceeded code 1");
  }
  const auto port_unreachable = icmp_port_unreachable(
      echo.view(), target, source, target_ip, source_ip);
  const auto port_unreachable_icmp =
      port_unreachable ? parse_icmp(*port_unreachable) : std::nullopt;
  if (!port_unreachable_icmp || port_unreachable_icmp->type != 3U ||
      port_unreachable_icmp->code != 3U ||
      port_unreachable_icmp->data.size() < 28U) {
    throw std::runtime_error(
        "IPv4 closed UDP port did not encode Destination Unreachable code 3");
  }
  const auto network_unreachable = icmp_network_unreachable(
      echo, target, source, target_ip, source_ip);
  const auto network_unreachable_icmp =
      network_unreachable ? parse_icmp(*network_unreachable) : std::nullopt;
  if (!network_unreachable_icmp ||
      network_unreachable_icmp->type != 3U ||
      network_unreachable_icmp->code != 0U ||
      network_unreachable_icmp->data.size() < 28U) {
    throw std::runtime_error(
        "Missing route did not encode Destination Unreachable code 0");
  }
  const auto protocol_unreachable = icmp_protocol_unreachable(
      echo.view(), target, source, target_ip, source_ip);
  const auto protocol_unreachable_icmp =
      protocol_unreachable ? parse_icmp(protocol_unreachable->view())
                           : std::nullopt;
  if (!protocol_unreachable_icmp ||
      protocol_unreachable_icmp->type != 3U ||
      protocol_unreachable_icmp->code != 2U ||
      protocol_unreachable_icmp->data.size() < 28U) {
    throw std::runtime_error(
        "Unknown local IPv4 protocol did not encode unreachable code 2");
  }

  // RFC 1191 requires type 3 code 4 to quote the rejected datagram and carry
  // the limiting next-hop MTU in the low 16 bits of the ICMP unused field.
  // The test reads wire bytes instead of relying on an internal error object.
  const auto oversized_df =
      icmp_echo(source, target, source_ip, target_ip, false, 11, 64, 1000, true);
  const auto needed = icmp_fragmentation_needed(
      oversized_df, target, source, target_ip, source_ip, 512);
  const auto needed_icmp = needed ? parse_icmp(*needed) : std::nullopt;
  if (!needed || !needed_icmp || needed_icmp->type != 3 ||
      needed_icmp->code != 4 || needed_icmp->parameter != 512U ||
      (*needed)[40] != 2 || (*needed)[41] != 0 ||
      needed_icmp->data.size() < 28) {
    throw std::runtime_error(
        "Oversized DF datagram did not encode the RFC 1191 next-hop MTU");
  }
  const auto quoted_ipv4 = parse_ipv4_quote(needed_icmp->data);
  if (!quoted_ipv4 || quoted_ipv4->source != source_ip ||
      quoted_ipv4->destination != target_ip || !quoted_ipv4->dont_fragment ||
      quoted_ipv4->total_length != parse_ipv4(oversized_df)->total_length) {
    throw std::runtime_error(
        "ICMP quotation parser did not preserve the invoking IPv4 header");
  }

  // A fragmentable 1028-byte IPv4 datagram crosses a 512-byte MTU as three
  // datagrams. Non-final payloads are multiples of eight and offsets continue
  // from the original payload, while TTL was decremented only once beforehand.
  const auto fragmentable =
      icmp_echo(source, target, source_ip, target_ip, false, 12, 64, 1000, false);
  const auto routed_large = route_ipv4(fragmentable, target, source);
  const auto fragments = routed_large ? fragment_ipv4(*routed_large, 512)
                                      : std::nullopt;
  if (!fragments || fragments->count != 3) {
    throw std::runtime_error("IPv4 fragmentation produced the wrong batch");
  }
  std::uint16_t expected_offset{};
  for (std::size_t index = 0; index < fragments->count; ++index) {
    const auto view = parse_ipv4(fragments->frames[index]);
    if (!view || view->total_length > 512 || view->ttl != 63 ||
        view->fragment_offset != expected_offset ||
        view->more_fragments != (index + 1U < fragments->count)) {
      throw std::runtime_error(
          "IPv4 fragment offset, size, flag or checksum was invalid");
    }
    expected_offset = static_cast<std::uint16_t>(
        expected_offset + (view->total_length - view->header_length) / 8U);
  }

  // The generated 9212-byte network MTU is a real codec bound, not only a CLI
  // validation value. At the minimum modeled MTU its payload requires 19
  // RFC 791 fragments, proving that the former four-fragment ceiling is gone.
  constexpr auto jumbo_payload =
      maximum_network_ip_mtu - 20U - 8U;
  const auto jumbo = icmp_echo(source, target, source_ip, target_ip, false, 13,
                               64, jumbo_payload, false);
  const auto routed_jumbo = route_ipv4(jumbo, target, source);
  const auto jumbo_fragments =
      routed_jumbo ? fragment_ipv4(*routed_jumbo,
                                   minimum_network_ip_mtu)
                   : std::nullopt;
  if (jumbo.size() != maximum_frame_octets || !jumbo_fragments ||
      jumbo_fragments->count != FragmentBatch::maximum_fragment_count) {
    throw std::runtime_error(
        "Jumbo IPv4 datagram was truncated or hit a stale fragment limit");
  }

  // IPv4 Total Length is independent of a physical Ethernet frame. Exercise
  // the complete 65,535-octet domain so a future optimization cannot restore
  // the former jumbo-Frame ceiling or discard the tail of a large UDP packet.
  std::vector<std::uint8_t> maximum_ipv4_payload(
      maximum_ipv4_datagram_octets - 20U);
  for (std::size_t index = 0; index < maximum_ipv4_payload.size(); ++index)
    maximum_ipv4_payload[index] = static_cast<std::uint8_t>(index * 29U + 7U);
  std::vector<std::uint8_t> maximum_ipv4_datagram(
      maximum_ethernet_ipv4_datagram_octets);
  const auto maximum_ipv4_octets = encode_ipv4_ethernet_datagram(
      maximum_ipv4_datagram, source, target, source_ip, target_ip, 17U, 64U,
      0x4a21U, maximum_ipv4_payload, false);
  const auto maximum_ipv4_view =
      maximum_ipv4_octets
          ? parse_ipv4(std::span<const std::uint8_t>{
                maximum_ipv4_datagram.data(), *maximum_ipv4_octets})
          : std::nullopt;
  constexpr std::uint16_t source_path_mtu = 1280U;
  const auto expected_ipv4_fragments = ipv4_fragment_count(
      std::span<const std::uint8_t>{maximum_ipv4_datagram.data(),
                                    maximum_ipv4_octets.value_or(0U)},
      source_path_mtu);
  std::vector<Frame> streamed_ipv4_fragments;
  const auto collect_fragment = +[](void *context,
                                    const Frame &fragment) noexcept {
    auto &fragments = *static_cast<std::vector<Frame> *>(context);
    fragments.push_back(fragment);
    return true;
  };
  const auto streamed_ipv4_count = fragment_ipv4_datagram(
      std::span<const std::uint8_t>{maximum_ipv4_datagram.data(),
                                    maximum_ipv4_octets.value_or(0U)},
      source_path_mtu, &streamed_ipv4_fragments, collect_fragment);
  if (!maximum_ipv4_octets ||
      *maximum_ipv4_octets != maximum_ethernet_ipv4_datagram_octets ||
      !maximum_ipv4_view || maximum_ipv4_view->total_length != 65535U ||
      !expected_ipv4_fragments || !streamed_ipv4_count ||
      *streamed_ipv4_count != *expected_ipv4_fragments ||
      streamed_ipv4_fragments.size() != *expected_ipv4_fragments) {
    throw std::runtime_error(
        "full-size IPv4 source datagram was truncated before fragmentation");
  }

  // Reassembly here is deliberately test-only: production ownership belongs
  // to the destination reassembly table. Copying by the Fragment Offset proves
  // that every streamed byte, final length, MF flag and header checksum has the
  // RFC 791 wire meaning expected by that future owner.
  std::vector<std::uint8_t> reconstructed(maximum_ipv4_payload.size());
  for (std::size_t index = 0; index < streamed_ipv4_fragments.size(); ++index) {
    const auto &fragment = streamed_ipv4_fragments[index];
    const auto view = parse_ipv4(fragment);
    if (!view || view->total_length > source_path_mtu ||
        view->identification != 0x4a21U ||
        view->more_fragments !=
            (index + 1U < streamed_ipv4_fragments.size())) {
      throw std::runtime_error(
          "streamed IPv4 fragment header did not preserve its datagram");
    }
    const auto payload_octets =
        static_cast<std::size_t>(view->total_length - view->header_length);
    const auto payload_offset =
        static_cast<std::size_t>(view->fragment_offset) * 8U;
    if (payload_offset + payload_octets > reconstructed.size())
      throw std::runtime_error("IPv4 fragment exceeded reassembly extent");
    std::copy_n(fragment.bytes.begin() + 14U + view->header_length,
                payload_octets, reconstructed.begin() + payload_offset);
  }
  if (reconstructed != maximum_ipv4_payload) {
    throw std::runtime_error(
        "streamed IPv4 fragmentation did not preserve every payload byte");
  }

  // DF is a protocol decision made by the socket or application. A source
  // fragmentation helper must reject it instead of silently clearing the bit.
  const auto df_octets = encode_ipv4_ethernet_datagram(
      maximum_ipv4_datagram, source, target, source_ip, target_ip, 17U, 64U,
      0x4a22U, maximum_ipv4_payload, true);
  if (!df_octets ||
      ipv4_fragment_count(
          std::span<const std::uint8_t>{maximum_ipv4_datagram.data(),
                                        *df_octets},
          source_path_mtu) ||
      fragment_ipv4_datagram(
          std::span<const std::uint8_t>{maximum_ipv4_datagram.data(),
                                        *df_octets},
          source_path_mtu, &streamed_ipv4_fragments, collect_fragment)) {
    throw std::runtime_error("IPv4 source fragmentation ignored DF");
  }

  // Deterministic mutation fuzzing covers every legal frame length and random
  // byte patterns under ASAN and UBSAN in CI. Parsers may reject a candidate,
  // but no rejected length or header may read outside Frame::view or allocate
  // attacker-controlled storage.
  std::uint32_t random = 0x82610791U;
  for (std::uint32_t iteration = 0; iteration < 10000; ++iteration) {
    Frame candidate;
    random ^= random << 13;
    random ^= random >> 17;
    random ^= random << 5;
    candidate.length =
        static_cast<std::uint16_t>(random % (candidate.bytes.size() + 1));
    for (std::size_t index = 0; index < candidate.length; ++index) {
      random ^= random << 13;
      random ^= random >> 17;
      random ^= random << 5;
      candidate.bytes[index] = static_cast<std::uint8_t>(random);
    }
    static_cast<void>(parse_ethernet(candidate));
    static_cast<void>(parse_arp(candidate));
    static_cast<void>(parse_ipv4(candidate));
    static_cast<void>(parse_icmp(candidate));
    static_cast<void>(parse_ipv6(candidate));
    static_cast<void>(parse_icmpv6(candidate));
    static_cast<void>(route_ipv4(candidate, target, source));
    static_cast<void>(route_ipv6(candidate, target, source));
    static_cast<void>(fragment_ipv4(candidate, 512));
  }
}
