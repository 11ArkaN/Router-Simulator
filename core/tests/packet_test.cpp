#include "router/packet.hpp"

#include <stdexcept>

void packet_tests() {
  using namespace router::packet;
  const Mac source{0x02, 0, 0, 0, 0, 1};
  const Mac target{0x02, 0, 0, 0, 0, 2};
  const Ipv4 source_ip{192, 0, 2, 1};
  const Ipv4 target_ip{192, 0, 2, 2};

  const auto arp = arp_request(source, source_ip, target_ip);
  if (arp.size() != 60 || arp[12] != 0x08 || arp[13] != 0x06) {
    throw std::runtime_error("ARP request encoding failed");
  }
  if (arp[14] != 0 || arp[15] != 1 || arp[18] != 6 || arp[19] != 4 ||
      arp[20] != 0 || arp[21] != 1 || arp[32] != 0 || arp[37] != 0) {
    throw std::runtime_error("ARP header or request opcode is invalid");
  }

  // RFC 792 defines an eight-octet Echo header followed by arbitrary data.
  // The pinned SR OS command profile uses 56 data octets, producing 64 ICMP
  // octets and an unpadded 98-octet captured Ethernet frame.
  const auto echo = icmp_echo(source, target, source_ip, target_ip, false, 1);
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
      parsed_icmp->data.size() != 56) {
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
      reply_icmp->sequence != 1 || reply_icmp->data.size() != 56 ||
      !std::equal(reply_icmp->data.begin(), reply_icmp->data.end(),
                  parsed_icmp->data.begin())) {
    throw std::runtime_error(
        "ICMP Echo Reply was not derived from the received request");
  }

  // RFC 1812 requires a router to return Time Exceeded when forwarding would
  // decrement TTL to zero. The ICMP payload must quote enough of the original
  // datagram to identify the failed probe.
  const auto expiring =
      icmp_echo(source, target, source_ip, target_ip, false, 9, 1);
  const auto exceeded =
      icmp_time_exceeded(expiring, target, source, target_ip, source_ip);
  const auto exceeded_icmp = exceeded ? parse_icmp(*exceeded) : std::nullopt;
  if (!exceeded || !exceeded_icmp || exceeded_icmp->type != 11 ||
      exceeded_icmp->code != 0 || exceeded_icmp->data.size() < 28) {
    throw std::runtime_error(
        "TTL expiry did not produce a valid ICMP Time Exceeded packet");
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
    static_cast<void>(route_ipv4(candidate, target, source));
  }
}
