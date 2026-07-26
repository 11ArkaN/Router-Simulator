// UDP codec conformance tests cover the complete ordinary 16-bit length
// domain, both IP pseudo-headers and malformed receive paths without a socket
// or network-owner dependency.

#include "router/udp_packet.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void udp_packet_tests() {
  using namespace router;
  using namespace router::packet;
  using namespace router::packet::udp;

  const auto source6 = ip::parse_ipv6("2001:db8::1");
  const auto destination6 = ip::parse_ipv6("2001:db8::2");
  if (!source6 || !destination6)
    throw std::runtime_error("UDP IPv6 fixture address parsing failed");

  std::array<std::uint8_t, 64> storage{};
  constexpr std::array<std::uint8_t, 5> payload{1U, 2U, 3U, 4U, 5U};
  const auto encoded6 = encode_ipv6(storage, *source6, *destination6, 546U,
                                    547U, payload);
  // 0x9714 is independently calculated from the RFC 8200 pseudo-header,
  // ports, thirteen-octet UDP length and the five payload octets. Keeping the
  // vector literal catches an encoder and decoder that share the same defect.
  if (!encoded6 || *encoded6 != 13U || storage[0] != 0x02U ||
      storage[1] != 0x22U || storage[2] != 0x02U ||
      storage[3] != 0x23U || storage[4] != 0U || storage[5] != 13U ||
      storage[6] != 0x97U || storage[7] != 0x14U)
    throw std::runtime_error("UDP over IPv6 wire vector did not match RFC format");
  const auto parsed6 = parse_ipv6(
      std::span<const std::uint8_t>{storage}.first(*encoded6), *source6,
      *destination6);
  if (!parsed6 || parsed6->source_port != 546U ||
      parsed6->destination_port != 547U ||
      !std::equal(parsed6->payload.begin(), parsed6->payload.end(),
                  payload.begin(), payload.end()))
    throw std::runtime_error("UDP over IPv6 parser lost header or payload state");

  auto corrupted = storage;
  corrupted[8] ^= 0x80U;
  if (parse_ipv6(std::span<const std::uint8_t>{corrupted}.first(*encoded6),
                 *source6, *destination6))
    throw std::runtime_error("UDP over IPv6 accepted a bad mandatory checksum");
  corrupted = storage;
  corrupted[6] = 0U;
  corrupted[7] = 0U;
  if (parse_ipv6(std::span<const std::uint8_t>{corrupted}.first(*encoded6),
                 *source6, *destination6))
    throw std::runtime_error("UDP over IPv6 accepted a missing checksum");
  corrupted = storage;
  corrupted[5] = 12U;
  if (parse_ipv6(std::span<const std::uint8_t>{corrupted}.first(*encoded6),
                 *source6, *destination6) ||
      parse_ipv6(std::span<const std::uint8_t>{storage}.first(7U), *source6,
                 *destination6))
    throw std::runtime_error("UDP parser accepted a truncated or inconsistent length");

  // A computed checksum of zero is represented by all ones on the wire. The
  // payload value is chosen for this exact tuple so the rarely reached branch
  // remains protected without brute force inside the test executable.
  constexpr std::array<std::uint8_t, 2> zero_checksum_payload{0xa0U, 0x20U};
  const auto escaped_checksum = encode_ipv6(
      storage, *source6, *destination6, 546U, 547U, zero_checksum_payload);
  if (!escaped_checksum || storage[6] != 0xffU || storage[7] != 0xffU ||
      !parse_ipv6(std::span<const std::uint8_t>{storage}.first(*escaped_checksum),
                  *source6, *destination6))
    throw std::runtime_error("UDP failed the RFC 768 zero-checksum wire escape");

  constexpr Ipv4 source4{192U, 0U, 2U, 1U};
  constexpr Ipv4 destination4{192U, 0U, 2U, 2U};
  const auto encoded4 =
      encode_ipv4(storage, source4, destination4, 10000U, 53U, payload);
  if (!encoded4 || !parse_ipv4(
                       std::span<const std::uint8_t>{storage}.first(*encoded4),
                       source4, destination4))
    throw std::runtime_error("UDP over IPv4 checksum validation failed");
  const auto unchecked4 = encode_ipv4(storage, source4, destination4, 10000U,
                                      53U, payload, false);
  if (!unchecked4 || storage[6] != 0U || storage[7] != 0U ||
      !parse_ipv4(std::span<const std::uint8_t>{storage}.first(*unchecked4),
                  source4, destination4))
    throw std::runtime_error("UDP over IPv4 rejected RFC 768 checksum omission");

  // Link MTU is intentionally absent from this assertion. The IP source owns
  // fragmentation, so the UDP codec must accept the entire non-jumbo length
  // domain even though no single Ethernet frame can carry this payload.
  static std::array<std::uint8_t, maximum_payload_octets> maximum_payload{};
  static std::array<std::uint8_t, maximum_datagram_octets> maximum_storage{};
  const auto maximum = encode_ipv6(maximum_storage, *source6, *destination6,
                                   1U, 65535U, maximum_payload);
  if (!maximum || *maximum != maximum_datagram_octets ||
      maximum_storage[4] != 0xffU || maximum_storage[5] != 0xffU ||
      !parse_ipv6(maximum_storage, *source6, *destination6))
    throw std::runtime_error("UDP codec imposed a link-sized datagram limit");
  static std::array<std::uint8_t, maximum_payload_octets + 1U> oversized{};
  if (encode_ipv6(maximum_storage, *source6, *destination6, 1U, 2U,
                  oversized) ||
      encode_ipv6(std::span<std::uint8_t>{storage}.first(12U), *source6,
                  *destination6, 1U, 2U, payload))
    throw std::runtime_error("UDP codec accepted overflow or short output storage");

  // IPv4's own 16-bit Total Length includes a minimum 20-octet IP header.
  // Fragmentation subdivides this original datagram and cannot enlarge it, so
  // the IPv4 UDP payload ceiling is 20 octets below the IPv6 ceiling.
  static std::array<std::uint8_t, maximum_ipv4_payload_octets>
      maximum_ipv4_payload{};
  const auto maximum4 = encode_ipv4(
      maximum_storage, source4, destination4, 1U, 65535U,
      maximum_ipv4_payload);
  if (!maximum4 ||
      *maximum4 != header_octets + maximum_ipv4_payload_octets ||
      !parse_ipv4(std::span<const std::uint8_t>{maximum_storage}.first(
                      *maximum4),
                  source4, destination4))
    throw std::runtime_error("UDP over IPv4 rejected its full IP length domain");
  static std::array<std::uint8_t, maximum_ipv4_payload_octets + 1U>
      oversized_ipv4{};
  if (encode_ipv4(maximum_storage, source4, destination4, 1U, 2U,
                  oversized_ipv4))
    throw std::runtime_error("UDP over IPv4 exceeded IPv4 Total Length");
}
