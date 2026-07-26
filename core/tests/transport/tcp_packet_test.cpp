// TCP wire tests cover both IP pseudo-headers, the complete ordinary segment
// length domains, option validation and mandatory checksum rejection. They do
// not claim connection-state behavior, which belongs to a later TCB module.

#include "router/tcp_packet.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void tcp_packet_tests() {
  using namespace router;
  using namespace router::packet;
  using namespace router::packet::tcp;

  constexpr Ipv4 source4{192U, 0U, 2U, 1U};
  constexpr Ipv4 destination4{198U, 51U, 100U, 2U};
  const auto source6 = ip::parse_ipv6("2001:db8::1");
  const auto destination6 = ip::parse_ipv6("2001:db8::2");
  if (!source6 || !destination6)
    throw std::runtime_error("TCP IPv6 fixture address parsing failed");

  const Fields fields{.source_port = 12345U,
                      .destination_port = 443U,
                      .sequence = 0xfedcba98U,
                      .acknowledgment = 0x01234567U,
                      .flags = static_cast<std::uint8_t>(syn | ack),
                      .window = 65535U,
                      .urgent_pointer = 0U};
  constexpr std::array<std::uint8_t, 4> mss{2U, 4U, 0x05U, 0xb4U};
  constexpr std::array<std::uint8_t, 5> payload{1U, 2U, 3U, 4U, 5U};
  std::array<std::uint8_t, 128> storage{};

  const auto encoded4 =
      encode_ipv4(storage, source4, destination4, fields, mss, payload);
  // 0x70e0 was independently calculated over this exact IPv4 pseudo-header,
  // TCP header, MSS option and odd five-octet payload. A fixed vector catches
  // an encoder and parser that accidentally share the same checksum defect.
  if (!encoded4 || *encoded4 != 29U || storage[12U] != 0x60U ||
      storage[13U] != 0x12U || storage[16U] != 0x70U ||
      storage[17U] != 0xe0U)
    throw std::runtime_error("TCP over IPv4 did not match the wire vector");
  const auto parsed4 = parse_ipv4(
      std::span<const std::uint8_t>{storage}.first(*encoded4), source4,
      destination4);
  if (!parsed4 || parsed4->source_port != fields.source_port ||
      parsed4->destination_port != fields.destination_port ||
      parsed4->sequence != fields.sequence ||
      parsed4->acknowledgment != fields.acknowledgment ||
      parsed4->flags != fields.flags || parsed4->window != 65535U ||
      parsed4->options.size() != mss.size() ||
      !std::equal(parsed4->payload.begin(), parsed4->payload.end(),
                  payload.begin(), payload.end()))
    throw std::runtime_error("TCP over IPv4 parser lost header or payload state");

  auto corrupted = storage;
  corrupted[28U] ^= 0x01U;
  if (parse_ipv4(std::span<const std::uint8_t>{corrupted}.first(*encoded4),
                 source4, destination4))
    throw std::runtime_error("TCP accepted a bad mandatory IPv4 checksum");

  // A non-aligned option list is legal input to the encoder. It pads the TCP
  // header with EOL octets and exposes those bytes in the parsed header view.
  constexpr std::array<std::uint8_t, 15> option_set{
      3U, 3U, 14U, 1U, 8U, 10U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 2U, 1U};
  const auto encoded6 = encode_ipv6(storage, *source6, *destination6, fields,
                                    option_set, payload);
  const auto parsed6 = encoded6 ? parse_ipv6(
                                     std::span<const std::uint8_t>{storage}.first(
                                         *encoded6),
                                     *source6, *destination6)
                                : std::nullopt;
  if (!parsed6 || parsed6->options.size() != 16U ||
      parsed6->options.back() != 0U || parsed6->payload.size() != payload.size())
    throw std::runtime_error("TCP over IPv6 lost option alignment or payload");
  corrupted = storage;
  corrupted[16U] = 0U;
  corrupted[17U] = 0U;
  if (parse_ipv6(std::span<const std::uint8_t>{corrupted}.first(*encoded6),
                 *source6, *destination6))
    throw std::runtime_error("TCP over IPv6 accepted a missing checksum");

  // Iterate known and unknown options without allocating or dropping an IANA
  // kind that this milestone does not yet interpret semantically.
  constexpr std::array<std::uint8_t, 9> unknown_options{
      1U, 30U, 4U, 0xaaU, 0xbbU, 2U, 4U, 0x04U, 0xb0U};
  if (!validate_options(unknown_options))
    throw std::runtime_error("TCP rejected a well-formed unknown option");
  std::size_t cursor{};
  const auto nop = next_option(unknown_options, cursor);
  const auto unknown = next_option(unknown_options, cursor);
  const auto parsed_mss = next_option(unknown_options, cursor);
  if (!nop || nop->kind != 1U || !unknown || unknown->kind != 30U ||
      unknown->raw.size() != 4U || !parsed_mss || parsed_mss->kind != 2U ||
      cursor != unknown_options.size())
    throw std::runtime_error("TCP option iterator changed option boundaries");

  constexpr std::array<std::uint8_t, 3> bad_mss{2U, 3U, 0U};
  constexpr std::array<std::uint8_t, 4> bad_tail{0U, 0U, 1U, 0U};
  constexpr std::array<std::uint8_t, 2> truncated_unknown{30U, 4U};
  if (validate_options(bad_mss) || validate_options(bad_tail) ||
      validate_options(truncated_unknown) ||
      encode_ipv4(storage, source4, destination4, fields, bad_mss, payload))
    throw std::runtime_error("TCP accepted a malformed option sequence");

  // Data Offset values below five and beyond the received segment must fail
  // before options or payload are exposed. Recompute a checksum so this test
  // reaches the shape validator instead of only exercising checksum failure.
  auto malformed = std::array<std::uint8_t, 20>{};
  malformed[12U] = 0x40U;
  malformed[16U] = 0U;
  malformed[17U] = 0U;
  auto shape_checksum = ipv4_upper_layer_checksum(
      source4, destination4, ipv6_next_header_tcp, malformed);
  malformed[16U] = static_cast<std::uint8_t>(shape_checksum >> 8U);
  malformed[17U] = static_cast<std::uint8_t>(shape_checksum);
  if (parse_ipv4(malformed, source4, destination4))
    throw std::runtime_error("TCP accepted Data Offset below five words");
  malformed[12U] = 0xf0U;
  malformed[16U] = 0U;
  malformed[17U] = 0U;
  shape_checksum = ipv4_upper_layer_checksum(
      source4, destination4, ipv6_next_header_tcp, malformed);
  malformed[16U] = static_cast<std::uint8_t>(shape_checksum >> 8U);
  malformed[17U] = static_cast<std::uint8_t>(shape_checksum);
  if (parse_ipv4(malformed, source4, destination4))
    throw std::runtime_error("TCP accepted a header beyond received bytes");

  // The transport codec follows IP's full datagram domain. A link owner may
  // fragment the enclosing IP packet later, but link MTU is not a TCP limit.
  static std::array<std::uint8_t, maximum_ipv6_segment_octets> maximum_storage{};
  static std::array<std::uint8_t,
                    maximum_ipv6_segment_octets - minimum_header_octets>
      maximum_ipv6_payload{};
  const auto maximum6 = encode_ipv6(maximum_storage, *source6, *destination6,
                                    fields, {}, maximum_ipv6_payload);
  if (!maximum6 || *maximum6 != maximum_ipv6_segment_octets ||
      !parse_ipv6(maximum_storage, *source6, *destination6))
    throw std::runtime_error("TCP imposed a link-sized IPv6 segment limit");

  static std::array<std::uint8_t,
                    maximum_ipv4_segment_octets - minimum_header_octets>
      maximum_ipv4_payload{};
  const auto maximum4 = encode_ipv4(maximum_storage, source4, destination4,
                                    fields, {}, maximum_ipv4_payload);
  if (!maximum4 || *maximum4 != maximum_ipv4_segment_octets ||
      !parse_ipv4(std::span<const std::uint8_t>{maximum_storage}.first(*maximum4),
                  source4, destination4))
    throw std::runtime_error("TCP exceeded or reduced IPv4 Total Length");

  static std::array<std::uint8_t,
                    maximum_ipv4_segment_octets - minimum_header_octets + 1U>
      oversized_ipv4{};
  if (encode_ipv4(maximum_storage, source4, destination4, fields, {},
                  oversized_ipv4) ||
      encode_ipv6(std::span<std::uint8_t>{storage}.first(20U), *source6,
                  *destination6, fields, {}, payload))
    throw std::runtime_error("TCP accepted IP overflow or short output storage");
}
