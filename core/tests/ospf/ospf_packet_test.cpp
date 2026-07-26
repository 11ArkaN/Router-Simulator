// OSPF wire tests exercise both protocol headers, all five packet bodies,
// version-specific Hello and DD layouts, nested LSA bounds and checksums.
// Fixtures are encoded as network-order octets so a host struct cannot make a
// test pass through the same alignment mistake as the production parser.

#include "router/ospf_packet.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void put16(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void put32(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

router::ip::Ipv6 address(const char *text) {
  const auto result = router::ip::parse_ipv6(text);
  if (!result)
    throw std::runtime_error("OSPF fixture address is invalid");
  return *result;
}

std::array<std::uint8_t, router::packet::ospf::lsa_header_octets>
router_lsa_header(std::uint8_t version, std::uint16_t length) {
  std::array<std::uint8_t, router::packet::ospf::lsa_header_octets> result{};
  put16(result, 0U, 12U);
  if (version == router::packet::ospf::version_two) {
    result[2U] = 0x02U;
    result[3U] = 1U;
  } else {
    put16(result, 2U, 0x2001U);
  }
  put32(result, 4U, 0x0a000001U);
  put32(result, 8U, 0x01010101U);
  put32(result, 12U, 0x80000001U);
  put16(result, 16U, 0x1234U);
  put16(result, 18U, length);
  return result;
}

} // namespace

void ospf_packet_tests() {
  using namespace router::packet::ospf;

  std::array<std::uint8_t, 128U> packet_storage{};
  std::array<std::uint8_t, 24U> hello_v2{};
  put32(hello_v2, 0U, 0xffffff00U);
  put16(hello_v2, 4U, 10U);
  hello_v2[6U] = 0x02U;
  hello_v2[7U] = 1U;
  put32(hello_v2, 8U, 40U);
  put32(hello_v2, 12U, 0x0a000001U);
  put32(hello_v2, 16U, 0x0a000002U);
  put32(hello_v2, 20U, 0x02020202U);
  const std::array<std::uint8_t, 8U> password{
      's', 'r', 'o', 's', '2', '6', '7', 'r'};

  const auto encoded_v2 = encode_version_two(
      packet_storage, PacketType::hello, 0x01010101U, 0U,
      AuthenticationType::simple_password, password, hello_v2);
  const auto packet_v2 =
      encoded_v2 ? parse_packet(*encoded_v2) : std::nullopt;
  const auto parsed_hello_v2 =
      packet_v2 ? parse_hello(*packet_v2) : std::nullopt;
  require(packet_v2 && verify_version_two_checksum(*packet_v2) &&
              packet_v2->router_id == 0x01010101U &&
              packet_v2->authentication == password &&
              parsed_hello_v2 &&
              parsed_hello_v2->network_mask == 0xffffff00U &&
              parsed_hello_v2->hello_interval_seconds == 10U &&
              parsed_hello_v2->dead_interval_seconds == 40U &&
              parsed_hello_v2->router_priority == 1U &&
              hello_neighbor(*parsed_hello_v2, 0U) ==
                  std::optional<std::uint32_t>{0x02020202U} &&
              !hello_neighbor(*parsed_hello_v2, 1U),
          "OSPFv2 Hello framing or checksum is incorrect");

  auto damaged_v2 = packet_storage;
  damaged_v2[version_two_header_octets + 8U] ^= 1U;
  const auto damaged_view = parse_packet(std::span<const std::uint8_t>(
      damaged_v2.data(), encoded_v2 ? encoded_v2->size() : 0U));
  require(damaged_view && !verify_version_two_checksum(*damaged_view),
          "OSPFv2 accepted a payload with a stale packet checksum");

  // RFC 2328 Appendix D excludes the digest from the OSPF Packet Length but
  // includes it in the enclosing IP payload. This fixture proves the parser
  // exposes the suffix without letting Hello parsing consume it.
  std::array<std::uint8_t, 128U> cryptographic_v2{};
  std::copy(encoded_v2->begin(), encoded_v2->end(),
            cryptographic_v2.begin());
  put16(cryptographic_v2, 12U, 0U);
  put16(cryptographic_v2, 14U, 2U);
  cryptographic_v2[16U] = 0U;
  cryptographic_v2[17U] = 0U;
  cryptographic_v2[18U] = 7U;
  cryptographic_v2[19U] = 32U;
  put32(cryptographic_v2, 20U, 0x01020304U);
  std::fill_n(cryptographic_v2.begin() +
                  static_cast<std::ptrdiff_t>(encoded_v2->size()),
              32U, 0x87U);
  const auto cryptographic_view = parse_packet(
      std::span<const std::uint8_t>{
          cryptographic_v2.data(), encoded_v2->size() + 32U});
  require(cryptographic_view &&
              cryptographic_view->packet.size() == encoded_v2->size() &&
              cryptographic_view->authentication_data.size() == 32U &&
              cryptographic_view->authentication[2U] == 7U &&
              verify_version_two_checksum(*cryptographic_view) &&
              parse_hello(*cryptographic_view),
          "OSPFv2 cryptographic trailer was not separated from packet data");
  cryptographic_v2[19U] = 31U;
  require(!parse_packet(std::span<const std::uint8_t>{
              cryptographic_v2.data(), encoded_v2->size() + 32U}),
          "OSPFv2 accepted an authentication length that disagreed with IP");

  std::array<std::uint8_t, 24U> hello_v3{};
  put32(hello_v3, 0U, 17U);
  hello_v3[4U] = 7U;
  hello_v3[5U] = 0U;
  hello_v3[6U] = 0U;
  hello_v3[7U] = 0x13U;
  put16(hello_v3, 8U, 5U);
  put16(hello_v3, 10U, 20U);
  put32(hello_v3, 12U, 0x03030303U);
  put32(hello_v3, 16U, 0x04040404U);
  put32(hello_v3, 20U, 0x05050505U);
  const auto source = address("fe80::1");
  const auto destination = address("ff02::5");

  const auto encoded_v3 = encode_version_three(
      packet_storage, PacketType::hello, 0x01010101U, 0U, 4U, source,
      destination, hello_v3);
  const auto packet_v3 =
      encoded_v3 ? parse_packet(*encoded_v3) : std::nullopt;
  const auto parsed_hello_v3 =
      packet_v3 ? parse_hello(*packet_v3) : std::nullopt;
  require(packet_v3 &&
              verify_version_three_checksum(*packet_v3, source, destination) &&
              packet_v3->instance_id == 4U && parsed_hello_v3 &&
              parsed_hello_v3->interface_id == 17U &&
              parsed_hello_v3->options == 0x13U &&
              parsed_hello_v3->hello_interval_seconds == 5U &&
              parsed_hello_v3->dead_interval_seconds == 20U &&
              hello_neighbor(*parsed_hello_v3, 0U) ==
                  std::optional<std::uint32_t>{0x05050505U},
          "OSPFv3 Hello framing or pseudo-header checksum is incorrect");
  const auto wrong_destination = address("ff02::6");
  require(!verify_version_three_checksum(*packet_v3, source,
                                         wrong_destination),
          "OSPFv3 checksum ignored its IPv6 pseudo-header destination");

  // DD packets carry only LSA headers even though each embedded Length names
  // the complete LSA. The parser must accept that representation but reject
  // unknown flag bits and truncated header lists.
  std::array<std::uint8_t, 28U> dd_v2{};
  put16(dd_v2, 0U, 1500U);
  dd_v2[2U] = 0x02U;
  dd_v2[3U] = 0x07U;
  put32(dd_v2, 4U, 0x10203040U);
  const auto lsa_v2 = router_lsa_header(version_two, 36U);
  std::copy(lsa_v2.begin(), lsa_v2.end(), dd_v2.begin() + 8U);
  const auto encoded_dd = encode_version_two(
      packet_storage, PacketType::database_description, 1U, 0U,
      AuthenticationType::none, std::array<std::uint8_t, 8U>{}, dd_v2);
  const auto dd_packet =
      encoded_dd ? parse_packet(*encoded_dd) : std::nullopt;
  const auto dd = dd_packet ? parse_database_description(*dd_packet)
                            : std::nullopt;
  require(dd && dd->interface_mtu == 1500U && dd->init && dd->more &&
              dd->master && dd->sequence_number == 0x10203040U &&
              lsa_header(dd->lsa_headers, version_two)->length == 36U,
          "OSPFv2 Database Description fields are incorrect");
  std::array<std::uint8_t, 128U> body_storage{};
  const auto written_dd = encode_database_description_payload(
      body_storage, version_two, 1500U, 0x02U, 0x10203040U, true, true,
      true, lsa_v2);
  require(written_dd &&
              std::equal(written_dd->begin(), written_dd->end(),
                         dd_v2.begin(), dd_v2.end()),
          "OSPFv2 Database Description writer drifted from its wire layout");
  require(!encode_database_description_payload(
              body_storage, version_two, 1500U, 0x02U, 0x10203040U,
              true, true, true, lsa_v2, true),
          "OSPFv2 accepted the OSPFv3-only M6 bit");

  std::array<std::uint8_t, 12U> dd_v3_payload{};
  const auto written_dd_v3 = encode_database_description_payload(
      dd_v3_payload, version_three, 1500U, option_address_family,
      0x01020304U, true, false, true, {}, true);
  std::array<std::uint8_t, 128U> dd_v3_packet_storage{};
  const auto encoded_dd_v3 =
      written_dd_v3
          ? encode_version_three(
                dd_v3_packet_storage, PacketType::database_description,
                1U, 0U, 64U, source, destination, *written_dd_v3)
          : std::nullopt;
  const auto parsed_dd_v3_packet =
      encoded_dd_v3 ? parse_packet(*encoded_dd_v3) : std::nullopt;
  const auto parsed_dd_v3 =
      parsed_dd_v3_packet
          ? parse_database_description(*parsed_dd_v3_packet)
          : std::nullopt;
  require(parsed_dd_v3 && parsed_dd_v3->ipv6_mtu_separate &&
              parsed_dd_v3->interface_mtu == 1500U,
          "OSPFv3 M6 did not survive the exact DD wire round trip");

  std::array<std::uint8_t, 24U> request_payload{};
  put32(request_payload, 0U, 1U);
  put32(request_payload, 4U, 0x0a000001U);
  put32(request_payload, 8U, 0x01010101U);
  put32(request_payload, 12U, 2U);
  put32(request_payload, 16U, 0x0a000002U);
  put32(request_payload, 20U, 0x02020202U);
  const auto encoded_request = encode_version_two(
      packet_storage, PacketType::link_state_request, 1U, 0U,
      AuthenticationType::none, std::array<std::uint8_t, 8U>{},
      request_payload);
  const auto request_packet =
      encoded_request ? parse_packet(*encoded_request) : std::nullopt;
  const auto request =
      request_packet ? parse_link_state_request(*request_packet)
                     : std::nullopt;
  require(request && request_entry(*request, 1U) ==
                         std::optional<LinkStateRequestEntry>{
                             {2U, 0x0a000002U, 0x02020202U}} &&
              !request_entry(*request, 2U),
          "OSPF Link State Request iteration is incorrect");
  const std::array request_entries{
      LinkStateRequestEntry{1U, 0x0a000001U, 0x01010101U},
      LinkStateRequestEntry{2U, 0x0a000002U, 0x02020202U}};
  const auto written_request = encode_link_state_request_payload(
      body_storage, version_two, request_entries);
  require(written_request &&
              std::equal(written_request->begin(), written_request->end(),
                         request_payload.begin(), request_payload.end()),
          "OSPF Link State Request writer drifted from its wire layout");

  std::array<std::uint8_t, 24U> update_payload{};
  put32(update_payload, 0U, 1U);
  const auto lsa_v3 = router_lsa_header(version_three, 20U);
  std::copy(lsa_v3.begin(), lsa_v3.end(), update_payload.begin() + 4U);
  const auto encoded_update = encode_version_three(
      packet_storage, PacketType::link_state_update, 1U, 0U, 0U, source,
      destination, update_payload);
  const auto update_packet =
      encoded_update ? parse_packet(*encoded_update) : std::nullopt;
  const auto update =
      update_packet ? parse_link_state_update(*update_packet) : std::nullopt;
  const auto first_lsa = update ? update_lsa(*update, 0U) : std::nullopt;
  require(update && first_lsa && first_lsa->size() == 20U &&
              !update_lsa(*update, 1U),
          "OSPF Link State Update did not validate its complete LSA list");
  const std::array encoded_lsas{EncodedLsa{lsa_v3}};
  const auto written_update = encode_link_state_update_payload(
      body_storage, version_three, encoded_lsas);
  require(written_update &&
              std::equal(written_update->begin(), written_update->end(),
                         update_payload.begin(), update_payload.end()),
          "OSPF Link State Update writer drifted from its wire layout");

  // A declared LSA count greater than the encoded advertisements must reject
  // the whole update. Returning the valid first LSA would let neighbors build
  // different databases from one malformed packet.
  put32(update_payload, 0U, 2U);
  const auto truncated_update = encode_version_three(
      packet_storage, PacketType::link_state_update, 1U, 0U, 0U, source,
      destination, update_payload);
  const auto truncated_packet =
      truncated_update ? parse_packet(*truncated_update) : std::nullopt;
  require(truncated_packet &&
              !parse_link_state_update(*truncated_packet),
          "OSPF accepted an LSU whose count exceeds its encoded LSA list");

  const auto encoded_ack = encode_version_three(
      packet_storage, PacketType::link_state_acknowledgment, 1U, 0U, 0U,
      source, destination, lsa_v3);
  const auto ack_packet =
      encoded_ack ? parse_packet(*encoded_ack) : std::nullopt;
  const auto ack =
      ack_packet ? parse_link_state_acknowledgment(*ack_packet)
                 : std::nullopt;
  require(ack && acknowledgment_header(*ack, 0U)->type == 0x2001U &&
              !acknowledgment_header(*ack, 1U),
          "OSPF Link State Acknowledgment header iteration is incorrect");
  const auto written_ack = encode_link_state_acknowledgment_payload(
      body_storage, version_three, lsa_v3);
  require(written_ack &&
              std::equal(written_ack->begin(), written_ack->end(),
                         lsa_v3.begin(), lsa_v3.end()),
          "OSPF Link State Acknowledgment writer changed LSA header bytes");
}
