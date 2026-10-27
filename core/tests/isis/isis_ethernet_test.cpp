// Encoded PDU fixtures cross the actual Ethernet adapter, including jumbo
// padding and aliasing. Destination selection remains explicit test input.

#include "router/isis_ethernet.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_ethernet_tests() {
  using namespace router::packet;
  using namespace router::packet::isis;
  const Mac source{2U, 0U, 0U, 0U, 0U, 1U};
  const Mac destination{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  std::array<std::uint8_t, 2048U> bytes{};
  const HelloInput input{PduType::point_to_point_hello, {1U, 2U, 3U, 4U, 5U, 6U},
                         30U, 3U, 7U, 0U, {}};
  const auto hello = encode_hello(bytes, input, {});
  require(hello.has_value(), "IS-IS Ethernet Hello fixture failed");
  Frame frame{};
  require(ethernet_pdu_into(frame, source, destination, *hello), "IS-IS Ethernet Hello encoding failed");
  EthernetDecodeError error;
  const auto decoded = parse_ethernet_pdu(frame.view(), error);
  require(decoded && error.envelope == EthernetError::none &&
            decoded->ethernet.destination == destination && std::ranges::equal(decoded->pdu.bytes, *hello),
          "IS-IS Ethernet padding changed the PDU boundary");
  auto malformed = frame;
  malformed.bytes[15U] = 0xffU;
  require(!parse_ethernet_pdu(malformed.view(), error) && error.envelope == EthernetError::network_sap,
          "IS-IS accepted a non-ISO source SAP");
  malformed = frame;
  malformed.bytes[17U] = 0x81U;
  require(!parse_ethernet_pdu(malformed.view(), error) && error.envelope == EthernetError::pdu &&
            error.pdu == DecodeError::discriminator, "IS-IS accepted a different NLPID");
  malformed = frame;
  malformed.bytes[16U] = 0U;
  require(!parse_ethernet_pdu(malformed.view(), error) && error.envelope == EthernetError::llc_envelope,
          "IS-IS accepted a non-UI control frame");
  const auto saved = frame;
  require(!ethernet_pdu_into(frame, source, destination, {}) && frame.bytes == saved.bytes &&
            frame.length == saved.length, "IS-IS malformed transmit changed output");
  std::copy(hello->begin(), hello->end(), frame.bytes.begin());
  require(ethernet_pdu_into(frame, source, destination, std::span(frame.bytes).first(hello->size())) &&
            std::ranges::equal(parse_ethernet_pdu(frame.view(), error)->pdu.bytes, *hello),
          "IS-IS aliased PDU was overwritten by its Ethernet prefix");
  std::array<std::uint8_t, 1600U> padding{};
  TlvWriter writer(padding);
  require(writer.pad_to(padding.size()), "IS-IS jumbo option fixture failed");
  const auto jumbo = encode_hello(bytes, input, writer.bytes());
  require(jumbo && ethernet_pdu_into(frame, source, destination, *jumbo) &&
            frame.bytes[12U] == 0x88U && frame.bytes[13U] == 0x70U,
          "IS-IS jumbo frame did not use LLC encapsulation EtherType");
  const auto large = parse_ethernet_pdu(frame.view(), error);
  require(large && std::ranges::equal(large->pdu.bytes, *jumbo), "IS-IS jumbo PDU did not round-trip");
}
