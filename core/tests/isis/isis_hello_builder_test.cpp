// Complete Hello fixtures verify option splitting, IID placement, IPv6 scope,
// padding edge cases and authentication over the final Ethernet-carried PDU.

#include "router/isis_hello_builder.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_hello_builder_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  auto scratch = std::make_unique<HelloScratch>();
  packet::Frame frame{};
  const std::array<std::uint8_t, 3U> area{0x49U, 0U, 1U};
  const std::array<std::span<const std::uint8_t>, 1U> areas{area};
  const std::array<std::uint8_t, 2U> protocols{ipv4_nlpid, ipv6_nlpid};
  const std::array<packet::Ipv4, 1U> ipv4{{{192U, 0U, 2U, 1U}}};
  std::array<packet::Ipv6, 16U> ipv6{};
  for (std::size_t index = 0U; index < ipv6.size(); ++index) {
    ipv6[index][0U] = 0xfeU;
    ipv6[index][1U] = 0x80U;
    ipv6[index].back() = static_cast<std::uint8_t>(index + 1U);
  }
  const std::array<std::uint16_t, 1U> topologies{0U};
  const std::array<TopologyComponent, 2U> mt_components{{{0U}, {2U}}};
  std::array<std::uint8_t, 40U> key{};
  key.fill(0x4bU);
  HelloContents contents;
  contents.header = {PduType::point_to_point_hello, {1U, 2U, 3U, 4U, 5U, 6U}, 27U, 3U, 1U};
  contents.source = {2U, 0U, 0U, 0U, 0U, 1U};
  contents.destination = {1U, 0U, 0x5eU, 0x90U, 0U, 2U};
  contents.areas = areas;
  contents.protocols = protocols;
  contents.topologies = mt_components;
  contents.ipv4_addresses = ipv4;
  contents.ipv6_addresses = ipv6;
  contents.three_way = ThreeWayOption{ThreeWayState::down, 1001U, std::nullopt, std::nullopt};
  contents.instance = HelloInstanceOption{InstanceFormat::standard, 7U, topologies};
  contents.authentication = AuthenticationKey{AuthenticationMethod::hmac_sha256, 512U, key};
  contents.maximum_pdu_octets = 1492U;
  contents.padding = true;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::encoded,
          "IS-IS complete authenticated Hello construction failed");
  EthernetDecodeError error;
  const auto decoded = parse_ethernet_pdu(frame.view(), error);
  require(decoded && decoded->pdu.bytes.size() >= 1491U && decoded->pdu.bytes.size() <= 1492U &&
            verify_authentication(decoded->pdu.bytes, *contents.authentication) == AuthenticationError::none,
          "IS-IS Hello authentication did not cover final padding");
  require(supports_topology(decoded->pdu, 0U) == true && supports_topology(decoded->pdu, 2U) == true,
          "IS-IS Hello confused MT membership with instance-specific topology zero");
  TlvCursor cursor(decoded->pdu.tlvs);
  const auto first = cursor.next();
  require(first && first->code == 7U, "IS-IS Hello did not place IID before other options");
  unsigned ipv6_options{};
  while (const auto tlv = cursor.next()) {
    if (tlv->code == 232U) {
      ++ipv6_options;
      require(valid_ipv6_interface_addresses(*tlv, contents.header.type), "IS-IS Hello advertised a global IPv6 address");
    }
  }
  require(cursor.valid() && ipv6_options == 2U, "IS-IS Hello did not split a full IPv6 address list");
  auto damaged = frame;
  damaged.bytes[damaged.length - 1U] ^= 1U;
  const auto changed = parse_ethernet_pdu(damaged.view(), error);
  require(changed && verify_authentication(changed->pdu.bytes, *contents.authentication) == AuthenticationError::mismatch,
          "IS-IS Hello padding corruption was not authenticated");

  contents.padding = false;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::encoded, "IS-IS unpadded Hello failed");
  const auto unpadded = parse_ethernet_pdu(frame.view(), error)->pdu.bytes.size();
  contents.maximum_pdu_octets = unpadded + 1U;
  contents.padding = true;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::encoded &&
            parse_ethernet_pdu(frame.view(), error)->pdu.bytes.size() == unpadded,
          "IS-IS one-octet padding gap exceeded the allowed PDU maximum");
  const auto saved = frame;
  contents.maximum_pdu_octets = unpadded - 1U;
  require(build_hello_frame(frame, contents, *scratch) != HelloBuildResult::encoded &&
            frame.length == saved.length && frame.bytes == saved.bytes,
          "IS-IS failed Hello capacity changed the prior output frame");
  contents.maximum_pdu_octets = 1492U;
  const auto link_local = ipv6[0U];
  ipv6[0U][0U] = 0x20U;
  ipv6[0U][1U] = 0x01U;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::addresses,
          "IS-IS Hello builder accepted a non-link-local IPv6 address");
  ipv6[0U] = link_local;

  contents.header.type = PduType::lan_hello_l1;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::three_way,
          "IS-IS LAN Hello accepted a P2P handshake option");
  contents.three_way.reset();
  contents.authentication.reset();
  contents.instance.reset();
  contents.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  std::array<packet::Mac, 43U> neighbors{};
  for (std::size_t index = 0U; index < neighbors.size(); ++index)
    neighbors[index] = {2U, 0U, 0U, 0U, 1U, static_cast<std::uint8_t>(index)};
  contents.neighbors = neighbors;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::encoded,
          "IS-IS LAN Hello with a split neighbor list failed");
  const auto lan = parse_ethernet_pdu(frame.view(), error);
  TlvCursor options(lan->pdu.tlvs);
  unsigned neighbor_options{};
  std::size_t count{};
  while (const auto tlv = options.next()) {
    if (tlv->code != 6U) continue;
    ++neighbor_options;
    FixedAddressCursor<6U> addresses(*tlv, 6U);
    while (addresses.next()) ++count;
    require(addresses.valid(), "IS-IS split LAN neighbor TLV was malformed");
  }
  require(neighbor_options == 2U && count == neighbors.size(), "IS-IS Hello lost neighbors at the TLV boundary");
  std::array<TopologyComponent, 128U> many_topologies{};
  for (std::size_t index = 0U; index < many_topologies.size(); ++index)
    many_topologies[index].id = static_cast<std::uint16_t>(index);
  contents.topologies = many_topologies;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::encoded,
          "IS-IS Hello could not split a full topology membership list");
  const auto many = parse_ethernet_pdu(frame.view(), error);
  TlvCursor many_options(many->pdu.tlvs);
  unsigned topology_options{};
  std::size_t topology_count{};
  while (const auto option = many_options.next()) {
    if (option->code != 229U) continue;
    ++topology_options;
    TopologyCursor components(*option);
    while (components.next()) ++topology_count;
    require(components.valid(), "IS-IS split topology option was malformed");
  }
  require(topology_options == 2U && topology_count == many_topologies.size() &&
            supports_topology(many->pdu, 127U) == true,
          "IS-IS Hello lost membership across the topology TLV boundary");
  const auto many_saved = frame;
  many_topologies.back().overloaded = true;
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::topologies &&
            frame.length == many_saved.length && frame.bytes == many_saved.bytes,
          "IS-IS invalid Hello topology flags changed the prior output frame");
  contents.topologies = mt_components;
  contents.instance = HelloInstanceOption{InstanceFormat::standard, 0U, {}};
  require(build_hello_frame(frame, contents, *scratch) == HelloBuildResult::instance,
          "IS-IS LAN Hello emitted an explicit standard IID zero");
}
