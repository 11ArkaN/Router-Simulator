// Two independent P2P owners learn only from encoded Hello frames delivered
// by physical queues and a link. A one-way failure exercises handshake loss.

#include "router/isis_basic_tlvs.hpp"
#include "router/isis_ethernet.hpp"
#include "router/isis_hello_builder.hpp"
#include "router/isis_p2p_adjacency.hpp"
#include "router/multi_device_fabric.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
struct Endpoint {
  router::isis::P2pLocal local;
  router::isis::PointToPointAdjacency adjacency;
  router::packet::Mac mac;
  router::packet::Ipv4 address;
  std::array<std::uint8_t, 3U> area;
  router::isis::HelloScratch scratch;
  unsigned received{};
  Endpoint(router::isis::P2pLocal configuration, router::packet::Mac source, router::packet::Ipv4 ipv4,
           std::array<std::uint8_t, 3U> manual_area)
      : local(configuration), adjacency(configuration), mac(source), address(ipv4), area(manual_area) {}
};
struct Context {
  std::array<Endpoint *, 2U> endpoints;
  router::lab::MultiDeviceFabric::Clock::time_point now;
};
void receive(void *opaque, const router::lab::MultiDeviceFabric::Delivery &delivery) {
  using namespace router;
  using namespace router::packet::isis;
  auto &context = *static_cast<Context *>(opaque);
  require(delivery.destination.node.index < context.endpoints.size(), "IS-IS P2P wire endpoint mismatch");
  auto &endpoint = *context.endpoints[delivery.destination.node.index];
  EthernetDecodeError error;
  const auto frame = parse_ethernet_pdu(delivery.frame.view(), error);
  require(frame && frame->pdu.type == PduType::point_to_point_hello, "IS-IS P2P wire envelope rejected");
  const auto header = hello(frame->pdu);
  bool common_area{};
  bool ipv4{};
  bool address_present{};
  std::optional<TlvView> three_way;
  TlvCursor cursor(frame->pdu.tlvs);
  while (const auto tlv = cursor.next()) {
    if (tlv->code == 1U) {
      AreaAddressCursor areas(*tlv);
      while (const auto area = areas.next()) common_area = common_area || std::ranges::equal(*area, endpoint.area);
      require(areas.valid(), "IS-IS P2P wire area list malformed");
    } else if (tlv->code == 129U) ipv4 = supports_protocol(*tlv, ipv4_nlpid);
    else if (tlv->code == 132U) {
      FixedAddressCursor<4U> addresses(*tlv, 132U);
      while (addresses.next()) address_present = true;
      require(addresses.valid(), "IS-IS P2P wire IPv4 address list malformed");
    } else if (tlv->code == 240U) three_way = *tlv;
  }
  require(cursor.valid() && header && ipv4 && address_present && three_way,
          "IS-IS P2P wire mandatory Hello fields missing");
  const auto result = endpoint.adjacency.receive(*header, frame->ethernet.source, common_area,
                                                 frame->pdu.maximum_area_addresses == 3U, three_way, context.now);
  require(result.holding_refreshed, "IS-IS P2P wire Hello did not advance its local owner");
  ++endpoint.received;
}
router::packet::Frame transmit(Endpoint &endpoint) {
  using namespace router::packet;
  using namespace router::packet::isis;
  const std::array<std::span<const std::uint8_t>, 1U> area{endpoint.area};
  const std::array<std::uint8_t, 1U> protocols{ipv4_nlpid};
  const std::array<router::packet::Ipv4, 1U> addresses{endpoint.address};
  Frame frame{};
  router::isis::HelloContents contents;
  contents.header = {PduType::point_to_point_hello, endpoint.local.system,
      3U, static_cast<std::uint8_t>(endpoint.local.levels), endpoint.local.local_circuit};
  contents.source = endpoint.mac;
  contents.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  contents.areas = area;
  contents.protocols = protocols;
  contents.ipv4_addresses = addresses;
  contents.three_way = endpoint.adjacency.outbound_three_way();
  contents.maximum_pdu_octets = 1492U;
  contents.padding = true;
  require(router::isis::build_hello_frame(frame, contents, endpoint.scratch) == router::isis::HelloBuildResult::encoded,
          "IS-IS P2P wire Hello encoding failed");
  return frame;
}
}

void isis_p2p_wire_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::lab;
  using namespace std::chrono_literals;
  Endpoint a({{1U, 2U, 3U, 4U, 5U, 6U}, 1001U, 1U, Levels::both, true},
               {2U, 0U, 0U, 0U, 0U, 1U}, {192U, 0U, 2U, 1U}, {0x49U, 0U, 1U});
  Endpoint b({{1U, 2U, 3U, 4U, 5U, 7U}, 1002U, 2U, Levels::both, true},
               {2U, 0U, 0U, 0U, 0U, 2U}, {192U, 0U, 2U, 2U}, {0x49U, 0U, 1U});
  auto fabric = std::make_unique<MultiDeviceFabric>();
  const LinkHandle cable{0U, 1U};
  require(fabric->configure(cable, {node(DeviceHandle{0U, 1U}), 0U, 1U},
              {node(DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 100ns, true),
          "IS-IS P2P wire physical setup failed");
  Context context{{&a, &b}, MultiDeviceFabric::Clock::time_point{100s}};
  const auto round = [&](bool first_direction) {
    if (first_direction) require(fabric->enqueue(cable, 0U, transmit(a)) == MultiDeviceFabric::DropReason::none,
                                 "IS-IS P2P wire source queue refused Hello");
    require(fabric->enqueue(cable, 1U, transmit(b)) == MultiDeviceFabric::DropReason::none,
            "IS-IS P2P wire return queue refused Hello");
    fabric->pump_transmit(context.now);
    context.now += 1ms;
    fabric->pump_delivery(&context, receive, context.now);
  };
  round(true);
  require(!a.adjacency.ready() && !b.adjacency.ready() &&
            a.adjacency.snapshot().three_way == ThreeWayState::initializing &&
            b.adjacency.snapshot().three_way == ThreeWayState::initializing,
          "IS-IS P2P adjacency became usable after only one-way knowledge");
  round(true);
  require(a.adjacency.ready() && b.adjacency.ready() && a.received == 2U && b.received == 2U,
          "IS-IS P2P owners did not converge from physical Hello delivery");
  const auto last_b_deadline = b.adjacency.deadline();
  for (unsigned turn = 0U; turn < 2U; ++turn) {
    context.now += 1s;
    round(false);
  }
  require(b.adjacency.deadline() == last_b_deadline && a.adjacency.ready(),
          "IS-IS missing forward Hellos were refreshed through a peer side channel");
  context.now = *last_b_deadline;
  require(b.adjacency.expire(context.now).reason == P2pReason::holding_expired && !b.adjacency.ready(),
          "IS-IS one-way loss did not expire the receiving adjacency");
  round(false);
  require(!a.adjacency.ready() && a.adjacency.snapshot().three_way == ThreeWayState::initializing &&
            fabric->available_packets() == PacketPool::capacity,
          "IS-IS surviving direction retained usable adjacency or leaked physical frames");
}
