// IS-IS PDUs travel as encoded bytes through physical fabric TX/in-flight/RX
// stages and a learning bridge's port queues. No protocol peer calls are used.

#include "router/ethernet_switch.hpp"
#include "router/isis_ethernet.hpp"
#include "router/multi_device_fabric.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

struct Medium {
  router::lab::MultiDeviceFabric &fabric;
  router::lab::EthernetSwitch &bridge;
  router::lab::MultiDeviceFabric::Clock::time_point now;
  std::span<const std::uint8_t> expected;
  std::array<unsigned, 3U> deliveries{};
};

void delivered(void *opaque, const router::lab::MultiDeviceFabric::Delivery &delivery) {
  using namespace router;
  using namespace router::lab;
  auto &medium = *static_cast<Medium *>(opaque);
  if (delivery.destination.node.kind == NodeKind::ethernet_switch) {
    const auto result = medium.bridge.ingress(delivery.destination.ordinal, delivery.frame, medium.now);
    require(result.admitted_egresses == 2U && !result.malformed,
            "IS-IS multicast did not enter two bridge port queues");
    for (std::uint16_t port = 0U; port < 3U; ++port) {
      while (const auto output = medium.bridge.dequeue(port)) {
        const auto admitted = medium.fabric.enqueue({port, 1U}, 1U, *output->frame);
        medium.bridge.release(output->handle);
        require(admitted == MultiDeviceFabric::DropReason::none,
                "IS-IS bridge egress did not enter its physical link queue");
      }
    }
    return;
  }
  packet::isis::EthernetDecodeError error;
  const auto pdu = packet::isis::parse_ethernet_pdu(delivery.frame.view(), error);
  require(pdu && std::ranges::equal(pdu->pdu.bytes, medium.expected),
          "IS-IS physical delivery changed encoded PDU bytes");
  require(delivery.destination.node.index < medium.deliveries.size(), "IS-IS unexpected physical endpoint");
  ++medium.deliveries[delivery.destination.node.index];
}
}

void isis_ethernet_fabric_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  auto fabric = std::make_unique<MultiDeviceFabric>();
  const auto &profile = device_catalog::ethernet_switch_profiles[0U];
  EthernetSwitch bridge(profile, fabric->packet_pool());
  const SwitchHandle switch_id{0U, 1U};
  const SwitchPortConfiguration up{profile.default_speed_mbps, profile.maximum_mtu, true, true};
  for (std::uint16_t port = 0U; port < 3U; ++port) {
    require(bridge.configure_port(port, up) && fabric->configure({port, 1U},
              {node(DeviceHandle{port, 1U}), 0U, 1U}, {node(switch_id), port, 1U},
              std::uint64_t{profile.default_speed_mbps} * 1'000'000U, 100ns, true),
            "IS-IS physical broadcast-domain setup failed");
  }
  const packet::Mac source{2U, 0U, 0U, 0U, 0U, 1U};
  const packet::Mac destination{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  const SystemId system{1U, 2U, 3U, 4U, 5U, 6U};
  const std::array<PduType, 9U> types{PduType::lan_hello_l1, PduType::lan_hello_l2,
      PduType::point_to_point_hello, PduType::lsp_l1, PduType::lsp_l2,
      PduType::csnp_l1, PduType::csnp_l2, PduType::psnp_l1, PduType::psnp_l2};
  Medium medium{*fabric, bridge, MultiDeviceFabric::Clock::time_point{100s}, {}, {}};
  std::array<std::uint8_t, 128U> bytes{};
  for (const auto type : types) {
    std::optional<std::span<const std::uint8_t>> pdu;
    if (type == PduType::lan_hello_l1 || type == PduType::lan_hello_l2 || type == PduType::point_to_point_hello)
      pdu = encode_hello(bytes, {type, system, 30U, 3U, 1U, 64U, {}}, {});
    else if (type == PduType::lsp_l1 || type == PduType::lsp_l2)
      pdu = encode_lsp(bytes, {type, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U}, {});
    else pdu = encode_snp(bytes, {type, system, {}, {}}, {});
    packet::Frame frame{};
    auto target = destination;
    if (type == PduType::lan_hello_l2 || type == PduType::lsp_l2 ||
        type == PduType::csnp_l2 || type == PduType::psnp_l2) target.back() = 0x15U;
    require(pdu && packet::isis::ethernet_pdu_into(frame, source, target, *pdu),
            "IS-IS physical PDU fixture encoding failed");
    medium.expected = *pdu;
    medium.deliveries = {};
    require(fabric->enqueue({0U, 1U}, 0U, frame) == MultiDeviceFabric::DropReason::none,
            "IS-IS source port rejected an encoded frame");
    frame.bytes[17U] = 0U;
    fabric->pump_transmit(medium.now);
    medium.now += 1ms;
    fabric->pump_delivery(&medium, delivered, medium.now);
    fabric->pump_transmit(medium.now);
    medium.now += 1ms;
    fabric->pump_delivery(&medium, delivered, medium.now);
    require(medium.deliveries == std::array<unsigned, 3U>{0U, 1U, 1U} &&
              fabric->available_packets() == PacketPool::capacity,
            "IS-IS broadcast domain leaked, duplicated or retained a packet");
  }
  require(fabric->set_carrier({0U, 1U}, false), "IS-IS carrier-loss setup failed");
  packet::Frame frame{};
  require(fabric->enqueue({0U, 1U}, 0U, frame) == MultiDeviceFabric::DropReason::carrier_down,
          "IS-IS frame bypassed a down physical link");
}
