// Three LAN circuit owners discover each other only through encoded Hellos,
// physical queues and a learning bridge. Injected owner-local deadlines prove
// election delay, two-way admission and DIS replacement after carrier loss.

#include "router/isis_lan_circuit.hpp"
#include "router/ethernet_switch.hpp"
#include "router/multi_device_fabric.hpp"

#include <memory>
#include <source_location>
#include <stdexcept>

namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS LAN circuit owner invariant failed at line " +
      std::to_string(location.line()));
}
LanCircuitConfiguration configuration(std::uint8_t id) {
  LanCircuitConfiguration result;
  result.mac = {2U, 0U, 0U, 0U, 0U, id};
  result.local = {{1U, 2U, 3U, 4U, 5U, id}, result.mac, 64U, id};
  result.levels = Levels::both;
  result.type = packet::isis::PduType::lan_hello_l1;
  result.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  NeighborArea area;
  area.bytes[0U] = 0x49U;
  area.bytes[2U] = 1U;
  area.length = 3U;
  result.areas.push_back(area);
  result.protocols = {packet::isis::ipv4_nlpid};
  result.ipv4_addresses.push_back({192U, 0U, 2U, id});
  result.maximum_area_addresses = 3U;
  result.holding_seconds = result.designated_holding_seconds = 3U;
  result.hello_interval = result.designated_hello_interval = 1s;
  result.maximum_pdu_octets = 1492U;
  result.limits = {4U, 3U};
  return result;
}
struct Events { unsigned up{}, down{}, changes{}; bool old_areas{true}; };
void peer(void *opaque, const LanPeerEvent &value) noexcept {
  auto &events = *static_cast<Events *>(opaque);
  if (value.transition.outcome == LanOutcome::up) ++events.up;
  if (value.transition.outcome == LanOutcome::down) {
    ++events.down;
    events.old_areas = events.old_areas && !value.before.areas.empty();
  }
}
void designated(void *opaque, const std::optional<DisSelection> &,
    const std::optional<DisSelection> &) noexcept {
  ++static_cast<Events *>(opaque)->changes;
}
struct Context {
  std::array<std::unique_ptr<LanCircuit>, 3U> circuits;
  std::array<Events, 3U> events;
  lab::EthernetSwitch &bridge;
  LanCircuit::Clock::time_point now;
  std::size_t active{3U};
  LanCircuitObserver observer(std::size_t index) { return {&events[index], peer, designated}; }
};
void delivered(void *opaque, const lab::MultiDeviceFabric::Delivery &delivery) {
  auto &context = *static_cast<Context *>(opaque);
  if (delivery.destination.node.kind == lab::NodeKind::ethernet_switch) {
    require(!context.bridge.ingress(delivery.destination.ordinal, delivery.frame, context.now).malformed);
  } else if (delivery.destination.node.index < context.active) {
    const auto index = delivery.destination.node.index;
    require(context.circuits[index]->receive(delivery.frame, std::nullopt, context.now,
        context.observer(index)) == LanCircuitReceive::accepted);
  }
}
}

void isis_lan_circuit_tests() {
  auto pool = std::make_unique<PacketPool>();
  lab::EthernetSwitch bridge(device_catalog::ethernet_switch_profiles[0U], *pool);
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const auto start = LanCircuit::Clock::time_point{100s};
  Context context{{}, {}, bridge, start};
  auto scratch = std::make_unique<PduScratch>();
  for (std::uint16_t index{}; index < 3U; ++index) {
    context.circuits[index] = std::make_unique<LanCircuit>(
        configuration(static_cast<std::uint8_t>(index + 1U)), index + 123U, start);
    require(bridge.configure_port(index, {1000U, 1514U, true, true}));
    require(fabric->configure({index, 1U}, {lab::node(lab::DeviceHandle{index, 1U}), 0U, 1U},
        {lab::node(lab::SwitchHandle{0U, 1U}), index, 1U}, 1'000'000'000U, 100ns, true));
  }
  const auto round = [&](LanCircuit::Clock::time_point now) {
    context.now = now;
    for (std::uint16_t index{}; index < context.active; ++index) {
      packet::Frame frame;
      require(context.circuits[index]->hello(frame, std::nullopt, *scratch, now,
          context.observer(index)) == HelloBuildResult::encoded);
      const bool admitted = fabric->enqueue({index, 1U}, 0U, frame) == lab::MultiDeviceFabric::DropReason::none;
      require(admitted && context.circuits[index]->complete_hello(admitted, now));
    }
    for (unsigned flight{}; flight < 3U; ++flight) {
      fabric->pump_transmit(context.now);
      context.now += 1ms;
      fabric->pump_delivery(&context, delivered, context.now);
    }
    for (std::uint16_t index{}; index < context.active; ++index) {
      while (const auto frame = bridge.dequeue(index)) {
        require(fabric->enqueue({index, 1U}, 1U, *frame->frame) == lab::MultiDeviceFabric::DropReason::none);
        bridge.release(frame->handle);
      }
    }
    for (unsigned flight{}; flight < 3U; ++flight) {
      fabric->pump_transmit(context.now);
      context.now += 1ms;
      fabric->pump_delivery(&context, delivered, context.now);
    }
  };
  round(start);
  for (const auto &circuit : context.circuits)
    require(circuit->neighbors().size() == 2U && !circuit->designated());
  round(start + 1s);
  for (std::size_t index{}; index < 3U; ++index)
    require(context.events[index].up == 2U && !context.circuits[index]->designated());
  auto stranger_configuration = configuration(4U);
  stranger_configuration.mac = configuration(3U).mac;
  stranger_configuration.local.mac = stranger_configuration.mac;
  stranger_configuration.protocols = {packet::isis::ipv6_nlpid};
  LanCircuit stranger(std::move(stranger_configuration), 444U, start + 1500ms);
  Events stranger_events;
  packet::Frame stranger_frame;
  const LanCircuitObserver stranger_observer{&stranger_events, peer, designated};
  require(stranger.hello(stranger_frame, std::nullopt, *scratch, start + 1500ms,
      stranger_observer) == HelloBuildResult::encoded);
  require(context.circuits[0U]->receive(stranger_frame, std::nullopt, start + 1500ms,
      context.observer(0U)) == LanCircuitReceive::discarded &&
      context.circuits[0U]->neighbors().find(configuration(3U).mac)->adjacency.system.back() == 3U &&
      context.events[0U].down == 0U);
  round(start + 2s);
  for (std::size_t index{}; index < 3U; ++index) {
    const auto selected = context.circuits[index]->designated();
    require(selected && selected->system.back() == 3U && selected->local == (index == 2U));
  }
  require(context.circuits[2U]->down(context.observer(2U)) &&
      context.events[2U].down == 2U && context.events[2U].old_areas);
  context.active = 2U;
  require(fabric->set_carrier({2U, 1U}, false) && bridge.configure_port(2U, {1000U, 1514U, true, false}));
  round(start + 3s);
  round(start + 4s);
  for (std::size_t index{}; index < 2U; ++index) {
    context.circuits[index]->service(start + 5s + 10ms, 4U, context.observer(index));
    const auto selected = context.circuits[index]->designated();
    require(selected && selected->system.back() == 2U && selected->local == (index == 1U) &&
        context.circuits[index]->neighbors().size() == 1U && context.events[index].down == 1U &&
        context.events[index].old_areas);
  }
}
