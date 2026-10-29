// Two complete circuit owners exchange their scheduled, authenticated Hellos
// only through physical link queues. Invalid input cannot refresh holding or
// publish partially retained peer attributes; Down observers retain old data.

#include "router/isis_p2p_circuit.hpp"
#include "router/multi_device_fabric.hpp"

#include <array>
#include <memory>
#include <stdexcept>

namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value) {
  if (!value) throw std::runtime_error("IS-IS P2P circuit owner invariant failed");
}
P2pCircuitConfiguration configuration(std::uint8_t id) {
  P2pCircuitConfiguration result;
  result.local = {{1U, 2U, 3U, 4U, 5U, id}, id, id, Levels::both, true};
  result.mac = {2U, 0U, 0U, 0U, 0U, id};
  result.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  NeighborArea area;
  area.bytes[0U] = 0x49U;
  area.bytes[2U] = 1U;
  area.length = 3U;
  result.areas.push_back(area);
  result.protocols.push_back(packet::isis::ipv4_nlpid);
  result.ipv4_addresses.push_back({192U, 0U, 2U, id});
  result.maximum_area_addresses = 3U;
  result.holding_seconds = 3U;
  result.hello_interval = 1s;
  result.maximum_pdu_octets = 1492U;
  result.peer_attribute_octets = 512U;
  result.padding = true;
  result.receive_authentication = true;
  result.transmit_authentication = true;
  return result;
}
struct Events { unsigned up{}; unsigned down{}; bool old_attributes_preserved{true}; };
void event(void *opaque, const P2pCircuitEvent &value) noexcept {
  auto &events = *static_cast<Events *>(opaque);
  if (value.transition.forwarding_readiness_changed && value.after.iso_up) ++events.up;
  if (value.transition.outcome == P2pOutcome::down) {
    ++events.down;
    events.old_attributes_preserved = events.old_attributes_preserved && !value.previous_attributes.empty();
  }
}
struct Context {
  std::array<PointToPointCircuit *, 2U> circuits;
  std::array<Events, 2U> events;
  AuthenticationKey key;
  PointToPointCircuit::Clock::time_point now;
};
void delivered(void *opaque, const lab::MultiDeviceFabric::Delivery &delivery) {
  auto &context = *static_cast<Context *>(opaque);
  const auto index = delivery.destination.node.index;
  require(index < context.circuits.size());
  require(context.circuits[index]->receive(delivery.frame, context.key, context.now,
      &context.events[index], event) == CircuitReceive::accepted);
}
}

void isis_p2p_circuit_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::lab;
  using namespace std::chrono_literals;
  const auto start = PointToPointCircuit::Clock::time_point{100s};
  PointToPointCircuit a(configuration(1U), 123U, start);
  PointToPointCircuit b(configuration(2U), 456U, start);
  const std::array<std::uint8_t, 32U> secret{0x5aU, 1U, 2U, 3U};
  const AuthenticationKey key{AuthenticationMethod::hmac_sha256, 7U, secret};
  Context context{{&a, &b}, {}, key, start};
  auto fabric = std::make_unique<MultiDeviceFabric>();
  auto scratch = std::make_unique<PduScratch>();
  const LinkHandle cable{0U, 1U};
  require(fabric->configure(cable, {node(DeviceHandle{0U, 1U}), 0U, 1U},
      {node(DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 100ns, true));
  packet::Frame last{};
  const auto round = [&] {
    for (std::uint8_t index{}; index < 2U; ++index) {
      packet::Frame frame{};
      auto &circuit = *context.circuits[index];
      require(circuit.hello(frame, key, *scratch, context.now) == HelloBuildResult::encoded);
      const bool accepted = fabric->enqueue(cable, index, frame) == MultiDeviceFabric::DropReason::none;
      require(circuit.complete_hello(accepted, context.now) && accepted);
      if (index == 1U) last = frame;
    }
    fabric->pump_transmit(context.now);
    context.now += 1ms;
    fabric->pump_delivery(&context, delivered, context.now);
  };
  round();
  require(a.adjacency().three_way == ThreeWayState::initializing && !a.adjacency().iso_up);
  round();
  require(a.adjacency().iso_up && b.adjacency().iso_up && context.events[0U].up == 1U &&
      context.events[1U].up == 1U && !a.peer_attributes().empty());
  packet::isis::TlvCursor attributes(a.peer_attributes());
  bool peer_address{};
  while (const auto option = attributes.next()) if (option->code == 132U) {
    packet::isis::FixedAddressCursor<4U> addresses(*option, 132U);
    peer_address = addresses.next() == std::optional<packet::Ipv4>{{192U, 0U, 2U, 2U}};
  }
  require(attributes.valid() && peer_address);
  const auto last_received = context.now;
  require(a.receive(last, std::nullopt, last_received + 1s, &context.events[0U], event) == CircuitReceive::authentication);
  auto wrong = last;
  wrong.bytes[100U] ^= 1U;
  require(a.receive(wrong, key, last_received + 2s, &context.events[0U], event) == CircuitReceive::authentication);
  require(a.expire(last_received + 3s, &context.events[0U], event) && !a.adjacency().present &&
      a.peer_attributes().empty() && context.events[0U].down == 1U && context.events[0U].old_attributes_preserved);
  auto limited = configuration(3U);
  limited.peer_attribute_octets = 1U;
  PointToPointCircuit small(std::move(limited), 789U, start);
  Events small_events;
  require(small.receive(last, key, start, &small_events, event) == CircuitReceive::capacity &&
      !small.adjacency().present && small.peer_attributes().empty());
  auto other = configuration(3U);
  other.emit_instance = true;
  other.instance_format = packet::isis::InstanceFormat::standard;
  other.wire_instance = 1U;
  other.instance_topologies = {0U};
  PointToPointCircuit isolated(std::move(other), 777U, start);
  require(isolated.receive(last, key, start, &small_events, event) == CircuitReceive::instance &&
      !isolated.adjacency().present);
  require(b.down(&context.events[1U], event) && context.events[1U].down == 1U &&
      context.events[1U].old_attributes_preserved && fabric->available_packets() == PacketPool::capacity);
  require(!b.operational() && b.deadline() == PointToPointCircuit::Clock::time_point::max() &&
      !b.hello(last, key, *scratch, context.now) && !b.complete_hello(true, context.now));
  require(b.up(context.now) && !b.up(context.now) && b.operational() &&
      b.hello(last, key, *scratch, context.now) == HelloBuildResult::encoded &&
      b.complete_hello(true, context.now) && !b.adjacency().present);
  auto strict_configuration = configuration(1U);
  strict_configuration.strict_adjacency_check = true;
  PointToPointCircuit strict(std::move(strict_configuration), 123U, start);
  PointToPointCircuit remote(configuration(2U), 456U, start);
  Events strict_events, remote_events;
  for (unsigned round_index{}; round_index < 2U; ++round_index) {
    packet::Frame first, second;
    require(strict.hello(first, key, *scratch, start) == HelloBuildResult::encoded &&
        strict.complete_hello(true, start));
    require(remote.hello(second, key, *scratch, start) == HelloBuildResult::encoded &&
        remote.complete_hello(true, start));
    require(strict.receive(second, key, start, &strict_events, event) == CircuitReceive::accepted);
    require(remote.receive(first, key, start, &remote_events, event) == CircuitReceive::accepted);
  }
  require(strict.adjacency().iso_up);
  auto stranger_configuration = configuration(3U);
  stranger_configuration.protocols = {packet::isis::ipv6_nlpid};
  PointToPointCircuit stranger(std::move(stranger_configuration), 654U, start);
  require(stranger.hello(last, key, *scratch, start) == HelloBuildResult::encoded &&
      strict.receive(last, key, start, &strict_events, event) == CircuitReceive::discarded &&
      strict.adjacency().iso_up && strict_events.down == 0U);
  auto dual_configuration = configuration(2U);
  dual_configuration.protocols.push_back(packet::isis::ipv6_nlpid);
  auto common_dual_configuration = dual_configuration;
  dual_configuration.topologies = {{2U, false, false}};
  PointToPointCircuit dual(std::move(dual_configuration), 789U, start);
  require(dual.hello(last, key, *scratch, start) == HelloBuildResult::encoded);
  require(strict.receive(last, key, start, &strict_events, event) == CircuitReceive::address_family &&
      !strict.adjacency().present && strict.peer_attributes().empty() && strict_events.down == 1U &&
      strict_events.old_attributes_preserved);
  PointToPointCircuit permissive(configuration(1U), 321U, start);
  PointToPointCircuit common_dual(std::move(common_dual_configuration), 951U, start);
  require(common_dual.hello(last, key, *scratch, start) == HelloBuildResult::encoded);
  require(permissive.receive(last, key, start, &strict_events, event) == CircuitReceive::accepted);
  auto ipv6_configuration = configuration(2U);
  ipv6_configuration.protocols = {packet::isis::ipv6_nlpid};
  PointToPointCircuit ipv6_only(std::move(ipv6_configuration), 987U, start);
  require(ipv6_only.hello(last, key, *scratch, start) == HelloBuildResult::encoded);
  require(permissive.receive(last, key, start, &strict_events, event) == CircuitReceive::address_family &&
      !permissive.adjacency().present);
}
