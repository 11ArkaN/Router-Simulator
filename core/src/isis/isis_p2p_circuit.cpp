// P2P circuit frame acceptance and owner-local Hello driving. All peer values
// originate in accepted wire TLVs. Projection admission precedes holding-time
// refresh; expiry events retain old attributes through synchronous Down work.

#include "router/isis_p2p_circuit.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace router::isis {

PointToPointCircuit::PointToPointCircuit(P2pCircuitConfiguration configuration,
    std::uint64_t random_state, Clock::time_point now)
    : configuration_(std::move(configuration)), adjacency_(configuration_.local),
      hello_(configuration_.hello_interval, false, false, random_state, now) {
  if (!configuration_.holding_seconds || !configuration_.maximum_area_addresses ||
      !configuration_.maximum_pdu_octets || !configuration_.peer_attribute_octets ||
      (configuration_.hello_destination[0U] & 1U) == 0U ||
      configuration_.physical_point_to_point == configuration_.local.over_lan ||
      (configuration_.emit_instance && !configuration_.instance_format) ||
      (!configuration_.emit_instance && configuration_.wire_instance))
    throw std::invalid_argument("Invalid IS-IS P2P circuit configuration");
  areas_.reserve(configuration_.areas.size());
  for (const auto &area : configuration_.areas) {
    if (!area.length || area.length > area.bytes.size())
      throw std::invalid_argument("Invalid IS-IS P2P area extent");
    areas_.push_back(area.view());
  }
  peer_.reserve(configuration_.peer_attribute_octets);
  staged_.reserve(configuration_.peer_attribute_octets);
}

void PointToPointCircuit::event(const P2pSnapshot &before, P2pUpdate update,
    std::span<const std::uint8_t> previous, void *context, P2pCircuitObserver observer) noexcept {
  const auto after = adjacency_.snapshot();
  if (before.three_way != after.three_way || before.present != after.present ||
      before.neighbor_system != after.neighbor_system ||
      before.neighbor_extended_circuit != after.neighbor_extended_circuit)
    hello_.changed();
  observer(context, {before, after, update, previous, peer_});
}

bool PointToPointCircuit::expire(Clock::time_point now,
    void *context, P2pCircuitObserver observer) noexcept {
  if (!observer) return false;
  const auto before = adjacency_.snapshot();
  const auto update = adjacency_.expire(now);
  if (update.outcome != P2pOutcome::down) return false;
  peer_.swap(staged_);
  peer_.clear();
  event(before, update, staged_, context, observer);
  staged_.clear();
  return true;
}

bool PointToPointCircuit::down(void *context, P2pCircuitObserver observer) noexcept {
  if (!observer || !operational_) return false;
  operational_ = false;
  if (hello_.pending()) static_cast<void>(hello_.complete(false, Clock::time_point{}));
  const auto before = adjacency_.snapshot();
  const auto update = adjacency_.circuit_down();
  if (update.outcome == P2pOutcome::down) {
    peer_.swap(staged_);
    peer_.clear();
    event(before, update, staged_, context, observer);
    staged_.clear();
  }
  return true;
}

bool PointToPointCircuit::up(Clock::time_point now) noexcept {
  if (operational_) return false;
  // Immutable constructor-validated values and a nonzero PRNG continuation
  // make this allocation-free replacement unable to reject its inputs.
  hello_ = HelloSchedule(configuration_.hello_interval, false, false, hello_.random_state(), now);
  operational_ = true;
  return true;
}

CircuitReceive PointToPointCircuit::receive(const packet::Frame &frame,
    std::optional<AuthenticationKey> key, Clock::time_point now,
    void *context, P2pCircuitObserver observer) noexcept {
  using namespace packet::isis;
  if (!observer) return CircuitReceive::missing_observer;
  if (!operational_) return CircuitReceive::discarded;
  static_cast<void>(expire(now, context, observer));
  EthernetDecodeError error{};
  const auto wire = parse_ethernet_pdu(frame.view(), error);
  if (!wire) return CircuitReceive::malformed;
  const auto &pdu = wire->pdu;
  if (pdu.type != PduType::point_to_point_hello ||
      (wire->ethernet.source[0U] & 1U) != 0U || wire->ethernet.source == configuration_.mac ||
      wire->ethernet.destination != configuration_.hello_destination || wire->ethernet.vlan_tag_count)
    return CircuitReceive::discarded;
  InstanceError instance_error{};
  const auto instance = select_instance(pdu,
      configuration_.instance_format.value_or(InstanceFormat::standard),
      configuration_.physical_point_to_point, instance_error);
  if (!instance || instance->instance != configuration_.wire_instance)
    return CircuitReceive::instance;
  if (configuration_.wire_instance && configuration_.instance_format == InstanceFormat::standard &&
      !instance->topology_zero) return CircuitReceive::instance;
  if (configuration_.receive_authentication && (!key ||
      verify_authentication(pdu.bytes, *key) != AuthenticationError::none))
    return CircuitReceive::authentication;
  const auto header = packet::isis::hello(pdu);
  if (!header || header->source == configuration_.local.system) return CircuitReceive::discarded;
  const auto established = adjacency_.snapshot();
  if (configuration_.local.over_lan && established.present &&
      established.neighbor_system != header->source) return CircuitReceive::discarded;
  bool common_topology{};
  if (configuration_.topologies.empty()) {
    const auto supported = supports_topology(pdu, 0U);
    if (!supported) return CircuitReceive::malformed;
    common_topology = *supported;
  } else for (const auto &topology : configuration_.topologies) {
    const auto supported = supports_topology(pdu, topology.id);
    if (!supported) return CircuitReceive::malformed;
    common_topology = common_topology || *supported;
  }
  staged_.clear();
  bool matching_area{};
  std::uint8_t peer_families{};
  std::optional<TlvView> three_way;
  TlvCursor options(pdu.tlvs);
  while (const auto option = options.next()) {
    if (option->code == 129U) {
      if (supports_protocol(*option, ipv4_nlpid)) peer_families |= 1U;
      if (supports_protocol(*option, ipv6_nlpid)) peer_families |= 2U;
    }
    if (option->code == 240U) {
      if (three_way) return CircuitReceive::malformed;
      three_way = option;
    }
    if (option->code == 1U) {
      AreaAddressCursor addresses(*option);
      while (const auto area = addresses.next())
        for (const auto local : areas_)
          matching_area = matching_area || std::equal(local.begin(), local.end(), area->begin(), area->end());
      if (!addresses.valid()) return CircuitReceive::malformed;
    }
    if (option->code == 132U && !FixedAddressCursor<4U>(*option, 132U).valid())
      return CircuitReceive::malformed;
    if (option->code == 232U && !valid_ipv6_interface_addresses(*option, pdu.type))
      return CircuitReceive::malformed;
    if (option->code != 1U && option->code != 129U && option->code != 132U &&
        option->code != 232U && option->code != 229U) continue;
    if (staged_.size() + 2U + option->value.size() > configuration_.peer_attribute_octets)
      return CircuitReceive::capacity;
    staged_.push_back(option->code);
    staged_.push_back(static_cast<std::uint8_t>(option->value.size()));
    staged_.insert(staged_.end(), option->value.begin(), option->value.end());
  }
  if (!options.valid()) return CircuitReceive::malformed;
  std::uint8_t local_families{};
  for (const auto protocol : configuration_.protocols) {
    if (protocol == ipv4_nlpid) local_families |= 1U;
    if (protocol == ipv6_nlpid) local_families |= 2U;
  }
  // SR OS strict-adjacency-check compares configured IPv4/IPv6 families.
  // A mismatch must remove existing state before any holding refresh. The
  // disabled policy still requires a common family, independent of MT IDs.
  if ((local_families & peer_families) == 0U ||
      (configuration_.strict_adjacency_check && local_families != peer_families)) {
    const auto before = adjacency_.snapshot();
    const auto update = adjacency_.circuit_down();
    if (update.outcome == P2pOutcome::down) {
      staged_.clear();
      peer_.swap(staged_);
      event(before, update, staged_, context, observer);
    }
    staged_.clear();
    return CircuitReceive::address_family;
  }
  if (!common_topology) return CircuitReceive::topology;
  const auto before = adjacency_.snapshot();
  const auto update = adjacency_.receive(*header, wire->ethernet.source, matching_area,
      pdu.maximum_area_addresses == configuration_.maximum_area_addresses, three_way, now);
  if (update.outcome == P2pOutcome::discarded) return CircuitReceive::discarded;
  if (update.holding_refreshed) peer_.swap(staged_);
  else if (!adjacency_.snapshot().present) { peer_.swap(staged_); peer_.clear(); }
  event(before, update, staged_, context, observer);
  staged_.clear();
  return update.outcome == P2pOutcome::rejected ? CircuitReceive::discarded : CircuitReceive::accepted;
}

std::optional<HelloBuildResult> PointToPointCircuit::hello(packet::Frame &output,
    std::optional<AuthenticationKey> key, PduScratch &scratch, Clock::time_point now) noexcept {
  if (!operational_) return std::nullopt;
  if (!hello_.begin(now)) return std::nullopt;
  if (configuration_.transmit_authentication && !key) {
    static_cast<void>(hello_.complete(false, now));
    return HelloBuildResult::authentication;
  }
  auto contents = circuit_hello_contents(configuration_, areas_, key);
  contents.header.type = packet::isis::PduType::point_to_point_hello;
  contents.header.source = configuration_.local.system;
  contents.header.holding_seconds = configuration_.holding_seconds;
  contents.header.circuit_type = static_cast<std::uint8_t>(configuration_.local.levels);
  contents.header.local_circuit_id = configuration_.local.local_circuit;
  contents.three_way = adjacency_.outbound_three_way();
  contents.physical_point_to_point = configuration_.physical_point_to_point;
  const auto result = build_hello_frame(output, contents, scratch);
  if (result != HelloBuildResult::encoded) static_cast<void>(hello_.complete(false, now));
  return result;
}

bool PointToPointCircuit::complete_hello(bool enqueued, Clock::time_point now) noexcept {
  return operational_ && hello_.complete(enqueued, now);
}

PointToPointCircuit::Clock::time_point PointToPointCircuit::deadline() const noexcept {
  if (!operational_) return Clock::time_point::max();
  const auto holding = adjacency_.deadline();
  return holding ? std::min(*holding, hello_.deadline()) : hello_.deadline();
}

} // namespace router::isis
