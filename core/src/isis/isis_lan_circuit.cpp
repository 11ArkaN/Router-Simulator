// LAN wire acceptance, bounded neighbor lifetime and per-level DIS driving.
// Circuit-local monotonic deadlines control election and Hello scheduling.
// ISO 10589 clauses 8.4.1 through 8.4.5; no remote owner state is inspected.

#include "router/isis_lan_circuit.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
LanCircuit::LanCircuit(LanCircuitConfiguration configuration, std::uint64_t random_state,
    Clock::time_point now)
    : configuration_(std::move(configuration)),
      neighbors_(configuration_.type, configuration_.mac, configuration_.limits),
      hello_(configuration_.hello_interval, true, false, random_state, now),
      election_ready_(now + 2 * configuration_.hello_interval) {
  const auto level = configuration_.type == packet::isis::PduType::lan_hello_l1 ? 1U : 2U;
  if (!configuration_.holding_seconds || !configuration_.designated_holding_seconds ||
      configuration_.designated_hello_interval <= std::chrono::microseconds::zero() ||
      !configuration_.maximum_area_addresses || !configuration_.maximum_pdu_octets ||
      (static_cast<unsigned>(configuration_.levels) & level) == 0U ||
      static_cast<unsigned>(configuration_.levels) > 3U || configuration_.local.priority > 127U ||
      configuration_.local.mac != configuration_.mac || (configuration_.mac[0U] & 1U) ||
      (configuration_.hello_destination[0U] & 1U) == 0U ||
      (configuration_.emit_instance && !configuration_.instance_format) ||
      (!configuration_.emit_instance && configuration_.wire_instance))
    throw std::invalid_argument("Invalid IS-IS LAN circuit configuration");
  areas_.reserve(configuration_.areas.size());
  for (const auto &area : configuration_.areas) {
    if (!area.length || area.length > area.bytes.size())
      throw std::invalid_argument("Invalid IS-IS LAN area extent");
    areas_.push_back(area.view());
  }
  hello_neighbors_.reserve(configuration_.limits.neighbors);
  candidates_.reserve(configuration_.limits.neighbors);
  std::copy(configuration_.local.system.begin(), configuration_.local.system.end(), advertised_lan_.begin());
  advertised_lan_.back() = configuration_.local.circuit;
}

bool LanCircuit::valid_observer(LanCircuitObserver observer) const noexcept {
  return observer.peer && observer.designated;
}

void LanCircuit::elect(Clock::time_point now, LanCircuitObserver observer) noexcept {
  if (now < election_ready_) return;
  election_started_ = true;
  candidates_.clear();
  bool any_up{};
  for (std::size_t index{}; index < neighbors_.size(); ++index) {
    const auto peer = neighbors_.at(index)->adjacency;
    const bool up = peer.state == LanState::up;
    any_up = any_up || up;
    candidates_.push_back({peer.system, peer.mac, peer.advertised_lan, peer.priority, up});
  }
  const auto selected = select_dis(configuration_.local, candidates_, true, any_up);
  if (selected == designated_) return;
  const bool was_local = designated_ && designated_->local;
  const bool is_local = selected && selected->local;
  const auto previous = designated_;
  designated_ = selected;
  if (selected) advertised_lan_ = selected->lan;
  else {
    std::copy(configuration_.local.system.begin(), configuration_.local.system.end(), advertised_lan_.begin());
    advertised_lan_.back() = configuration_.local.circuit;
  }
  if (was_local != is_local)
    static_cast<void>(hello_.role(is_local ? configuration_.designated_hello_interval :
        configuration_.hello_interval, is_local, now));
  hello_.changed();
  observer.designated(observer.context, previous, designated_);
}

void LanCircuit::service(Clock::time_point now, std::size_t budget, LanCircuitObserver observer) noexcept {
  if (!operational_ || !valid_observer(observer)) return;
  while (budget-- && neighbors_.expire_one(now, observer.context, observer.peer)) {
    hello_.changed();
    elect(now, observer);
  }
  elect(now, observer);
}

LanCircuitReceive LanCircuit::receive(const packet::Frame &frame,
    std::optional<AuthenticationKey> key, Clock::time_point now, LanCircuitObserver observer) noexcept {
  using namespace packet::isis;
  if (!valid_observer(observer)) return LanCircuitReceive::missing_observer;
  if (!operational_) return LanCircuitReceive::discarded;
  service(now, neighbors_.size(), observer);
  EthernetDecodeError error{};
  const auto wire = parse_ethernet_pdu(frame.view(), error);
  if (!wire) return LanCircuitReceive::malformed;
  if (wire->pdu.type != configuration_.type || wire->ethernet.vlan_tag_count ||
      wire->ethernet.destination != configuration_.hello_destination ||
      wire->ethernet.source == configuration_.mac || (wire->ethernet.source[0U] & 1U))
    return LanCircuitReceive::discarded;
  InstanceError instance_error{};
  const auto instance = select_instance(wire->pdu,
      configuration_.instance_format.value_or(InstanceFormat::standard), false, instance_error);
  if (!instance || instance->instance != configuration_.wire_instance ||
      (configuration_.wire_instance && configuration_.instance_format == InstanceFormat::standard &&
       !instance->topology_zero)) return LanCircuitReceive::instance;
  if (configuration_.receive_authentication && (!key ||
      verify_authentication(wire->pdu.bytes, *key) != AuthenticationError::none))
    return LanCircuitReceive::authentication;
  const auto header = packet::isis::hello(wire->pdu);
  if (!header || header->source == configuration_.local.system) return LanCircuitReceive::discarded;
  const auto existing = neighbors_.find(wire->ethernet.source);
  if (existing && existing->adjacency.system != header->source) return LanCircuitReceive::discarded;
  // LAN adjacency admission does not require a common MT component. Validate
  // its encoding while leaving topology-specific use to the instance owner.
  if (!supports_topology(wire->pdu, 0U)) return LanCircuitReceive::malformed;
  bool area_match{};
  std::uint8_t peer_families{}, local_families{};
  TlvCursor options(wire->pdu.tlvs);
  while (const auto option = options.next()) {
    if (option->code == 6U && !FixedAddressCursor<6U>(*option, 6U).valid())
      return LanCircuitReceive::malformed;
    if (option->code == 1U) {
      AreaAddressCursor addresses(*option);
      while (const auto area = addresses.next()) for (const auto local : areas_)
        area_match = area_match || std::equal(local.begin(), local.end(), area->begin(), area->end());
      if (!addresses.valid()) return LanCircuitReceive::malformed;
    }
    if (option->code == 129U) {
      if (supports_protocol(*option, ipv4_nlpid)) peer_families |= 1U;
      if (supports_protocol(*option, ipv6_nlpid)) peer_families |= 2U;
    }
    if (option->code == 132U && !FixedAddressCursor<4U>(*option, 132U).valid())
      return LanCircuitReceive::malformed;
    if (option->code == 232U && !valid_ipv6_interface_addresses(*option, wire->pdu.type))
      return LanCircuitReceive::malformed;
  }
  if (!options.valid()) return LanCircuitReceive::malformed;
  if (configuration_.type == PduType::lan_hello_l1 && (!area_match ||
      wire->pdu.maximum_area_addresses != configuration_.maximum_area_addresses)) return LanCircuitReceive::area;
  for (const auto protocol : configuration_.protocols) {
    if (protocol == ipv4_nlpid) local_families |= 1U;
    if (protocol == ipv6_nlpid) local_families |= 2U;
  }
  if (!(local_families & peer_families) ||
      (configuration_.strict_adjacency_check && local_families != peer_families)) {
    if (neighbors_.policy_down(wire->ethernet.source, observer.context, observer.peer)) hello_.changed();
    elect(now, observer);
    return LanCircuitReceive::discarded;
  }
  const bool existed = neighbors_.find(wire->ethernet.source).has_value();
  const auto accepted = neighbors_.receive(wire->pdu, wire->ethernet.source, now,
      observer.context, observer.peer);
  if (accepted == LanSetResult::malformed) return LanCircuitReceive::malformed;
  if (accepted == LanSetResult::capacity_refused || accepted == LanSetResult::memory_refused)
    return LanCircuitReceive::capacity;
  if (accepted != LanSetResult::accepted) return LanCircuitReceive::discarded;
  if (!existed) hello_.changed();
  elect(now, observer);
  return LanCircuitReceive::accepted;
}

std::optional<HelloBuildResult> LanCircuit::hello(packet::Frame &frame,
    std::optional<AuthenticationKey> key, PduScratch &scratch, Clock::time_point now,
    LanCircuitObserver observer) noexcept {
  if (!operational_ || !valid_observer(observer)) return std::nullopt;
  service(now, neighbors_.size(), observer);
  if (!hello_.begin(now)) return std::nullopt;
  if (configuration_.transmit_authentication && !key) {
    static_cast<void>(hello_.complete(false, now));
    return HelloBuildResult::authentication;
  }
  hello_neighbors_.clear();
  for (std::size_t index{}; index < neighbors_.size(); ++index)
    hello_neighbors_.push_back(neighbors_.at(index)->adjacency.mac);
  auto contents = circuit_hello_contents(configuration_, areas_, key);
  contents.header.type = configuration_.type;
  contents.header.source = configuration_.local.system;
  contents.header.circuit_type = static_cast<std::uint8_t>(configuration_.levels);
  contents.header.priority = configuration_.local.priority;
  contents.header.designated_id = advertised_lan_;
  contents.header.holding_seconds = designated_ && designated_->local ?
      configuration_.designated_holding_seconds : configuration_.holding_seconds;
  contents.neighbors = hello_neighbors_;
  const auto result = build_hello_frame(frame, contents, scratch);
  if (result != HelloBuildResult::encoded) static_cast<void>(hello_.complete(false, now));
  return result;
}

bool LanCircuit::complete_hello(bool enqueued, Clock::time_point now) noexcept {
  return operational_ && hello_.complete(enqueued, now);
}

bool LanCircuit::down(LanCircuitObserver observer) noexcept {
  if (!operational_ || !valid_observer(observer)) return false;
  static_cast<void>(neighbors_.circuit_down(observer.context, observer.peer));
  if (designated_) {
    const auto previous = designated_;
    designated_.reset();
    observer.designated(observer.context, previous, designated_);
  }
  if (hello_.pending()) static_cast<void>(hello_.complete(false, Clock::time_point{}));
  operational_ = false;
  return true;
}

LanCircuit::Clock::time_point LanCircuit::deadline() const noexcept {
  if (!operational_) return Clock::time_point::max();
  auto result = hello_.deadline();
  if (!election_started_) result = std::min(result, election_ready_);
  if (const auto holding = neighbors_.deadline()) result = std::min(result, *holding);
  return result;
}
} // namespace router::isis
