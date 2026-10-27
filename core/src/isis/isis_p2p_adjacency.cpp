// P2P holding state commits only accepted Hello projections. The enclosing
// protocol owner alone invokes this state machine and publishes its events.
// Sources: iso.10589.2002.adjacency_decisions, ietf.isis.three_way.rfc5303,
// and iso.10589.2002.ethernet_dispatch

#include "router/isis_p2p_adjacency.hpp"

#include <stdexcept>

namespace router::isis {
namespace {
P2pReason reason(AdjacencyReason value) noexcept {
  switch (value) {
  case AdjacencyReason::none: return P2pReason::none;
  case AdjacencyReason::wrong_system: return P2pReason::wrong_system;
  case AdjacencyReason::area_mismatch: return P2pReason::area_mismatch;
  case AdjacencyReason::maximum_area_mismatch: return P2pReason::maximum_area_mismatch;
  default: return P2pReason::invalid_state;
  }
}
}

PointToPointAdjacency::PointToPointAdjacency(P2pLocal local) : local_(local) {
  if (local.levels == Levels::none || local.levels > Levels::both)
    throw std::invalid_argument("IS-IS P2P adjacency requires a valid local level capability");
}

bool PointToPointAdjacency::ready() const noexcept {
  return state_.present && state_.iso_up &&
         (!state_.uses_three_way || state_.three_way == ThreeWayState::up);
}

std::optional<PointToPointAdjacency::Clock::time_point> PointToPointAdjacency::deadline() const noexcept {
  return state_.present ? std::optional(holding_deadline_) : std::nullopt;
}

ThreeWayOption PointToPointAdjacency::outbound_three_way() const noexcept {
  ThreeWayOption option{state_.present ? state_.three_way : ThreeWayState::down,
                         local_.extended_circuit, std::nullopt, std::nullopt};
  if (state_.present && state_.three_way != ThreeWayState::down && state_.neighbor_extended_circuit) {
    option.neighbor_system = state_.neighbor_system;
    option.neighbor_circuit = state_.neighbor_extended_circuit;
  }
  return option;
}

P2pUpdate PointToPointAdjacency::remove(P2pReason cause) noexcept {
  const bool was_ready = ready();
  state_ = {};
  holding_deadline_ = {};
  return {P2pOutcome::down, cause, false, was_ready};
}

P2pUpdate PointToPointAdjacency::expire(Clock::time_point now) noexcept {
  return state_.present && now >= holding_deadline_ ? remove(P2pReason::holding_expired) : P2pUpdate{};
}

P2pUpdate PointToPointAdjacency::circuit_down() noexcept {
  return state_.present ? remove(P2pReason::circuit_down) : P2pUpdate{};
}

P2pUpdate PointToPointAdjacency::receive(const packet::isis::HelloView &hello,
    const packet::Mac &source, bool matching_area, bool matching_maximum_areas,
    std::optional<packet::isis::TlvView> option, Clock::time_point now) noexcept {
  // RFC 5309 keeps the established P2P-over-LAN peer fixed until it expires.
  if (local_.over_lan && state_.present && state_.neighbor_system != hello.source)
    return {P2pOutcome::discarded, P2pReason::different_lan_neighbor};
  const auto handshake = three_way_receive(state_.three_way, local_.system, local_.extended_circuit, true, option);
  if (handshake.action == ThreeWayAction::discard)
    return {P2pOutcome::discarded, P2pReason::invalid_three_way};
  const auto iso = p2p_hello_decision(local_.levels, static_cast<Levels>(hello.circuit_type),
      state_.iso_up ? state_.usage : Levels::none, matching_area, matching_maximum_areas);
  if (iso.action == P2pAction::discard) return {P2pOutcome::discarded, reason(iso.reason)};
  if (iso.action == P2pAction::reject) {
    state_ = {};
    holding_deadline_ = {};
    return {P2pOutcome::rejected, reason(iso.reason)};
  }
  if (iso.action == P2pAction::down) return remove(reason(iso.reason));
  const auto negotiated = p2p_circuit_id(local_.system, local_.local_circuit,
                                        hello.source, hello.local_circuit_id);
  const bool legacy = handshake.action == ThreeWayAction::legacy;
  // RFC 5303 skips ISO identity/circuit comparison when option 240 is used.
  if (legacy && iso.action == P2pAction::accept &&
      (state_.neighbor_system != hello.source || state_.negotiated_circuit != negotiated))
    return remove(P2pReason::identity_changed);
  if (handshake.action == ThreeWayAction::down) return remove(P2pReason::neighbor_restarted);
  const bool was_ready = ready();
  state_.present = true;
  state_.usage = iso.usage;
  state_.uses_three_way = !legacy;
  state_.neighbor_system = hello.source;
  state_.neighbor_mac = source;
  if (legacy) {
    state_.negotiated_circuit = negotiated;
    state_.neighbor_extended_circuit.reset();
    state_.iso_up = true;
  } else {
    state_.three_way = handshake.next_state;
    state_.neighbor_extended_circuit = decode_three_way(*option)->local_circuit;
    if (handshake.action == ThreeWayAction::up) state_.iso_up = true;
  }
  holding_deadline_ = now + std::chrono::seconds(hello.holding_seconds);
  const auto outcome = legacy ? (iso.action == P2pAction::up ? P2pOutcome::up : P2pOutcome::accepted) :
      handshake.action == ThreeWayAction::up ? P2pOutcome::up :
      handshake.action == ThreeWayAction::initialize ? P2pOutcome::initializing : P2pOutcome::accepted;
  return {outcome, P2pReason::none, true, was_ready != ready()};
}

} // namespace router::isis
