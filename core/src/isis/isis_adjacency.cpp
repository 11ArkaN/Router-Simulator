// ISO adjacency table and DIS election predicates. All state is passed by value
// or immutable spans; only the process owner may act on returned decisions.
// Source: iso.10589.2002.adjacency_decisions

#include "router/isis_adjacency.hpp"

#include <algorithm>

namespace router::isis {

P2pDecision p2p_hello_decision(Levels local, Levels remote, Levels usage,
    bool matching_area, bool matching_maximum_areas) noexcept {
  using Action = P2pAction;
  using Reason = AdjacencyReason;
  const auto discard = P2pDecision{Action::discard, usage, Reason::invalid_state};
  if (local == Levels::none || local > Levels::both || remote == Levels::none ||
      remote > Levels::both || usage > Levels::both) return discard;
  if (matching_area && !matching_maximum_areas)
    return {Action::discard, usage, Reason::maximum_area_mismatch};
  const auto rejected = [&](Reason reason) {
    return P2pDecision{usage == Levels::none ? Action::reject : Action::down, Levels::none, reason};
  };
  if (!matching_area) {
    if (local == Levels::level1) return rejected(Reason::area_mismatch);
    if (usage == Levels::none)
      return remote == Levels::level1 ? rejected(Reason::area_mismatch) :
          P2pDecision{Action::up, Levels::level2, Reason::none};
    if (usage == Levels::level2 && remote != Levels::level1)
      return {Action::accept, usage, Reason::none};
    const bool area_reason = (usage == Levels::level1 && remote == Levels::level1) ||
                             (usage == Levels::both && remote == Levels::both);
    return rejected(area_reason ? Reason::area_mismatch : Reason::wrong_system);
  }
  if (local == Levels::level1) {
    if (usage != Levels::none && usage != Levels::level1) return discard;
    if (remote == Levels::level2) return rejected(Reason::wrong_system);
    return {usage == Levels::none ? Action::up : Action::accept, Levels::level1, Reason::none};
  }
  if (local == Levels::level2) {
    if (usage == Levels::level1) return discard;
    if (remote == Levels::level1 || usage == Levels::both) return rejected(Reason::wrong_system);
    return {usage == Levels::none ? Action::up : Action::accept, Levels::level2, Reason::none};
  }
  if (usage == Levels::none) return {Action::up, remote, Reason::none};
  return usage == remote ? P2pDecision{Action::accept, usage, Reason::none} : rejected(Reason::wrong_system);
}

packet::isis::LanId p2p_circuit_id(const packet::isis::SystemId &local,
    std::uint8_t local_circuit, const packet::isis::SystemId &remote,
    std::uint8_t remote_circuit) noexcept {
  packet::isis::LanId result{};
  const bool remote_wins = remote > local;
  const auto &system = remote_wins ? remote : local;
  std::copy(system.begin(), system.end(), result.begin());
  result.back() = remote_wins ? remote_circuit : local_circuit;
  return result;
}

std::optional<DisSelection> select_dis(const DisLocal &local,
    std::span<const DisNeighbor> neighbors, bool initial_delay_elapsed,
    bool any_up_adjacency) noexcept {
  if (!initial_delay_elapsed || !any_up_adjacency || local.priority > 127U) return std::nullopt;
  auto priority = local.priority;
  DisSelection winner{local.system, local.mac, {}, true};
  std::copy(local.system.begin(), local.system.end(), winner.lan.begin());
  winner.lan.back() = local.circuit;
  for (const auto &neighbor : neighbors) {
    if (neighbor.priority > 127U) return std::nullopt;
    if (!neighbor.adjacency_up) continue;
    if (neighbor.priority > priority || (neighbor.priority == priority && neighbor.mac > winner.mac)) {
      winner = {neighbor.system, neighbor.mac, neighbor.advertised_lan, false};
      priority = neighbor.priority;
    }
  }
  return winner;
}

} // namespace router::isis
