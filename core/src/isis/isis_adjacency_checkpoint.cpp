// Circuit-local adjacency owners retain accepted identities and holding time.
// Transfer does not replay a Hello, refresh its timer or dispatch an event.
// Both state machines validate their complete value before atomic assignment.

#include "router/isis_p2p_adjacency.hpp"
#include "router/isis_lan_adjacency.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <stdexcept>

namespace router::isis {
namespace {
bool valid_holding(const std::optional<std::int64_t> &value, bool present) noexcept {
  return value.has_value() == present && (!value || *value <= 65535000000000LL);
}
}
P2pAdjacencyCheckpoint PointToPointAdjacency::checkpoint(Clock::time_point now) const {
  P2pAdjacencyCheckpoint result{1U, local_, state_, {}};
  if (state_.present) {
    result.holding_nanoseconds = checkpoint_time::offset(holding_deadline_, now);
    if (!result.holding_nanoseconds) throw std::invalid_argument("IS-IS P2P checkpoint clock range");
  }
  return result;
}
bool PointToPointAdjacency::restore(const P2pAdjacencyCheckpoint &saved, Clock::time_point now) noexcept {
  const auto &state = saved.state;
  if (saved.version != 1U || saved.local != local_ || !valid_holding(saved.holding_nanoseconds, state.present) ||
      (!state.present && state != P2pSnapshot{}) ||
      (state.present && (state.usage == Levels::none || state.usage > Levels::both ||
          (static_cast<unsigned>(state.usage) & ~static_cast<unsigned>(local_.levels)) ||
          state.three_way > ThreeWayState::down || (!state.uses_three_way && (!state.iso_up || state.neighbor_extended_circuit)) ||
          (state.uses_three_way && state.three_way == ThreeWayState::down) ||
          (state.uses_three_way && state.three_way == ThreeWayState::up && !state.iso_up)))) return false;
  const auto due = saved.holding_nanoseconds ? checkpoint_time::restore(*saved.holding_nanoseconds, now) :
      std::optional{Clock::time_point{}};
  if (!due) return false;
  state_ = state;
  holding_deadline_ = *due;
  return true;
}
LanAdjacencyCheckpoint LanAdjacency::checkpoint(Clock::time_point now) const {
  LanAdjacencyCheckpoint result{1U, type_, peer_, peer_mac_, local_mac_, state_, {}};
  if (state_.present) {
    result.holding_nanoseconds = checkpoint_time::offset(holding_deadline_, now);
    if (!result.holding_nanoseconds) throw std::invalid_argument("IS-IS LAN checkpoint clock range");
  }
  return result;
}
bool LanAdjacency::restore(const LanAdjacencyCheckpoint &saved, Clock::time_point now) noexcept {
  const auto &state = saved.state;
  if (saved.version != 1U || saved.type != type_ || saved.peer != peer_ || saved.peer_mac != peer_mac_ ||
      saved.local_mac != local_mac_ || !valid_holding(saved.holding_nanoseconds, state.present) ||
      (!state.present && state != LanSnapshot{}) ||
      (state.present && (state.system != peer_ || state.mac != peer_mac_ || state.state > LanState::up || state.priority > 127U)))
    return false;
  const auto due = saved.holding_nanoseconds ? checkpoint_time::restore(*saved.holding_nanoseconds, now) :
      std::optional{Clock::time_point{}};
  if (!due) return false;
  state_ = state;
  holding_deadline_ = *due;
  return true;
}
} // namespace router::isis
