// A LAN level restores neighbors and retained non-secret TLVs together.
// Area projections are derived once using the normal receive validator.
// Cold capacity is reserved before a candidate can replace any live owner.

#include "router/isis_lan_adjacency_set.hpp"

#include <new>
#include <stdexcept>
#include <utility>

namespace router::isis {
LanSetCheckpoint LanAdjacencySet::checkpoint(Clock::time_point now) const {
  LanSetCheckpoint result{1U, type_, local_, limits_, maximum_attribute_octets_, {}};
  result.peers.reserve(peers_.size());
  for (const auto &peer : peers_) result.peers.push_back({peer.adjacency.checkpoint(now), peer.attributes});
  return result;
}
std::unique_ptr<LanAdjacencySet> LanAdjacencySet::restore_checkpoint(const LanSetCheckpoint &saved,
    packet::isis::PduType type, packet::Mac local, LanSetLimits limits,
    std::size_t attribute_octets, Clock::time_point now) noexcept {
  if (saved.version != 1U || saved.type != type || saved.local != local || saved.limits != limits ||
      saved.maximum_attribute_octets != attribute_octets || saved.peers.size() > limits.neighbors) return nullptr;
  try {
    auto result = std::make_unique<LanAdjacencySet>(type, local, limits, attribute_octets);
    for (std::size_t index{}; index < saved.peers.size(); ++index) {
      const auto &entry = saved.peers[index];
      const auto &state = entry.adjacency;
      if (!state.state.present || state.type != type || state.local_mac != local ||
          (index && saved.peers[index - 1U].adjacency.peer_mac >= state.peer_mac) ||
          entry.attributes.size() > attribute_octets) return nullptr;
      LanAdjacency adjacency(type, state.peer, state.peer_mac, local);
      if (!adjacency.restore(state, now)) return nullptr;
      const packet::isis::PduView projection{type, 0U, {}, entry.attributes};
      if (result->stage_peer(projection) != LanSetResult::accepted || result->attribute_scratch_ != entry.attributes)
        return nullptr;
      // Equality above rejects unretained TLVs, including authentication, rather
      // than silently dropping secret-bearing or unknown input from a transfer.
      Peer peer{std::move(adjacency), {}, {}};
      peer.areas.reserve(limits.areas_per_neighbor);
      peer.attributes.reserve(attribute_octets);
      peer.areas.assign(result->area_scratch_.begin(), result->area_scratch_.end());
      peer.attributes.assign(entry.attributes.begin(), entry.attributes.end());
      result->peers_.push_back(std::move(peer));
    }
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
