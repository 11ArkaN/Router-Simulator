// A LAN level restores election, accepted peers and Hello role atomically.
// The new owner rebuilds borrowed local area views and bounded work scratch.
// Election validation reads only the captured same-circuit accepted catalog.

#include "router/isis_lan_circuit.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>
#include <utility>

namespace router::isis {
LanCircuitCheckpoint LanCircuit::checkpoint(Clock::time_point now) const {
  const auto election = checkpoint_time::offset(election_ready_, now);
  if (!election) throw std::invalid_argument("IS-IS LAN election checkpoint clock range");
  return {1U, configuration_, neighbors_.checkpoint(now), hello_.checkpoint(now), *election, designated_,
      advertised_lan_, election_started_, operational_};
}
std::unique_ptr<LanCircuit> LanCircuit::restore_checkpoint(const LanCircuitCheckpoint &saved,
    LanCircuitConfiguration expected, Clock::time_point now) noexcept {
  if (saved.version != 1U || saved.configuration != expected ||
      (!saved.operational && (!saved.neighbors.peers.empty() || saved.designated || saved.hello.pending)) ||
      (!saved.election_started && saved.designated) || (saved.election_started && saved.election_nanoseconds > 0)) return nullptr;
  try {
    auto result = std::make_unique<LanCircuit>(std::move(expected), 1U, now);
    const auto &configuration = result->configuration_;
    if (saved.election_nanoseconds >
        std::chrono::duration_cast<Clock::duration>(configuration.hello_interval * 2).count()) return nullptr;
    const auto election = checkpoint_time::restore(saved.election_nanoseconds, now);
    if (!election) return nullptr;
    auto neighbors = LanAdjacencySet::restore_checkpoint(saved.neighbors, configuration.type,
        configuration.mac, configuration.limits, configuration.peer_attribute_octets, now);
    if (!neighbors) return nullptr;
    bool any_up{};
    for (std::size_t index{}; index < neighbors->size(); ++index) {
      const auto retained = *neighbors->at(index);
      const auto peer = retained.adjacency;
      std::uint8_t peer_families{}, local_families{};
      packet::isis::TlvCursor attributes(retained.attributes);
      while (const auto option = attributes.next()) if (option->code == 129U) {
        if (packet::isis::supports_protocol(*option, packet::isis::ipv4_nlpid)) peer_families |= 1U;
        if (packet::isis::supports_protocol(*option, packet::isis::ipv6_nlpid)) peer_families |= 2U;
      }
      for (const auto protocol : configuration.protocols) {
        if (protocol == packet::isis::ipv4_nlpid) local_families |= 1U;
        if (protocol == packet::isis::ipv6_nlpid) local_families |= 2U;
      }
      bool matching_area{};
      for (const auto &remote_area : retained.areas) for (const auto &local_area : configuration.areas)
        matching_area = matching_area || std::ranges::equal(remote_area.view(), local_area.view());
      if (!(local_families & peer_families) ||
          (configuration.strict_adjacency_check && local_families != peer_families) ||
          (configuration.type == packet::isis::PduType::lan_hello_l1 && !matching_area)) return nullptr;
      if (peer.system == configuration.local.system || peer.mac == configuration.mac || (peer.mac[0U] & 1U)) return nullptr;
      const bool up = peer.state == LanState::up;
      any_up = any_up || up;
      result->candidates_.push_back({peer.system, peer.mac, peer.advertised_lan, peer.priority, up});
    }
    if (saved.operational) {
      const auto selected = select_dis(configuration.local, result->candidates_, saved.election_started, any_up);
      if (selected != saved.designated || saved.hello.designated != (selected && selected->local)) return nullptr;
      packet::isis::LanId advertised{};
      std::copy(configuration.local.system.begin(), configuration.local.system.end(), advertised.begin());
      advertised.back() = configuration.local.circuit;
      if (selected) advertised = selected->lan;
      if (advertised != saved.advertised_lan) return nullptr;
    }
    const auto interval = saved.hello.designated ? configuration.designated_hello_interval : configuration.hello_interval;
    if (saved.hello.interval != interval || !result->hello_.role(interval, saved.hello.designated, now) ||
        !result->hello_.restore(saved.hello, now)) return nullptr;
    result->neighbors_ = std::move(*neighbors);
    result->election_ready_ = *election;
    result->designated_ = saved.designated;
    result->advertised_lan_ = saved.advertised_lan;
    result->election_started_ = saved.election_started;
    result->operational_ = saved.operational;
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
