// P2P restoration joins accepted peer identity, non-secret TLVs and Hello state.
// Cold construction rebuilds area views against the new configuration storage.
// No accepted Hello is replayed and no observer sees a partially restored peer.

#include "router/isis_p2p_circuit.hpp"

#include <new>
#include <stdexcept>
#include <utility>

namespace router::isis {
P2pCircuitCheckpoint PointToPointCircuit::checkpoint(Clock::time_point now) const {
  return {1U, configuration_, adjacency_.checkpoint(now), hello_.checkpoint(now), peer_, operational_};
}
std::unique_ptr<PointToPointCircuit> PointToPointCircuit::restore_checkpoint(const P2pCircuitCheckpoint &saved,
    P2pCircuitConfiguration expected, Clock::time_point now) noexcept {
  if (saved.version != 1U || saved.configuration != expected ||
      saved.peer_attributes.size() > expected.peer_attribute_octets ||
      (!saved.adjacency.state.present && !saved.peer_attributes.empty()) ||
      (!saved.operational && (saved.adjacency.state.present || saved.hello.pending))) return nullptr;
  try {
    auto result = std::make_unique<PointToPointCircuit>(std::move(expected), 1U, now);
    if (!result->adjacency_.restore(saved.adjacency, now) || !result->hello_.restore(saved.hello, now)) return nullptr;
    const auto &configuration = result->configuration_;
    if (saved.adjacency.state.present && (saved.adjacency.state.neighbor_system == configuration.local.system ||
        saved.adjacency.state.neighbor_mac == configuration.mac || (saved.adjacency.state.neighbor_mac[0U] & 1U))) return nullptr;
    const packet::isis::PduView projection{packet::isis::PduType::point_to_point_hello, 0U, {}, saved.peer_attributes};
    bool common_topology{};
    if (configuration.topologies.empty()) {
      const auto supported = supports_topology(projection, 0U);
      if (!supported) return nullptr;
      common_topology = *supported;
    } else for (const auto &topology : configuration.topologies) {
      const auto supported = supports_topology(projection, topology.id);
      if (!supported) return nullptr;
      common_topology = common_topology || *supported;
    }
    std::uint8_t peer_families{}, local_families{};
    packet::isis::TlvCursor options(saved.peer_attributes);
    while (const auto option = options.next()) {
      switch (option->code) {
      case 1U: {
        packet::isis::AreaAddressCursor areas(*option);
        while (areas.next()) {}
        if (!areas.valid()) return nullptr;
        break;
      }
      case 129U:
        if (packet::isis::supports_protocol(*option, packet::isis::ipv4_nlpid)) peer_families |= 1U;
        if (packet::isis::supports_protocol(*option, packet::isis::ipv6_nlpid)) peer_families |= 2U;
        break;
      case 132U:
        if (!packet::isis::FixedAddressCursor<4U>(*option, 132U).valid()) return nullptr;
        break;
      case 232U:
        if (!packet::isis::valid_ipv6_interface_addresses(*option, projection.type)) return nullptr;
        break;
      case 229U: break; // MT encoding was checked by supports_topology above.
      default: return nullptr; // Only the receive owner's non-secret projection is legal.
      }
    }
    if (!options.valid()) return nullptr;
    for (const auto protocol : configuration.protocols) {
      if (protocol == packet::isis::ipv4_nlpid) local_families |= 1U;
      if (protocol == packet::isis::ipv6_nlpid) local_families |= 2U;
    }
    if (saved.adjacency.state.present && (!common_topology || !(local_families & peer_families) ||
        (configuration.strict_adjacency_check && local_families != peer_families))) return nullptr;
    result->peer_.assign(saved.peer_attributes.begin(), saved.peer_attributes.end());
    result->operational_ = saved.operational;
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
