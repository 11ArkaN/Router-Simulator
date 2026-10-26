// Pure IS-IS adjacency and DIS decisions. The process owner retains neighbors,
// timers and events; this module returns explicit decisions without mutation.
// Dependencies point only to encoded packet and identifier value contracts.

#pragma once

#include "router/isis_packet.hpp"
#include "router/packet.hpp"

namespace router::isis {

enum class Levels : std::uint8_t { none = 0U, level1 = 1U, level2 = 2U, both = 3U };
enum class P2pAction : std::uint8_t { discard, reject, down, up, accept };
enum class AdjacencyReason : std::uint8_t {
  none, wrong_system, area_mismatch, maximum_area_mismatch, invalid_state
};

struct P2pDecision {
  P2pAction action{P2pAction::discard};
  Levels usage{Levels::none};
  AdjacencyReason reason{AdjacencyReason::none};
};

// ISO 10589 8.2.5.2 tables 5 through 8. current_usage is none unless the ISO
// adjacency is Up. Both area matching and maximum-area matching are explicit
// caller projections. Authentication, instance, envelope and media acceptance
// precede this call. RFC 5303 consumes Up/Accept decisions separately before
// any adjacency event is committed. Invalid states preserve current usage.
[[nodiscard]] P2pDecision p2p_hello_decision(Levels local, Levels remote,
    Levels current_usage, bool matching_area, bool matching_maximum_areas) noexcept;

// ISO circuit-ID negotiation uses the higher system ID and its local circuit
// octet. Equal IDs select the local value. This never changes the local circuit
// identifier placed in outbound Hellos. No allocation or retained memory.
[[nodiscard]] packet::isis::LanId p2p_circuit_id(const packet::isis::SystemId &local,
    std::uint8_t local_circuit, const packet::isis::SystemId &remote,
    std::uint8_t remote_circuit) noexcept;

struct DisLocal {
  packet::isis::SystemId system{};
  packet::Mac mac{};
  std::uint8_t priority{};
  std::uint8_t circuit{};
};
struct DisNeighbor {
  packet::isis::SystemId system{};
  packet::Mac mac{};
  packet::isis::LanId advertised_lan{};
  std::uint8_t priority{};
  bool adjacency_up{};
};
struct DisSelection {
  packet::isis::SystemId system{};
  packet::Mac mac{};
  packet::isis::LanId lan{};
  bool local{};
};

// ISO 10589 8.4.1 and 8.4.5. Caller supplies neighbors for exactly one level
// and instance. Election is suppressed until the initial two-Hello interval
// delay passed and at least one eligible ES/IS adjacency on the circuit is Up.
// Only Up peers compete. Priority zero remains eligible; MAC breaks priority
// ties. A remote winner's reported LAN ID is copied, never inferred from its
// source ID. Invalid priorities return nullopt without retaining input spans.
[[nodiscard]] std::optional<DisSelection> select_dis(const DisLocal &local,
    std::span<const DisNeighbor> neighbors, bool initial_delay_elapsed,
    bool any_up_adjacency) noexcept;

} // namespace router::isis
