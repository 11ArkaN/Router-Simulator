// RFC 5303 three-way option codec and pure transition decisions. The adjacency
// owner retains state; this module owns no timer or neighbor and depends only
// on the IS-IS wire contract. ISO adjacency state remains a separate FSM.

#pragma once

#include "router/isis_packet.hpp"

namespace router::isis {

enum class ThreeWayState : std::uint8_t { up = 0U, initializing = 1U, down = 2U };
enum class ThreeWayAction : std::uint8_t { discard, legacy, initialize, up, accept, down };

struct ThreeWayOption {
  ThreeWayState state{ThreeWayState::down};
  std::optional<std::uint32_t> local_circuit;
  std::optional<packet::isis::SystemId> neighbor_system;
  std::optional<std::uint32_t> neighbor_circuit;
};

struct ThreeWayDecision {
  ThreeWayAction action{ThreeWayAction::discard};
  ThreeWayState next_state{ThreeWayState::down};
};

// Parses option 240 using the six-octet ID profile. Entire optional fields may
// be omitted; partial fields, an invalid state or another TLV return nullopt.
// Values are copied and retain no packet memory. Runs on any owning shard.
[[nodiscard]] std::optional<ThreeWayOption>
decode_three_way(const packet::isis::TlvView &tlv) noexcept;

// Appends one complete option. Optional fields form a prefix of the RFC wire
// structure. Invalid combinations or capacity failure leave the writer intact.
[[nodiscard]] bool encode_three_way(packet::isis::TlvWriter &writer,
                                   const ThreeWayOption &option) noexcept;

// Preconditions: ISO 10589 acceptance, instance and authentication checks have
// been performed. iso_accepted is true only for an ISO "Up" or "Accept" action.
// A malformed option or mismatched neighbor identity is Discard and must not
// refresh holding timers or mutate the adjacency. Legacy follows the original
// ISO procedure. Initialize emits no adjacency event; Up/Down emit their named
// events. This API returns values only and has no cross-router side channel.
[[nodiscard]] ThreeWayDecision
three_way_receive(ThreeWayState current, const packet::isis::SystemId &local_system,
                  std::uint32_t local_circuit, bool iso_accepted,
                  std::optional<packet::isis::TlvView> option) noexcept;

} // namespace router::isis
