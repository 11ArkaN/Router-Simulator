// One LAN neighbor at one level of one circuit/instance. The control shard
// owns its holding timer and two-way state. The enclosing process owns area
// retention, capacity admission, eviction acknowledgement and DIS election.

#pragma once

#include "router/isis_basic_tlvs.hpp"
#include "router/packet.hpp"

#include <chrono>

namespace router::isis {

enum class LanState : std::uint8_t { initializing, up };
enum class LanOutcome : std::uint8_t { discarded, initializing, up, accepted, down };
enum class LanReason : std::uint8_t { none, malformed, different_peer, one_way, holding_expired, circuit_down };
struct LanUpdate {
  LanOutcome outcome{LanOutcome::discarded};
  LanReason reason{LanReason::none};
  bool holding_refreshed{};
};
struct LanSnapshot {
  packet::isis::SystemId system{};
  packet::Mac mac{};
  packet::isis::LanId advertised_lan{};
  std::uint8_t priority{};
  LanState state{LanState::initializing};
  bool present{};
};

class LanAdjacency final {
public:
  using Clock = std::chrono::steady_clock;
  // type must be L1 or L2 LAN Hello, otherwise throws invalid_argument.
  // Peer identity is immutable for this record. Construction allocates nothing.
  LanAdjacency(packet::isis::PduType type, packet::isis::SystemId peer,
                packet::Mac peer_mac, packet::Mac local_mac);

  // Preconditions: parsed PDU has passed instance, media, authentication and
  // level-specific area/max-area checks. Owner preflighted area retention and
  // capacity, and dispatched due expiry before this call. TLV 6 is decoded
  // from these same wire bytes; malformed lists cannot refresh the deadline.
  // A peer is included in future local Hellos even while Initializing. Up and
  // Down outcomes emit events, with Down/one_way retaining the Init neighbor.
  // Caller retains all PDU bytes; only fixed-width projections are copied.
  [[nodiscard]] LanUpdate receive(const packet::isis::PduView &pdu,
      const packet::Mac &source, Clock::time_point now) noexcept;
  [[nodiscard]] LanUpdate expire(Clock::time_point now) noexcept;
  [[nodiscard]] LanUpdate circuit_down() noexcept;
  [[nodiscard]] LanSnapshot snapshot() const noexcept { return state_; }
  [[nodiscard]] std::optional<Clock::time_point> deadline() const noexcept;

private:
  [[nodiscard]] LanUpdate remove(LanReason reason) noexcept;
  packet::isis::PduType type_;
  packet::isis::SystemId peer_;
  packet::Mac peer_mac_;
  packet::Mac local_mac_;
  LanSnapshot state_;
  Clock::time_point holding_deadline_{};
};

} // namespace router::isis
