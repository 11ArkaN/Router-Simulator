// One P2P adjacency's negotiated identity, ISO/three-way states and holding
// deadline. The IS-IS control shard is the sole mutable owner. Area/address
// retention and protocol events remain with its enclosing instance process.

#pragma once

#include "router/isis_adjacency.hpp"
#include "router/isis_three_way.hpp"

#include <chrono>

namespace router::isis {

enum class P2pReason : std::uint8_t {
  none, wrong_system, area_mismatch, maximum_area_mismatch, invalid_state,
  invalid_three_way, different_lan_neighbor, identity_changed, neighbor_restarted,
  holding_expired, circuit_down
};
enum class P2pOutcome : std::uint8_t { discarded, rejected, initializing, up, accepted, down };
struct P2pUpdate {
  P2pOutcome outcome{P2pOutcome::discarded};
  P2pReason reason{P2pReason::none};
  bool holding_refreshed{};
  bool forwarding_readiness_changed{};
};

struct P2pLocal {
  packet::isis::SystemId system{};
  std::uint32_t extended_circuit{};
  std::uint8_t local_circuit{};
  Levels levels{Levels::none};
  bool over_lan{};
};

struct P2pSnapshot {
  packet::isis::SystemId neighbor_system{};
  packet::Mac neighbor_mac{};
  packet::isis::LanId negotiated_circuit{};
  std::optional<std::uint32_t> neighbor_extended_circuit;
  Levels usage{Levels::none};
  ThreeWayState three_way{ThreeWayState::down};
  bool present{};
  bool iso_up{};
  bool uses_three_way{};
};

class PointToPointAdjacency final {
public:
  using Clock = std::chrono::steady_clock;
  // Local levels must be nonzero and valid, otherwise throws invalid_argument.
  // Circuit IDs are assigned by the instance owner and remain immutable until
  // this object is replaced. Construction performs no allocation.
  explicit PointToPointAdjacency(P2pLocal local);

  // Preconditions: the enclosing owner accepted the encoded P2P Hello's media,
  // instance, authentication and mandatory options, preflighted neighbor data
  // retention, and computed area matching from those same wire bytes. Supply
  // the received option 240, if present. No borrowed input is retained.
  // Dispatch an expired holding deadline with expire() before this call, so
  // an expiration Down event precedes any new adjacency created by the Hello.
  // Invalid three-way options or a different established P2P-over-LAN peer
  // discard without refreshing the deadline. Up/Down are protocol events;
  // Initializing emits no ISO adjacency event. Runs only on the control shard.
  [[nodiscard]] P2pUpdate receive(const packet::isis::HelloView &hello,
      const packet::Mac &source, bool matching_area, bool matching_maximum_areas,
      std::optional<packet::isis::TlvView> three_way, Clock::time_point now) noexcept;

  // Holding expiry deletes even an initializing adjacency and emits Down.
  // Calling before the deadline or with no adjacency leaves state unchanged.
  [[nodiscard]] P2pUpdate expire(Clock::time_point now) noexcept;
  [[nodiscard]] P2pUpdate circuit_down() noexcept;
  [[nodiscard]] P2pSnapshot snapshot() const noexcept { return state_; }
  [[nodiscard]] std::optional<Clock::time_point> deadline() const noexcept;
  [[nodiscard]] bool ready() const noexcept;
  // Outbound option contains this circuit's assigned ID and includes the peer
  // identity only when both peer fields are known in Initializing or Up.
  [[nodiscard]] ThreeWayOption outbound_three_way() const noexcept;

private:
  [[nodiscard]] P2pUpdate remove(P2pReason reason) noexcept;
  P2pLocal local_;
  P2pSnapshot state_;
  Clock::time_point holding_deadline_{};
};

} // namespace router::isis
