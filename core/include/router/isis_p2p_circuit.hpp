// One point-to-point circuit owns its negotiated adjacency, received peer
// attributes and Hello schedule. Its instance control shard is the sole owner.
// Only encoded frames enter or leave; local events never carry peer shortcuts.

#pragma once

#include "router/isis_circuit_configuration.hpp"
#include "router/isis_hello_schedule.hpp"
#include "router/isis_neighbor_attributes.hpp"
#include "router/isis_p2p_adjacency.hpp"

namespace router::isis {

struct P2pCircuitConfiguration : CircuitHelloConfiguration {
  P2pLocal local;
  bool physical_point_to_point{};
  bool operator==(const P2pCircuitConfiguration &) const = default;
};

struct P2pCircuitEvent {
  P2pSnapshot before;
  P2pSnapshot after;
  P2pUpdate transition;
  std::span<const std::uint8_t> previous_attributes;
  std::span<const std::uint8_t> attributes;
};
// Same-owner synchronous callback. Borrowed attributes expire on return.
// Down processing must finish here before the instance accepts replacement
// state. The observer must not mutate this circuit or retain borrowed views.
using P2pCircuitObserver = void (*)(void *, const P2pCircuitEvent &) noexcept;

enum class CircuitReceive : std::uint8_t {
  accepted, discarded, malformed, instance, authentication, topology, capacity,
  missing_observer, address_family
};

class PointToPointCircuit final {
public:
  using Clock = HelloSchedule::Clock;
  // Effective configuration is owned by value. All receive projection storage
  // allocates before publication. Invalid local values throw. Keys are never
  // retained: their vault leases must outlive only the synchronous API call.
  PointToPointCircuit(P2pCircuitConfiguration configuration,
      std::uint64_t random_state, Clock::time_point now);
  PointToPointCircuit(const PointToPointCircuit &) = delete;
  PointToPointCircuit &operator=(const PointToPointCircuit &) = delete;
  PointToPointCircuit(PointToPointCircuit &&) noexcept = default;
  PointToPointCircuit &operator=(PointToPointCircuit &&) noexcept = default;
  [[nodiscard]] CircuitReceive receive(const packet::Frame &frame,
      std::optional<AuthenticationKey> key, Clock::time_point now,
      void *context, P2pCircuitObserver observer) noexcept;
  // Expiry dispatches Down with the old peer attributes before releasing them.
  [[nodiscard]] bool expire(Clock::time_point now,
      void *context, P2pCircuitObserver observer) noexcept;
  [[nodiscard]] bool down(void *context, P2pCircuitObserver observer) noexcept;
  // Owner increments its circuit epoch before reactivation, invalidating all
  // old output receipts. Restarts the local timer with retained PRNG state.
  [[nodiscard]] bool up(Clock::time_point now) noexcept;
  [[nodiscard]] bool operational() const noexcept { return operational_; }
  [[nodiscard]] bool hello_pending() const noexcept { return hello_.pending(); }
  [[nodiscard]] std::optional<Clock::time_point> holding_deadline() const noexcept {
    return adjacency_.deadline();
  }
  // A successful build reserves the Hello until complete_hello receives its
  // actual egress result. The instance supplies exclusively owned scratch and
  // sends the returned encoded frame through its normal egress SPSC channel.
  [[nodiscard]] std::optional<HelloBuildResult> hello(packet::Frame &output,
      std::optional<AuthenticationKey> key, PduScratch &scratch,
      Clock::time_point now) noexcept;
  [[nodiscard]] bool complete_hello(bool enqueued, Clock::time_point now) noexcept;
  [[nodiscard]] Clock::time_point deadline() const noexcept;
  [[nodiscard]] P2pSnapshot adjacency() const noexcept { return adjacency_.snapshot(); }
  [[nodiscard]] std::span<const std::uint8_t> peer_attributes() const noexcept { return peer_; }
  // Same-owner immutable construction value. Borrow only until circuit removal
  // or generation replacement; no forwarding or UI owner may retain the view.
  [[nodiscard]] const P2pCircuitConfiguration &configuration() const noexcept { return configuration_; }

private:
  void event(const P2pSnapshot &before, P2pUpdate update,
      std::span<const std::uint8_t> previous, void *context,
      P2pCircuitObserver observer) noexcept;
  P2pCircuitConfiguration configuration_;
  PointToPointAdjacency adjacency_;
  HelloSchedule hello_;
  std::vector<std::span<const std::uint8_t>> areas_;
  std::vector<std::uint8_t> peer_;
  std::vector<std::uint8_t> staged_;
  bool operational_{true};
};

} // namespace router::isis
