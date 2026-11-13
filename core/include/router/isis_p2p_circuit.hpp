// One point-to-point circuit owns its negotiated adjacency, received peer
// attributes and Hello schedule. Its instance control shard is the sole owner.
// Only encoded frames enter or leave; local events never carry peer shortcuts.

#pragma once

#include "router/isis_circuit_configuration.hpp"
#include "router/isis_hello_schedule.hpp"
#include "router/isis_neighbor_attributes.hpp"
#include "router/isis_p2p_adjacency.hpp"

#include <memory>

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

struct P2pCircuitCheckpoint {
  std::uint32_t version{1U};
  P2pCircuitConfiguration configuration;
  P2pAdjacencyCheckpoint adjacency;
  HelloScheduleCheckpoint hello;
  std::vector<std::uint8_t> peer_attributes;
  bool operational{};
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
  // Restarts the local timer with retained PRNG state. Operational recovery
  // retains monotonically increasing receipt tickets; configuration replacement
  // additionally requires a fresh circuit epoch in the enclosing owner.
  [[nodiscard]] bool up(Clock::time_point now) noexcept;
  // Circuit owner only. Preflights retained attributes before changing policy.
  // Matching peers, timers and counters survive; mismatched peers complete Down
  // synchronously. Missing observer or malformed retained input changes nothing.
  [[nodiscard]] bool set_strict_adjacency_check(bool enabled, void *context, P2pCircuitObserver observer) noexcept;
  // Same circuit control writer. Assignment changes advertised addresses only;
  // NLPIDs, peers and periodic PRNG survive. Content changes request a fresh
  // Hello through ordinary scheduling, including LAN minimum spacing.
  [[nodiscard]] bool set_ipv6_addresses_ready(bool ready) noexcept {
    if (configuration_.ipv6_addresses_ready == ready) return false;
    configuration_.ipv6_addresses_ready = ready; hello_.changed(); return true;
  }
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
  // or generation replacement or a policy edit; no forwarding or UI owner may retain the view.
  [[nodiscard]] const P2pCircuitConfiguration &configuration() const noexcept { return configuration_; }

  // Same circuit owner after transport quiescence. Capture owns non-secret
  // peer attributes and timers, and can throw allocation/clock errors. Restore
  // requires identical effective configuration and publishes a fresh heap owner
  // only after all nested values pass validation; refusal emits no events.
  [[nodiscard]] P2pCircuitCheckpoint checkpoint(Clock::time_point now) const;
  [[nodiscard]] static std::unique_ptr<PointToPointCircuit> restore_checkpoint(const P2pCircuitCheckpoint &saved,
      P2pCircuitConfiguration expected, Clock::time_point now) noexcept;
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
