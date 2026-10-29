// One LAN circuit level owns its neighbors, DIS selection and Hello schedule.
// All mutation runs on the IS-IS control owner. Only encoded frames supply peer
// information; synchronous events connect to the enclosing LSP originator.

#pragma once

#include "router/isis_circuit_configuration.hpp"
#include "router/isis_hello_schedule.hpp"
#include "router/isis_lan_adjacency_set.hpp"

namespace router::isis {
struct LanCircuitConfiguration : CircuitHelloConfiguration {
  DisLocal local;
  Levels levels{Levels::none};
  packet::isis::PduType type{};
  LanSetLimits limits;
  std::chrono::microseconds designated_hello_interval{};
  std::uint16_t designated_holding_seconds{};
};
struct LanCircuitObserver {
  void *context{};
  LanPeerObserver peer{};
  // Borrowed selections last only through this callback. Local-role changes
  // require pseudonode generation or purge by the same instance owner.
  void (*designated)(void *, const std::optional<DisSelection> &,
      const std::optional<DisSelection> &) noexcept{};
};
enum class LanCircuitReceive : std::uint8_t {
  accepted, discarded, malformed, instance, authentication, area, capacity, missing_observer
};
class LanCircuit final {
public:
  using Clock = HelloSchedule::Clock;
  // Effective non-DIS and DIS intervals/holding values are resolved by the
  // model owner. Invalid values throw before publication; storage reserves at
  // construction. Initial election delay uses twice the non-DIS interval.
  LanCircuit(LanCircuitConfiguration configuration, std::uint64_t random_state,
      Clock::time_point now);
  LanCircuit(const LanCircuit &) = delete;
  LanCircuit &operator=(const LanCircuit &) = delete;
  LanCircuit(LanCircuit &&) noexcept = default;
  LanCircuit &operator=(LanCircuit &&) noexcept = default;
  [[nodiscard]] LanCircuitReceive receive(const packet::Frame &frame,
      std::optional<AuthenticationKey> key, Clock::time_point now,
      LanCircuitObserver observer) noexcept;
  // Drains at most budget expirations and reevaluates DIS after each Down.
  // The caller must service another immediate deadline if more peers are due.
  void service(Clock::time_point now, std::size_t budget, LanCircuitObserver observer) noexcept;
  [[nodiscard]] std::optional<HelloBuildResult> hello(packet::Frame &frame,
      std::optional<AuthenticationKey> key, PduScratch &scratch,
      Clock::time_point now, LanCircuitObserver observer) noexcept;
  [[nodiscard]] bool complete_hello(bool enqueued, Clock::time_point now) noexcept;
  [[nodiscard]] bool down(LanCircuitObserver observer) noexcept;
  [[nodiscard]] Clock::time_point deadline() const noexcept;
  [[nodiscard]] const LanAdjacencySet &neighbors() const noexcept { return neighbors_; }
  [[nodiscard]] std::optional<DisSelection> designated() const noexcept { return designated_; }
private:
  [[nodiscard]] bool valid_observer(LanCircuitObserver observer) const noexcept;
  void elect(Clock::time_point now, LanCircuitObserver observer) noexcept;
  LanCircuitConfiguration configuration_;
  LanAdjacencySet neighbors_;
  HelloSchedule hello_;
  Clock::time_point election_ready_{};
  std::vector<std::span<const std::uint8_t>> areas_;
  std::vector<packet::Mac> hello_neighbors_;
  std::vector<DisNeighbor> candidates_;
  std::optional<DisSelection> designated_;
  packet::isis::LanId advertised_lan_{};
  bool election_started_{};
  bool operational_{true};
};
} // namespace router::isis
