// One circuit/instance/level owns this bounded LAN neighbor collection. Its
// control shard retains area projections and synchronously dispatches local
// adjacency events. No forwarding, runtime or other device state is accessed.

#pragma once

#include "router/isis_adjacency.hpp"
#include "router/isis_lan_adjacency.hpp"

#include <vector>

namespace router::isis {

struct NeighborArea {
  std::array<std::uint8_t, packet::isis::maximum_area_octets> bytes{};
  std::uint8_t length{};
  // Set-owned projections guarantee 1 <= length <= bytes.size(). A caller
  // constructing a value independently must preserve that extent invariant.
  [[nodiscard]] std::span<const std::uint8_t> view() const noexcept {
    return std::span(bytes).first(length);
  }
};
struct LanSetLimits {
  std::size_t neighbors{};
  std::size_t areas_per_neighbor{};
};
struct LanPeerView {
  LanSnapshot adjacency;
  std::span<const NeighborArea> areas;
};
enum class LanEventCause : std::uint8_t { received, expired, capacity_evicted, circuit_down };
struct LanPeerEvent {
  LanPeerView before;
  LanPeerView after;
  LanUpdate transition;
  LanEventCause cause{};
};
// The same control owner completes local area/flooding Down work before this
// callback returns. An eviction inserts the replacement only afterward. Views
// borrow until return; callback may query this set but must not mutate it.
using LanPeerObserver = void (*)(void *, const LanPeerEvent &) noexcept;

enum class LanSetResult : std::uint8_t {
  accepted, discarded, malformed, capacity_refused, memory_refused, missing_observer
};

class LanAdjacencySet final {
public:
  using Clock = LanAdjacency::Clock;
  // Type must be an L1/L2 LAN Hello. Limits are explicit emulator resources,
  // not protocol or vendor scale claims. Metadata and reusable receive scratch
  // allocate here; a new peer allocates its bounded area storage before any
  // eviction. Allocation/invalid container extent may throw at construction.
  LanAdjacencySet(packet::isis::PduType type, packet::Mac local, LanSetLimits limits);

  // Owner has accepted media, instance, authentication and level-specific
  // area/max-area tests and drained due holding expirations. This call retains
  // all received area options before refreshing any timer. Existing MAC with
  // a changed system ID is discarded. Capacity includes Initializing peers;
  // the lowest priority then lowest MAC loses. Failed admission changes no
  // peer or timer. Every accepted update, including one-way loss, is observed.
  // Area and neighbor budgets refuse admission explicitly; existing updates
  // reuse preallocated area buffers without transferring borrowed wire views.
  [[nodiscard]] LanSetResult receive(const packet::isis::PduView &pdu,
      const packet::Mac &source, Clock::time_point now,
      void *context, LanPeerObserver observer) noexcept;

  // Removes at most one due adjacency per call, emitting Down even for an
  // Initializing record. The instance driver supplies its own work budget.
  // A missing observer performs no mutation and returns false.
  [[nodiscard]] bool expire_one(Clock::time_point now,
      void *context, LanPeerObserver observer) noexcept;
  // Circuit shutdown emits and completes each Down before destroying its
  // retained area projection. Returns false without mutation if the observer
  // is missing. No events are emitted by the destructor.
  [[nodiscard]] bool circuit_down(void *context, LanPeerObserver observer) noexcept;
  // Views borrow until the next mutation. Queries run on the same owner only.
  [[nodiscard]] std::optional<LanPeerView> find(const packet::Mac &mac) const noexcept;
  [[nodiscard]] std::optional<LanPeerView> at(std::size_t index) const noexcept;
  // Earliest owner-local holding deadline, or nullopt for an empty collection.
  [[nodiscard]] std::optional<Clock::time_point> deadline() const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return peers_.size(); }

private:
  struct Peer {
    LanAdjacency adjacency;
    std::vector<NeighborArea> areas;
  };
  [[nodiscard]] LanPeerView view(const Peer &peer) const noexcept;
  [[nodiscard]] std::size_t position(const packet::Mac &mac) const noexcept;
  [[nodiscard]] LanSetResult stage_areas(const packet::isis::PduView &pdu) noexcept;
  Peer remove(std::size_t index, LanEventCause cause, Clock::time_point now,
              void *context, LanPeerObserver observer) noexcept;
  packet::isis::PduType type_;
  packet::Mac local_;
  LanSetLimits limits_;
  std::vector<Peer> peers_;
  std::vector<NeighborArea> area_scratch_;
  std::vector<LanCandidate> candidate_scratch_;
};

} // namespace router::isis
