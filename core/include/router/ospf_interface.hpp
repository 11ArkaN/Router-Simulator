// Owner-local OSPF interface and neighbor runtime. One control shard mutates
// each instance. Deadlines use steady_clock and configuration values supplied
// by the release-scoped datastore, with no global timer queue or simulated time.

#pragma once

#include "router/ospf_fsm.hpp"
#include "router/ospf_lsdb.hpp"
#include "router/ospf_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::ospf {

struct InterfaceConfiguration {
  std::uint32_t router_id{};
  std::uint32_t area_id{};
  std::uint32_t interface_id{};
  std::uint32_t network_mask{};
  // OSPFv2 writes the local interface IPv4 address into Hello DR/BDR fields.
  // OSPFv3 leaves this zero because its election identity is the Router ID.
  std::uint32_t local_election_identity{};
  std::uint32_t options{};
  std::uint16_t hello_interval_seconds{};
  std::uint16_t dead_interval_seconds{};
  std::uint16_t interface_mtu{};
  std::uint8_t router_priority{};
  std::uint8_t version{};
  std::uint8_t instance_id{};
  // Runtime configurations normally copy the validated configuration intent.
  // Keep the defensive default aligned with SR OS Ethernet behavior so a
  // partially constructed test or restore object cannot silently bypass the
  // broadcast election required on a multi-access segment.
  NetworkType network_type{NetworkType::broadcast};
  bool passive{};
  bool enabled{};
  bool operator==(const InterfaceConfiguration &) const = default;
};

struct NeighborRuntime {
  std::uint32_t router_id{};
  // OSPFv2 elects by Router ID but advertises the neighbor's interface IPv4
  // address in the DR and BDR fields. OSPFv3 uses Router ID for both. This
  // owner-local value records the version-specific wire identity supplied by
  // the packet owner and is never inferred from the editor topology.
  std::uint32_t election_identity{};
  // RFC 5340 section 3.2.1 carries the neighbor's locally assigned Interface
  // ID in every OSPFv3 Hello. Router-LSAs must repeat that received value for
  // the remote end of a point-to-point link. OSPFv2 has no equivalent field,
  // so its neighbor records leave this member zero and never serialize it.
  std::uint32_t interface_id{};
  std::uint32_t designated_router{};
  std::uint32_t backup_designated_router{};
  // Options is the exact capability bitmap accepted from the latest valid
  // Hello. The show owner must report peer-advertised capability state rather
  // than substituting the local interface configuration.
  std::uint32_t options{};
  RuntimeClock::time_point inactivity_deadline{};
  // These timestamps and counters belong to the neighbor FSM owner. Keeping
  // them beside state prevents a show command from fabricating timing data by
  // observing UI events or the editor topology.
  RuntimeClock::time_point state_since{};
  RuntimeClock::time_point last_event_at{};
  RuntimeClock::time_point last_restart_at{};
  std::uint64_t event_count{};
  std::uint64_t restart_count{};
  std::uint64_t bad_neighbor_states{};
  std::uint64_t bad_sequence_numbers{};
  std::uint64_t bad_link_state_requests{};
  NeighborState state{NeighborState::down};
  std::uint8_t priority{};
};

enum class HelloDisposition : std::uint8_t {
  accepted,
  malformed,
  interface_down,
  self,
  area_mismatch,
  instance_mismatch,
  timer_mismatch,
  network_mask_mismatch,
  options_mismatch,
  neighbor_capacity_exhausted
};

struct HelloResult {
  HelloDisposition disposition{HelloDisposition::malformed};
  NeighborState state{NeighborState::down};
  NeighborAction actions{NeighborAction::none};
  std::uint32_t neighbor_router_id{};
  // RFC 2328 section 9.2 raises BackupSeen only while the interface waits for
  // the initial election. The packet owner reports the condition separately
  // from NeighborChange so InterfaceRuntime can select the exact FSM event.
  bool backup_seen{};
};

struct ExpiredNeighbor {
  std::uint32_t router_id{};
  NeighborAction actions{NeighborAction::none};
};

struct NeighborReconciliation {
  std::uint32_t router_id{};
  NeighborAction actions{NeighborAction::none};
};

struct InterfaceRuntimeCheckpoint {
  InterfaceConfiguration configuration;
  std::vector<NeighborRuntime> neighbors;
  std::chrono::milliseconds hello_remaining{};
  std::chrono::milliseconds wait_remaining{};
  InterfaceState state{InterfaceState::down};
  std::uint32_t designated_router{};
  std::uint32_t backup_designated_router{};
};

class InterfaceRuntime final {
public:
  InterfaceRuntime(InterfaceConfiguration configuration,
                   std::size_t maximum_neighbors,
                   RuntimeClock::time_point now);

  // validate_configuration contains only protocol and representation rules.
  // Platform-specific ranges are checked by the generated CLI and datastore
  // before this value reaches the protocol owner.
  [[nodiscard]] static bool
  validate_configuration(const InterfaceConfiguration &configuration) noexcept;

  [[nodiscard]] HelloResult
  receive_hello(const packet::ospf::PacketView &packet,
                std::uint32_t neighbor_election_identity,
                RuntimeClock::time_point now) noexcept;

  // process_deadlines writes at most output.size() expired neighbors. false
  // means the caller's work budget was insufficient and it must immediately
  // schedule another owner turn before sleeping.
  [[nodiscard]] bool
  process_deadlines(RuntimeClock::time_point now,
                    std::span<ExpiredNeighbor> output,
                    std::size_t &written) noexcept;
  // A standards-valid graceful-restart helper relationship suppresses only
  // the neighbor inactivity transition until its owner-local grace deadline.
  // The OSPF instance, not this generic FSM, decides whether helper policy and
  // Grace-LSA validation permit that deferral.
  [[nodiscard]] bool defer_inactivity(
      std::uint32_t router_id,
      RuntimeClock::time_point deadline) noexcept;
  // The multi-access WaitTimer is an interface-owned deadline. Expiry runs the
  // RFC election from this interface's accepted Hello repository and returns
  // the resulting origination actions to the instance owner.
  [[nodiscard]] InterfaceAction
  process_interface_deadline(RuntimeClock::time_point now) noexcept;
  // A Hello, 1-Way transition or neighbor expiry can alter the multi-access
  // candidate set. The owner passes BackupSeen explicitly because it ends the
  // WaitTimer, while an ordinary NeighborChange during Waiting does not.
  [[nodiscard]] InterfaceAction neighbor_change(bool backup_seen) noexcept;
  // DR and BDR election changes which 2-Way neighbors require adjacency.
  // Re-run AdjacencyOk for the complete bounded repository and return only
  // neighbors whose FSM emitted work. false means the caller supplied too
  // little output space and no neighbor state was changed.
  [[nodiscard]] bool reconcile_adjacencies(
      std::span<NeighborReconciliation> output,
      std::size_t &written) noexcept;
  [[nodiscard]] std::optional<RuntimeClock::time_point>
  next_deadline() const noexcept;

  [[nodiscard]] bool hello_due(RuntimeClock::time_point now) const noexcept;
  void hello_sent(RuntimeClock::time_point now) noexcept;

  // The payload encoder writes only the version-specific Hello body. The packet
  // owner then adds authentication and IPv4 or IPv6 pseudo-header checksums.
  [[nodiscard]] std::optional<std::span<const std::uint8_t>>
  encode_hello_payload(std::span<std::uint8_t> output) const noexcept;

  [[nodiscard]] std::span<const NeighborRuntime> neighbors() const noexcept {
    return neighbors_;
  }
  [[nodiscard]] const InterfaceConfiguration &configuration() const noexcept {
    return configuration_;
  }
  [[nodiscard]] InterfaceState state() const noexcept { return state_; }
  // These are the exact identities encoded in Hello DR and BDR fields.
  // OSPFv2 returns interface IPv4 addresses and OSPFv3 returns Router IDs.
  [[nodiscard]] std::uint32_t designated_router() const noexcept {
    return designated_router_;
  }
  [[nodiscard]] std::uint32_t backup_designated_router() const noexcept {
    return backup_designated_router_;
  }
  [[nodiscard]] std::optional<NeighborTransition>
  apply_neighbor_event(std::uint32_t router_id, NeighborEvent event,
                       bool requests_pending) noexcept;
  // Delete is separate from the FSM transition because the caller must first
  // consume ClearAdjacency and NeighborChange actions while the row identity
  // is still available. The sole interface owner invokes this only for the
  // explicit KillNbr event defined by RFC 2328 section 10.2.
  [[nodiscard]] bool erase_neighbor(std::uint32_t router_id) noexcept;
  [[nodiscard]] DrBdrElection elect() noexcept;
  void set_election_result(const DrBdrElection &election) noexcept {
    designated_router_ = election.designated_router;
    backup_designated_router_ = election.backup_designated_router;
    state_ = election.local_state;
  }
  [[nodiscard]] InterfaceRuntimeCheckpoint
  checkpoint(RuntimeClock::time_point now) const;
  [[nodiscard]] bool restore(const InterfaceRuntimeCheckpoint &checkpoint,
                             RuntimeClock::time_point now) noexcept;

private:
  [[nodiscard]] bool adjacency_required(
      const NeighborRuntime &neighbor) const noexcept;
  [[nodiscard]] InterfaceAction
  apply_election(InterfaceAction requested) noexcept;

  InterfaceConfiguration configuration_;
  std::vector<NeighborRuntime> neighbors_;
  std::size_t maximum_neighbors_{};
  RuntimeClock::time_point hello_deadline_{};
  RuntimeClock::time_point wait_deadline_{};
  InterfaceState state_{InterfaceState::down};
  std::uint32_t designated_router_{};
  std::uint32_t backup_designated_router_{};
};

} // namespace router::ospf
