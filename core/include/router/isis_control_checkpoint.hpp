// Detached IS-IS control state belongs to the quiescent persistence coordinator.
// Each value owns its payload; no observer, queue pointer, key lease or borrowed
// packet view escapes. Dependencies point to control contracts and child images.

#pragma once

#include "router/isis_control_worker.hpp"
#include "router/isis_checkpoint_time.hpp"

namespace router::isis {
struct ControlEgressCheckpoint {
  struct Retry { packet::isis::LspView header; std::size_t level{}; checkpoint_time::DeadlineCheckpoint at; };
  struct Reservation { std::size_t level{}; std::uint64_t epoch{}, ticket{}; };
  UpdateTransmissionProgram program;
  std::vector<Retry> retries;
  std::array<std::uint64_t, 2U> epochs{}, revision{};
  std::array<checkpoint_time::DeadlineCheckpoint, 2U> partial, complete, complete_periodic, lsp, earliest;
  std::array<bool, 2U> complete_started{}, transient_first{}, designated{};
  std::array<std::size_t, 2U> scan{}, remaining{};
  checkpoint_time::DeadlineCheckpoint pacing, csnp_ready;
  std::size_t credits{};
  std::uint64_t random{};
  std::optional<BroadcastScanCheckpoint> broadcast_scan;
  bool lan_active{}, synchronize{};
  std::optional<Reservation> lan_lsp, lan_csnp;
};
struct ControlCircuitCheckpoint {
  struct PreviousDis {
    std::optional<packet::isis::LanId> remote;
    std::uint16_t fragment{256U};
    checkpoint_time::DeadlineCheckpoint retry;
  };
  CircuitDefinition definition;
  std::variant<P2pCircuitCheckpoint, LanPairCheckpoint> medium;
  protocol::TransmissionWindowCheckpoint transmission;
  std::array<protocol::TransmissionWindowCheckpoint, 2U> lan_transmissions;
  CircuitCounters counters;
  std::optional<std::size_t> update_slot;
  bool queued_lsp{};
  std::array<PreviousDis, 2U> previous_dis;
  std::optional<ControlEgressCheckpoint> egress;
};
struct ControlFamilyCheckpoint {
  std::array<std::optional<DecisionCheckpoint>, 2U> decisions;
  std::array<std::uint64_t, 2U> consumed{};
  std::array<DecisionStatus, 2U> status{DecisionStatus::invalid, DecisionStatus::invalid};
  std::array<std::vector<std::optional<AdjacencyNextHop>>, 2U> bindings;
};
struct ControlInstanceCheckpoint {
  std::uint8_t instance{};
  UpdateInstanceProgram configuration;
  std::optional<InstanceUpdateCheckpoint> process;
  std::optional<LocalLspSetCheckpoint> local;
  std::array<std::optional<DecisionCheckpoint>, 2U> decisions;
  std::array<std::uint64_t, 2U> consumed_decision_revision{}, decision_runs{};
  std::array<DecisionStatus, 2U> decision_status{DecisionStatus::invalid, DecisionStatus::invalid};
  std::array<ControlFamilyCheckpoint, 2U> families;
  std::array<bool, 2U> local_roots_dirty{};
  std::size_t first_root_level{};
  std::array<std::optional<DatabaseValidationCheckpoint>, 2U> validation;
  std::array<std::uint64_t, 2U> database_validations{}, decision_revisions{}, revision{}, expiration_revision{};
  std::array<std::vector<packet::isis::LspId>, 2U> expiration_blocked;
  std::optional<packet::isis::LspId> corrupted_lsp;
  UpdateStatus status{UpdateStatus::applied};
};
struct ControlRouteStamp {
  std::uint64_t epoch{};
  std::array<std::uint64_t, 2U> decision{};
  UpdateStatus status{UpdateStatus::inactive};
  std::uint8_t families{};
};
struct ControlDeviceCheckpoint {
  struct Gate { std::uint8_t instance{}; SequenceRecoveryCheckpoint state; };
  lab::DeviceHandle handle{};
  bool active{};
  std::uint64_t retired_epoch_floor{};
  std::vector<ControlCircuitCheckpoint> circuits;
  std::vector<ControlInstanceCheckpoint> instances;
  std::vector<Gate> gates;
  std::array<std::uint64_t, device_catalog::isis_instance_last + 1U> update_fences{};
  std::vector<std::uint8_t> instance_order;
  std::size_t first_instance{}, first_circuit{};
  std::array<ControlRouteStamp, device_catalog::isis_instance_last + 1U> installed_routes, pending_routes;
  std::uint64_t route_generation{}, route_installed{}, route_pending{};
  routing::RouteInstallStatus route_status{routing::RouteInstallStatus::pending};
  checkpoint_time::DeadlineCheckpoint route_retry_at;
  std::chrono::milliseconds route_retry{};
};
struct ControlWorkerCheckpoint {
  std::uint32_t version{1U};
  std::uint64_t barrier_epoch{};
  std::size_t forwarding_shards{}, maximum_circuits{}, active_circuits{}, first_device{};
  std::vector<ControlDeviceCheckpoint> devices;
};
} // namespace router::isis
