// Dedicated IS-IS control owner. Serialized control publishes owned generation
// values; forwarding shards exchange encoded frames through independent SPSC
// pairs. All circuit state remains exclusively on this pthread.

#pragma once

#include "router/isis_instance_update.hpp"
#include "router/isis_broadcast_scan.hpp"
#include "router/isis_lan_circuit_pair.hpp"
#include "router/isis_local_lsp_set.hpp"
#include "router/isis_local_prefix_catalog.hpp"
#include "router/isis_neighbor_origination.hpp"
#include "router/isis_origin_fragment_workspace.hpp"
#include "router/isis_p2p_decision.hpp"
#include "router/isis_spf_throttle.hpp"
#include "router/isis_next_hop.hpp"
#include "router/route_publication.hpp"
#include "router/isis_database_validation.hpp"
#include "router/isis_sequence_recovery.hpp"
#include "router/owned_spsc_channel.hpp"
#include "router/protocol_packet_channel.hpp"
#include "router/protocol_transmission.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <thread>
#include <variant>
#include <stdexcept>

namespace router::isis {

struct ControlWorkerCheckpoint;
struct ControlInstanceCheckpoint;
struct ControlCircuitCheckpoint;
struct AdjacencyQuery;

struct ControlChannels {
  // One forwarding producer and this control consumer per ingress pair. Roles
  // reverse for egress; its receipt returns actual port-queue admission.
  // Capacity and FIFO release/acquire semantics belong to PacketChannel.
  std::array<protocol::PacketChannel<device_catalog::isis_packet_ring_frames>,
             device_catalog::high_forwarding_shards> ingress;
  std::array<protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>,
             device_catalog::high_forwarding_shards> egress;
  // Producer: this protocol pthread. Consumer: serialized network RIB owner.
  // Fixed generations and installation results use the receipt-enabled SPSC
  // contract. The aggregate outlives both owners; no LSDB pointer crosses it.
  std::unique_ptr<::router::routing::RoutePublication> routes{
      std::make_unique<::router::routing::RoutePublication>()};
  void *route_wakeup_context{};
  void (*route_wakeup)(void *){};
  // Installed before startup. Notification carries no network information.
  void *egress_context{};
  void (*egress_wakeup)(void *, std::size_t forwarding_shard){};
};

struct CircuitIdentity {
  lab::DeviceHandle device{};
  std::uint64_t interface_id{};
  std::uint64_t configuration_generation{};
  std::uint16_t physical_port_ordinal{};
  std::uint8_t instance{};
  bool operator==(const CircuitIdentity &) const = default;
};

enum class ControlCommandKind : std::uint8_t {
  query_worker, register_device, remove_device, add_p2p_circuit,
  remove_circuit, query_circuit, prepare_generation, commit_generation,
  abort_generation, add_update_instance, remove_update_instance, query_update_instance, originate_lsp, shutdown,
  query_sequence_recovery, replace_local_content, withdraw_local_content, add_lan_circuit, begin_checkpoint_barrier, end_checkpoint_barrier, capture_checkpoint,
  prepare_checkpoint_restore, commit_checkpoint_restore, abort_checkpoint_restore,
  set_circuit_carrier, set_update_admin_state, query_adjacencies,
  set_local_port_carrier, query_local_port_usage
};
// Exactly one medium is supplied. A broadcast program requires the legacy
// P2P value to remain empty; selecting LAN never constructs a P2P state owner.
[[nodiscard]] inline const CircuitHelloConfiguration *circuit_hello_configuration(
    const P2pCircuitConfiguration &p2p, const std::optional<LanCircuitProgram> &broadcast) noexcept {
  if (!broadcast) return &p2p;
  for (const auto &level : broadcast->levels) if (level) return &*level;
  return nullptr;
}
// Effective values, not product defaults. Positive PSNP/retry seconds, pacing
// period and transit decrement are mandatory. Zero complete_seconds selects
// ISO startup-only CSNP; zero pacing_burst blocks LSP output while SNPs continue.
// The configuration owner resolves per-interface SR OS burst policy beforehand.
// Explicit effective LAN timing, not a vendor default or an optional burst.
// Zero LSP scan suppresses LSP output; CSNP separation stays positive.
struct BroadcastTransmissionProgram {
  std::chrono::microseconds lsp_scan_interval{}, csnp_separation{};
  bool operator==(const BroadcastTransmissionProgram &) const = default;
};
struct UpdateTransmissionProgram {
  std::uint16_t partial_seconds{}, retransmit_seconds{}, complete_seconds{};
  std::chrono::milliseconds pacing_period{};
  std::size_t pacing_burst{};
  std::uint16_t maximum_pdu_octets{}, transit_seconds{};
  std::optional<BroadcastTransmissionProgram> broadcast{};
  bool operator==(const UpdateTransmissionProgram &) const = default;
};
// Immutable same-owner medium view; the referenced Hello configuration outlives
// the current call. No view crosses a queue or a configuration mutation.
struct CircuitUpdateView {
  const CircuitHelloConfiguration &hello;
  packet::isis::SystemId system;
  Levels levels;
  bool physical_point_to_point{}, broadcast{};
  std::uint32_t circuit_id{};
  std::size_t neighbor_capacity{};
};
struct CircuitDefinition {
  CircuitIdentity identity;
  P2pCircuitConfiguration configuration;
  std::uint64_t random_state{};
  std::optional<LanCircuitProgram> broadcast{};
  // Cold effective interface policy overrides the experimental instance policy.
  // It shares the circuit epoch: edits cannot retain live timers/tickets.
  std::optional<UpdateTransmissionProgram> update_transmission{};
  // Effective local port state at cold admission, independent of configured
  // enablement. Down circuits reserve identity/resources for later link Up.
  bool carrier{true};
  [[nodiscard]] const CircuitHelloConfiguration *common() const noexcept {
    return circuit_hello_configuration(configuration, broadcast);
  }
  // Requires common() != nullptr; borrow only through this cold owner call.
  [[nodiscard]] CircuitUpdateView update_view() const noexcept {
    if (!broadcast) return {configuration, configuration.local.system, configuration.local.levels,
        configuration.physical_point_to_point, false, configuration.local.extended_circuit, 0U};
    const auto &first = broadcast->levels[0U] ? *broadcast->levels[0U] : *broadcast->levels[1U];
    std::size_t capacity{};
    for (const auto &level : broadcast->levels)
      if (level && level->limits.neighbors > capacity) capacity = level->limits.neighbors;
    return {first, first.local.system, levels(), false, true, first.local.circuit, capacity};
  }
  // LAN presence is explicit; cold admission checks each advertised mask.
  [[nodiscard]] Levels levels() const noexcept {
    if (!broadcast) return configuration.local.levels;
    return static_cast<Levels>((broadcast->levels[0U] ? 1U : 0U) | (broadcast->levels[1U] ? 2U : 0U));
  }
};
// Explicit LAN origin intent. Circuit identity and maximum accepted neighbor
// budget must match the transport owner; peer system IDs are learned on wire.
struct LanOriginInterface {
  std::uint64_t interface_id{};
  std::uint8_t circuit{};
  std::size_t maximum_neighbors{};
  std::array<std::optional<P2pOriginMetric>, 2U> levels;
  bool operator==(const LanOriginInterface &) const = default;
};
struct LocalOriginProgram {
  LocalLspProgram content;
  // Optional MT0 P2P neighbor ownership. Present programs reserve every allowed
  // interface and metric before activation; base semantic records contain no
  // neighbor TLVs. Values are resolved from the profile, never guessed here.
  std::optional<std::vector<P2pOriginInterface>> neighbors;
  // Emulator allocation recovery policy, supplied explicitly by its owner.
  std::chrono::milliseconds resource_retry{};
  // Cold preparation reserves inactive pseudonode identities and semantic
  // capacity. The same instance owner activates them from actual Up peers/DIS;
  // caller-supplied pseudonode bodies and overlapping P2P interfaces reject.
  std::optional<std::vector<LanOriginInterface>> broadcast_neighbors{};
  // Conditional local reachability belongs to this instance, including passive
  // interfaces without a Hello/update transport. Availability is control-owned.
  std::optional<LocalPrefixCatalogProgram> prefixes{};
  [[nodiscard]] bool automatic_roots() const noexcept {
    return neighbors || broadcast_neighbors || prefixes;
  }
  bool operator==(const LocalOriginProgram &) const = default;
};
// Experimental wide MT0 decision budgets. No production routing or timer
// defaults are inferred; root peers come from this owner's actual circuits.
struct P2pDecisionProgram {
  std::size_t nodes{}, links{}, pending{};
  // Absent family selects topology diagnostics only. Prefix collection requires
  // an explicit IPv4/IPv6 NLPID and never implies forwarding installation.
  std::optional<std::uint8_t> protocol;
  std::optional<PrefixCollectionBudget> prefixes;
  bool operator==(const P2pDecisionProgram &) const = default;
};
// Explicit effective configuration for experimental wide MT0 installation.
// Family protocol and prefix budgets must be present; no vendor default is
// inferred by this control owner. Preferences come from the configuration owner.
struct P2pRouteFamilyProgram {
  P2pDecisionProgram calculation;
  struct Preference {
    std::uint16_t internal{}, external{};
    bool operator==(const Preference &) const = default;
  };
  std::array<Preference, 2U> preferences;
  bool operator==(const P2pRouteFamilyProgram &) const = default;
};
struct UpdateInstanceProgram {
  packet::isis::SystemId local{};
  std::uint8_t maximum_areas{};
  std::array<std::optional<UpdateLevelConfiguration>, 2U> levels;
  std::size_t maximum_circuits{};
  UpdateTransmissionProgram transmission;
  std::uint16_t wire_instance{};
  packet::isis::InstanceFormat format{packet::isis::InstanceFormat::standard};
  std::optional<LocalOriginProgram> origination{};
  std::optional<P2pDecisionProgram> decision{};
  std::array<std::optional<P2pRouteFamilyProgram>, 2U> routing{};
  // Absent retains the explicit experimental immediate-decision policy.
  // Canonical SR OS preparation supplies normalized source-backed SPF delays.
  std::optional<SpfDelayPolicy> spf_delay{};
  bool operator==(const UpdateInstanceProgram &) const = default;
};
// Fresh owner programs transfer with a circuit generation, in sorted key order.
// Additions require absent keys and no transport-only bindings. Replacement
// explicitly requires a live owner plus the same key in retired_instances.
struct NewUpdateInstance {
  std::uint8_t instance{};
  UpdateInstanceProgram program;
  bool replace_existing{};
  // Detached owner starts with this local administrative gate before any circuit binds.
  bool admin_enabled{true};
};
// The serialized configuration owner transfers sorted, unique local instance
// edits to the control pthread through the command SPSC lease. The receiver
// exclusively owns their storage; invalid keys or exhausted epochs refuse
// preparation without changing live state. Capacity is the local instance range.
// Cold root-policy edit. Configuration publishes sorted unique instance keys;
// the control owner commits all edits only after generation preparation succeeds.
struct UpdateAdjacencyPolicy { std::uint8_t instance{}; bool strict_families{}; };
// Owned cold catalog transfers with its root generation. No live prefix view
// crosses the configuration/control SPSC boundary; commit swaps reserved state.
struct UpdatePrefixCatalog { std::uint8_t instance{}; LocalPrefixCatalogProgram program; };
struct UpdateAdminState {
  std::uint8_t instance{};
  bool enabled{};
};
struct ControlCommand {
  // One-shot cold query lease, transferred inside OwnedSpscChannel. A fresh
  // object belongs to exactly one command and must never be resubmitted.
  // Caller retains one
  // strong reference but must not read or write its value until this command's
  // matching result acquire. The IS-IS pthread is the sole writer until that
  // release; afterward the result is immutable. A refused query has no rows.
  std::shared_ptr<AdjacencyQuery> adjacency_query{};
  std::uint64_t id{};
  ControlCommandKind kind{ControlCommandKind::query_worker};
  // Serialized persistence coordinator. Begin requires zero and returns a new
  // owner-local token; End must echo that exact token. No network information
  // or clock is carried, and the token alone does not pause forwarding owners.
  std::uint64_t checkpoint_barrier_epoch{};
  // Internal synchronous transfer only. The serialized coordinator owns a
  // ControlWorkerCheckpoint at this address and waits for this exact result
  // before ending its lifetime. Neither pointer nor host epoch is persisted.
  std::uintptr_t checkpoint_transfer{};
  std::int64_t checkpoint_now_nanoseconds{};
  std::uint64_t checkpoint_source_epoch{};
  // Local physical state, serialized by the network owner. A carrier event
  // carries no peer data and preserves configuration identity and ticket floors.
  bool carrier{true};
  CircuitIdentity identity;
  // set_update_admin_state selects an existing instance on this device.
  // This gate is independent of every circuit's local physical carrier.
  bool admin_enabled{true};
  P2pCircuitConfiguration configuration;
  std::uint64_t random_state{};
  std::optional<LanCircuitProgram> broadcast{};
  // Cold effective interface policy overrides the experimental instance policy.
  // It shares the circuit epoch: edits cannot retain live timers/tickets.
  std::optional<UpdateTransmissionProgram> update_transmission{};
  // Complete router generation, sorted by interface ID then local instance.
  // OwnedSpscChannel transfers these values without copying containers into a
  // ring. Prepare allocates before publication; commit preserves unchanged
  // epochs and consumes no heap storage. Abort leaves every live circuit intact.
  std::vector<CircuitDefinition> circuits;
  std::vector<NewUpdateInstance> new_instances;
  std::vector<UpdateAdminState> administrative;
  std::vector<UpdateAdjacencyPolicy> adjacency_policies;
  std::vector<UpdatePrefixCatalog> prefix_catalogs;
  // Serialized RIB high water. Preparation reserves a strictly newer local
  // publication for synchronous administrative withdrawal of both families.
  std::uint64_t route_generation_floor{};
  // Sorted live keys withdrawn by this complete generation. No candidate
  // circuit may reference a pure retirement. An explicit replacement supplies
  // its fresh owner and fresh circuit epochs. Prepare never detaches live state.
  std::vector<std::uint8_t> retired_instances;
  // Experimental update admission supplies all effective values and budgets.
  // Raw local PDUs already passed the originator's sequence and key policy.
  std::optional<UpdateInstanceProgram> update;
  std::vector<std::uint8_t> local_lsp;
  // Owned local configuration intent, never received peer content.
  std::optional<LocalLspContent> local_content;
  std::uint8_t level{};
  // Read-only selected-LSP projection; no retained packet view crosses owners.
  std::optional<packet::isis::LspId> selected_lsp{};
  std::optional<ip::IpPrefix> selected_prefix{};
  std::optional<ip::IpAddress> selected_next_hop{};
  std::optional<packet::Mac> selected_lan_peer{};
  OriginPurgeReason purge{OriginPurgeReason::none};
};
enum class ControlError : std::uint8_t {
  none, invalid_argument, stale_device, stale_configuration, not_found,
  already_exists, capacity, unsupported_authentication, construction_failed,
  generation_pending, epoch_exhausted, update_refused, unsupported_update_instance, sequence_cooldown,
  unsupported_origination, unsupported_update_medium, checkpoint_barrier_pending, stale_checkpoint_barrier
};
struct CircuitCounters {
  std::uint64_t received{};
  std::uint64_t discarded{};
  std::uint64_t stale_ingress{};
  std::uint64_t stale_completion{};
  std::uint64_t hello_enqueued{};
  std::uint64_t hello_refused{};
  std::uint64_t adjacency_up{};
  std::uint64_t adjacency_down{};
  std::uint64_t transmission_exhausted{};
  std::uint64_t update_received{}, update_discarded{};
  UpdateStatus last_update{UpdateStatus::inactive};
  std::uint64_t lsp_enqueued{}, lsp_refused{}, snp_enqueued{}, snp_refused{};
  std::uint64_t lsp_too_large{}, purge_pending{}, designated_changes{};
};
struct ControlResult {
  std::uint64_t id{};
  // A nonzero value reports protocol-owner quiescence only. The result ring's
  // release/acquire acknowledgement publishes all prior protocol state writes.
  std::uint64_t checkpoint_barrier_epoch{};
  // On successful barrier acquisition, the protocol owner samples this anchor
  // after stopping service. Reuse it for joined capture/restore: independent
  // browser performance clocks can differ even after an acknowledged handoff.
  std::int64_t checkpoint_anchor_nanoseconds{};
  ControlError error{ControlError::none};
  P2pSnapshot adjacency{};
  bool carrier{true};
  bool admin_enabled{true};
  bool broadcast_circuit{};
  bool local_port_in_use{};
  std::array<std::size_t, 2U> lan_neighbors{}, lan_up{};
  std::array<std::optional<DisSelection>, 2U> designated{};
  std::optional<AdjacencyNextHop> bound_next_hop{};
  CircuitCounters counters{};
  std::uint64_t thread_identity{};
  std::int64_t holding_deadline_nanoseconds{};
  std::uint32_t active_circuits{};
  bool hello_pending{};
  std::array<std::size_t, 2U> retained_lsps{}, retained_purges{};
  std::array<std::uint32_t, 2U> local_root_sequences{};
  std::array<std::optional<LspLinkCounts>, 2U> local_root_links{};
  std::array<std::uint64_t, 2U> database_validations{}, decision_revisions{};
  std::optional<packet::isis::LspId> corrupted_lsp{};
  std::optional<packet::isis::LspView> selected_lsp{};
  std::optional<LspLinkCounts> selected_lsp_links{};
  std::array<std::uint64_t, 2U> decision_runs{};
  // Immutable owner query values; no timer or clock ownership crosses shards.
  std::array<bool, 2U> spf_pending{};
  std::array<std::optional<std::uint32_t>, 2U> selected_cost{};
  std::array<std::size_t, 2U> prefix_advertisements{};
  std::array<std::optional<PrefixDistance>, 2U> selected_prefix_distance{};
  std::array<DecisionStatus, 2U> decision_status{DecisionStatus::invalid, DecisionStatus::invalid};
  // Administrative prepare returns its reserved synchronous publication key;
  // ordinary queries report the actual published and installed high water.
  std::uint64_t route_published_generation{}, route_installed_generation{};
  bool route_withdrawal_pending{};
  ::router::routing::RouteInstallStatus route_install_status{::router::routing::RouteInstallStatus::pending};
  bool sequence_recovery_pending{};
  UpdateStatus update_status{UpdateStatus::inactive};
  LocalContentResult local_content_result{LocalContentResult::missing};
  LevelOriginResult origin{};
  std::uint64_t update_epoch{};
  std::array<std::size_t, 2U> flood_requests{}, snp_requests{};
};

class ControlWorker final {
public:
  // Channels and callbacks outlive this object. A nonzero circuit budget is
  // an emulator admission limit, independent of the configuration ID range.
  // Thread creation failure throws and startup must fail closed.
  ControlWorker(ControlChannels &channels, std::size_t forwarding_shards,
                std::size_t maximum_circuits);
  ~ControlWorker();
  // Serialized control-owner shutdown, never called from this worker. Joins
  // idempotently but retains notification storage until forwarding producers
  // have joined. Later submit rejects without consuming the command value.
  void stop() noexcept;
  ControlWorker(const ControlWorker &) = delete;
  ControlWorker &operator=(const ControlWorker &) = delete;
  // Exactly one serialized control producer. False preserves command values
  // and applies backpressure. No pointer or container crosses a ring.
  [[nodiscard]] bool submit(ControlCommand &&command) noexcept;
  // Exactly one control consumer. Results are immutable value projections.
  [[nodiscard]] bool read(ControlResult &result) noexcept;
  void notify() noexcept;
  // Startup telemetry reads only this release/acquire publication, never the
  // owned circuit registry. Zero means the run loop has not entered yet.
  [[nodiscard]] std::uint64_t thread_id() const noexcept {
    return identity_.load(std::memory_order_acquire);
  }
private:
  struct OwnedInstance {
    UpdateInstanceProgram configuration;
    // The control pthread retains configuration, LSDBs, sequence floors and
    // counters while administratively down. Local lifetime aging continues;
    // origination, SPF, ingress and circuit output require this gate.
    bool admin_enabled{true};
    // The stable shell outlives a disabled process. Reconstruction can release
    // the old databases before allocating fresh storage within the same budget.
    std::unique_ptr<InstanceUpdateProcess> process;
    std::unique_ptr<LocalLspSet> local;
    std::array<std::unique_ptr<P2pRouteDecision>, 2U> decisions;
    std::array<std::uint64_t, 2U> consumed_decision_revision{}, decision_runs{};
    std::array<DecisionStatus, 2U> decision_status{DecisionStatus::invalid, DecisionStatus::invalid};
    struct RouteFamily {
      std::array<std::unique_ptr<P2pRouteDecision>, 2U> decisions;
      std::array<std::uint64_t, 2U> consumed{};
      std::array<DecisionStatus, 2U> status{DecisionStatus::invalid, DecisionStatus::invalid};
      // Exact token-indexed bindings commit only with the complete decision.
      std::array<std::vector<std::optional<AdjacencyNextHop>>, 2U> bindings;
    };
    std::array<RouteFamily, 2U> route_families;
    std::array<std::optional<SpfThrottle>, 2U> spf;
    struct DecisionInput {
      std::vector<P2pSpfSeed> seeds;
      std::vector<LanSpfCircuit> lans;
      std::vector<std::optional<AdjacencyNextHop>> bindings;
    };
    // One control-owned work catalog is reused across levels/families. Bounds
    // cover configured P2P interfaces and every potential LAN adjacency, rather
    // than the requested ECMP width. No borrowed peer view survives preparation.
    DecisionInput decision_input;
    [[nodiscard]] bool level_decisions_pending(std::size_t level) const noexcept {
      if (decisions[level] && consumed_decision_revision[level] != decision_revisions[level]) return true;
      for (const auto &family : route_families)
        if (family.decisions[level] && family.consumed[level] != decision_revisions[level]) return true;
      return false;
    }
    [[nodiscard]] RuntimeClock::time_point decision_deadline(RuntimeClock::time_point now) const noexcept {
      auto due = RuntimeClock::time_point::max();
      for (std::size_t level{}; level < 2U; ++level) if (level_decisions_pending(level))
        due = std::min(due, spf[level] ? spf[level]->deadline().value_or(now) : now);
      return due;
    }
    void reset_spf() {
      for (std::size_t level{}; level < 2U; ++level) {
        spf[level].reset();
        if (configuration.levels[level] && configuration.spf_delay) spf[level].emplace(*configuration.spf_delay);
      }
    }
    struct NeighborProjection { packet::isis::SystemId peer{}; Levels usage{Levels::none}; bool up{}; };
    // Fixed slots follow sorted configured interface IDs. This owner rewrites
    // the projection only while composing dirty roots; it contains no pointers.
    std::vector<NeighborProjection> neighbor_projection;
    // Derived composition buffers, rebuilt cold from the recorded catalog.
    std::unique_ptr<OriginFragmentWorkspace> fragment_workspace;
    // One scratch catalog, owned by this instance control shard. Cold reserve
    // covers its largest configured LAN. Sorting/deduplication never allocates.
    std::vector<packet::isis::SystemId> lan_projection;
    std::array<bool, 2U> local_roots_dirty{true, true};
    std::size_t first_root_level{};
    std::array<std::optional<DatabaseValidation>, 2U> validation;
    std::array<std::uint64_t, 2U> database_validations{}, decision_revisions{};
    std::optional<packet::isis::LspId> corrupted_lsp;
    UpdateStatus status{UpdateStatus::applied};
    std::array<std::uint64_t, 2U> revision{}, expiration_revision{};
    std::array<std::vector<packet::isis::LspId>, 2U> expiration_blocked;
    OwnedInstance(UpdateInstanceProgram program, std::span<const UpdateCircuitConfiguration> circuits,
        std::uint64_t epoch, bool deferred = false)
        : configuration(std::move(program)), process(deferred ? std::unique_ptr<InstanceUpdateProcess>{} : std::make_unique<InstanceUpdateProcess>(
            configuration.local, configuration.maximum_areas, configuration.levels, circuits,
            UpdateInstanceSelector{configuration.format, configuration.wire_instance},
            configuration.maximum_circuits, epoch)) {
      reset_spf();
      const bool routing = std::any_of(configuration.routing.begin(), configuration.routing.end(),
          [](const auto &family) { return family.has_value(); });
      if (configuration.decision || routing) {
        const auto capacity = catalog_budget(*configuration.origination);
        if (!capacity) throw std::invalid_argument("IS-IS adjacency catalog exceeds its explicit token storage");
        decision_input.seeds.reserve(*capacity);
        decision_input.bindings.reserve(*capacity);
        decision_input.lans.reserve(configuration.origination->broadcast_neighbors ?
            configuration.origination->broadcast_neighbors->size() : 0U);
        for (std::size_t family{}; family < configuration.routing.size(); ++family) if (configuration.routing[family])
          for (std::size_t level{}; level < 2U; ++level) if (configuration.levels[level])
            route_families[family].bindings[level].reserve(*capacity);
      }
      if (configuration.decision) for (std::size_t level{}; level < 2U; ++level)
        if (configuration.levels[level]) decisions[level] = std::make_unique<P2pRouteDecision>(
            configuration.decision->nodes, configuration.decision->links, configuration.decision->pending, MetricStyle::wide, configuration.decision->prefixes);
      for (std::size_t family{}; family < configuration.routing.size(); ++family)
        if (configuration.routing[family]) {
          const auto &calculation = configuration.routing[family]->calculation;
          for (std::size_t level{}; level < 2U; ++level) if (configuration.levels[level])
            route_families[family].decisions[level] = std::make_unique<P2pRouteDecision>(
                calculation.nodes, calculation.links, calculation.pending, MetricStyle::wide, calculation.prefixes);
        }
      for (std::size_t level{}; level < 2U; ++level)
        if (configuration.levels[level]) expiration_blocked[level].reserve(configuration.levels[level]->database.records);
      if (configuration.origination) {
        local = std::make_unique<LocalLspSet>(configuration.local, configuration.maximum_areas,
            UpdateInstanceSelector{configuration.format, configuration.wire_instance},
            configuration.origination->content, RuntimeClock::now());
        if (process && !local->reserve_publication(*process)) throw std::invalid_argument("IS-IS fragment transaction capacity refused");
        if (configuration.origination->automatic_roots())
          fragment_workspace = make_fragment_workspace(configuration);
        reset_validation(RuntimeClock::now());
        if (configuration.origination->neighbors)
          neighbor_projection.resize(configuration.origination->neighbors->size());
        if (configuration.origination->broadcast_neighbors) {
          std::size_t maximum{};
          for (const auto &entry : *configuration.origination->broadcast_neighbors)
            if (entry.maximum_neighbors > maximum) maximum = entry.maximum_neighbors;
          lan_projection.reserve(maximum);
        }
      }
    }
    // Cold validated program reconstruction, on this control owner only.
    void reset_validation(RuntimeClock::time_point now) {
      for (std::size_t level{}; level < validation.size(); ++level) {
        validation[level].reset();
        if (!configuration.origination || !configuration.origination->content.levels[level]) continue;
        const auto seed = configuration.origination->content.random ^ ((level + 1U) << 8U);
        validation[level].emplace(configuration.origination->content.levels[level]->refresh_interval,
            seed ? seed : configuration.origination->content.random, now);
      }
    }
    OwnedInstance(OwnedInstance &&) = delete;
    OwnedInstance &operator=(OwnedInstance &&) = delete;
    [[nodiscard]] LevelObserver observer() noexcept { return {this, level_event}; }
    static void level_event(void *context, const LevelEvent &event) noexcept;
  };
  struct UpdateEgress {
    struct Retry {
      packet::isis::LspView header;
      std::size_t level{};
      RuntimeClock::time_point at{};
    };
    // Same protocol producer owns all deadlines and bounded retry metadata.
    // Credits cover both levels on this interface; port receipts alone anchor
    // retransmission. No frame, key, LSDB reference or cross-shard clock lives here.
    UpdateEgress(const OwnedInstance &instance, std::uint64_t seed,
        const std::optional<UpdateTransmissionProgram> &override_program = {});
    UpdateTransmissionProgram program;
    std::vector<Retry> retries;
    std::array<std::uint64_t, 2U> epochs{};
    std::array<RuntimeClock::time_point, 2U> partial{}, complete{}, complete_periodic{};
    std::array<bool, 2U> complete_started{}, transient_first{};
    std::array<std::size_t, 2U> scan{}, remaining{};
    std::array<std::uint64_t, 2U> revision{};
    std::array<RuntimeClock::time_point, 2U> lsp{}, earliest{};
    RuntimeClock::time_point pacing{};
    std::size_t credits{};
    std::uint64_t random{};
    struct LanReservation { std::size_t level{}; std::uint64_t epoch{}, ticket{}; };
    // One interface scan and receipt fence cover both levels. Physical success
    // alone commits backlog spacing; selected-level cancellation releases it.
    std::optional<BroadcastScan> broadcast_scan;
    bool lan_active{};
    std::optional<LanReservation> lan_lsp, lan_csnp;
    RuntimeClock::time_point csnp_ready{};
    std::array<bool, 2U> designated{};
    bool synchronize{true};
  };
  struct OwnedCircuit {
    CircuitIdentity identity;
    // Solely the control pthread mutates this local transport gate. Recovery
    // may restart protocol state only while the physical carrier remains up.
    bool carrier{true};
    std::uint16_t wire_instance{};
    CircuitDestinations destinations;
    std::optional<UpdateTransmissionProgram> update_transmission;
    packet::isis::InstanceFormat format{};
    bool physical_point_to_point{};
    using Medium = std::variant<PointToPointCircuit, LanCircuitPair>;
    Medium circuit;
    protocol::TransmissionWindow transmission;
    std::array<protocol::TransmissionWindow, 2U> lan_transmissions;
    CircuitCounters counters;
    OwnedInstance *update{};
    std::size_t update_slot{};
    bool rebind_update{};
    bool queued_lsp{};
    // This circuit control owner remembers the last remote DIS across an empty
    // neighbor set. One bounded fragment cursor per level runs only while local
    // DIS; role loss cancels work before a newly legitimate remote incarnation.
    struct PreviousDis {
      std::optional<packet::isis::LanId> remote;
      std::uint16_t fragment{256U};
      RuntimeClock::time_point retry{};
    };
    std::array<PreviousDis, 2U> previous_dis;
    std::unique_ptr<UpdateEgress> update_egress;
    // Sorted accepted MAC scratch belongs to this control owner. Each level
    // reserves its configured neighbor bound cold; callbacks never allocate.
    std::array<std::vector<packet::Mac>, 2U> update_peers;
    std::uint64_t random_state{};
    [[nodiscard]] CircuitUpdateView update_view() const noexcept {
      if (const auto *broadcast = lan()) {
        const auto &first = broadcast->common();
        std::size_t capacity{};
        for (std::size_t level{}; level < 2U; ++level)
          if (const auto *entry = broadcast->at(level); entry && entry->configuration().limits.neighbors > capacity)
            capacity = entry->configuration().limits.neighbors;
        return {first, first.local.system, broadcast->levels(), false, true, first.local.circuit, capacity};
      }
      const auto &value = p2p().configuration();
      return {value, value.local.system, value.local.levels, value.physical_point_to_point,
          false, value.local.extended_circuit, 0U};
    }
    [[nodiscard]] static const CircuitHelloConfiguration &common(ControlCommand &command) {
      const auto *value = circuit_hello_configuration(command.configuration, command.broadcast);
      if (!value || (command.broadcast && command.configuration != P2pCircuitConfiguration{}))
        throw std::invalid_argument("Invalid IS-IS circuit medium program");
      return *value;
    }
    [[nodiscard]] static Medium make(ControlCommand &command, RuntimeClock::time_point now) {
      if (command.broadcast)
        return Medium{std::in_place_type<LanCircuitPair>, std::move(*command.broadcast), command.random_state, now};
      return Medium{std::in_place_type<PointToPointCircuit>, std::move(command.configuration), command.random_state, now};
    }
    // Same owner. P2P access requires the selected medium to be P2P; cold
    // update admission rejects broadcast before any P2P-only operation.
    [[nodiscard]] PointToPointCircuit &p2p() { return std::get<PointToPointCircuit>(circuit); }
    [[nodiscard]] const PointToPointCircuit &p2p() const { return std::get<PointToPointCircuit>(circuit); }
    [[nodiscard]] LanCircuitPair *lan() noexcept { return std::get_if<LanCircuitPair>(&circuit); }
    [[nodiscard]] const LanCircuitPair *lan() const noexcept { return std::get_if<LanCircuitPair>(&circuit); }
    [[nodiscard]] const CircuitHelloConfiguration &common() const noexcept {
      if (const auto *broadcast = lan()) return broadcast->common();
      return p2p().configuration();
    }
    [[nodiscard]] bool matches(const CircuitDefinition &definition) const noexcept {
      if (update_transmission != definition.update_transmission) return false;
      if (carrier != definition.carrier) return false;
      if (const auto *broadcast = lan())
        return definition.broadcast && definition.configuration == P2pCircuitConfiguration{} && broadcast->matches(*definition.broadcast);
      return !definition.broadcast && p2p().configuration() == definition.configuration;
    }
    OwnedCircuit(ControlCommand &command, PointToPointCircuit::Clock::time_point now,
        std::optional<Medium> restored = {})
        : identity(command.identity),
          carrier(command.carrier),
          wire_instance(common(command).wire_instance),
          destinations(common(command).destinations()),
          update_transmission(command.update_transmission),
          format(common(command).instance_format.value_or(packet::isis::InstanceFormat::standard)),
          physical_point_to_point(!command.broadcast && command.configuration.physical_point_to_point),
          circuit(restored ? std::move(*restored) : make(command, now)),
          transmission(command.identity.configuration_generation),
          lan_transmissions{protocol::TransmissionWindow(command.identity.configuration_generation),
              protocol::TransmissionWindow(command.identity.configuration_generation)}, random_state(command.random_state) {
      if (const auto *broadcast = lan()) for (std::size_t level{}; level < 2U; ++level)
        if (const auto *entry = broadcast->at(level)) update_peers[level].reserve(entry->configuration().limits.neighbors);
      if (!carrier && !restored) circuit_down(*this);
    }
  };
  struct RouteStamp {
    std::uint64_t epoch{};
    std::array<std::uint64_t, 2U> decision{};
    UpdateStatus status{UpdateStatus::inactive};
    std::uint8_t families{};
    bool operator==(const RouteStamp &) const = default;
  };
  using RouteStamps = std::array<RouteStamp, device_catalog::isis_instance_last + 1U>;
  struct DeviceState {
    lab::DeviceHandle handle{};
    bool active{};
    // Sole control-owner high-water mark, retained while the same router
    // handle is unregistered. New logical circuits must exceed every retired
    // epoch; unchanged live circuits retain their independent older epochs.
    std::uint64_t retired_epoch_floor{};
    std::vector<OwnedCircuit> circuits;
    // Heap-stable instance owners survive circuit-vector moves. Fences belong
    // to the device scope and survive protocol removal for this same handle.
    std::array<std::unique_ptr<OwnedInstance>, device_catalog::isis_instance_last + 1U> instances;
    std::array<std::uint64_t, device_catalog::isis_instance_last + 1U> update_fences{};
    // This control owner retains disabled-entity gates after instance deletion.
    // Only a different physical DeviceHandle clears a pending cooldown early.
    // Cold allocation is per configured originator, not per possible instance.
    std::array<std::unique_ptr<SequenceRecovery>, device_catalog::isis_instance_last + 1U> sequence_recovery;
    // Same control owner maintains this dense iteration projection. Every live
    // key appears once; capacity is the configuration ID range, not admission.
    std::array<std::uint8_t, device_catalog::isis_instance_last + 1U> instance_order{};
    std::size_t instance_count{}, first_instance{};
    std::size_t first_circuit{};
    // This protocol owner keeps publication high water across unregistering
    // the same physical handle. Pending snapshots own exact revision values;
    // no hash or pointer substitutes for a freshness fence.
    RouteStamps installed_routes{}, pending_routes{};
    std::uint64_t route_generation{}, route_installed{}, route_pending{};
    ::router::routing::RouteInstallStatus route_status{::router::routing::RouteInstallStatus::pending};
    RuntimeClock::time_point route_retry_at{};
    std::chrono::milliseconds route_retry{};

  };
  struct PreparedGeneration {
    PreparedGeneration() = default;
    PreparedGeneration(PreparedGeneration &&) noexcept = default;
    PreparedGeneration(const PreparedGeneration &) = delete;
    ~PreparedGeneration();
    // Declared before dependents so candidate instances outlive circuit and
    // reservation destruction on both cancellation and successful commit.
    std::unique_ptr<DeviceState> additions;
    std::vector<std::uint8_t> retired_instances;
    std::vector<UpdateAdminState> administrative;
    std::vector<UpdateAdjacencyPolicy> adjacency_policies;
    std::vector<UpdatePrefixCatalog> prefix_catalogs;
    std::vector<std::unique_ptr<OriginFragmentWorkspace>> prefix_workspaces;
    std::uint64_t route_commit_generation{};
    struct UpdateReservation { OwnedInstance *instance{}; UpdateCircuitAdmission admission; };
    std::vector<UpdateReservation> update_reservations;
    bool committed{};
    lab::DeviceHandle device{};
    struct Selection { std::size_t index{}; bool retained{}; };
    std::vector<OwnedCircuit> replacements;
    std::vector<OwnedCircuit> output;
    std::vector<Selection> plan;
    std::vector<std::uint8_t> keep;
  };
  [[nodiscard]] ControlError prepare_generation(ControlCommand &command, DeviceState &device) noexcept;
  void commit_generation(DeviceState &device) noexcept;
  void set_admin_state(DeviceState &device, OwnedInstance &instance, bool enabled) noexcept;
  static void retire_circuit(DeviceState &device, OwnedCircuit &circuit) noexcept;
  [[nodiscard]] ControlError add_update_instance(ControlCommand &command, DeviceState &device,
      const OwnedInstance *sequence_source = nullptr) noexcept;
  [[nodiscard]] static ControlError attach_update_circuit(DeviceState &device, OwnedCircuit &circuit) noexcept;
  static void remove_update_instance(DeviceState &device, std::size_t instance) noexcept;
  static UpdateCircuitConfiguration update_configuration(const OwnedCircuit &circuit) noexcept;
  [[nodiscard]] static bool matches_update_instance(const UpdateInstanceProgram &instance,
      CircuitUpdateView circuit, std::uint64_t interface_id) noexcept;
  [[nodiscard]] RuntimeClock::time_point service_update_lifetimes(OwnedInstance &instance,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
  // Cold validation shares normal admission policy and prepares automatic
  // identities in the caller-owned program. Failure publishes no live state.
  [[nodiscard]] ControlError validate_update_program(UpdateInstanceProgram &program) const noexcept;
  [[nodiscard]] static std::unique_ptr<OriginFragmentWorkspace> make_fragment_workspace(const UpdateInstanceProgram &program);
  [[nodiscard]] static ControlError prepare_fragment_origination(UpdateInstanceProgram &program) noexcept;
  [[nodiscard]] static ControlError prepare_neighbor_origination(UpdateInstanceProgram &program) noexcept;
  [[nodiscard]] static ControlError prepare_lan_origination(UpdateInstanceProgram &program) noexcept;
  [[nodiscard]] bool compose_lan_pseudonodes(OwnedInstance &instance, const DeviceState &device,
      std::size_t index, std::size_t level, LocalLspSet &target, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] static bool append_lan_links(const OwnedInstance &instance, const DeviceState &device,
      std::size_t index, std::size_t level, OriginFragmentWorkspace &workspace, const LocalLspSet &target) noexcept;
  [[nodiscard]] bool compose_local_neighbors(OwnedInstance &instance, const DeviceState &device,
      std::size_t index, LocalLspSet &target, RuntimeClock::time_point now, std::size_t &budget) noexcept;
  [[nodiscard]] static std::optional<std::size_t> catalog_budget(const LocalOriginProgram &origin) noexcept;
  [[nodiscard]] static DecisionStatus prepare_decision_input(OwnedInstance &instance, const DeviceState &device,
      std::size_t index, std::size_t level, std::optional<std::uint8_t> protocol) noexcept;
  void service_p2p_decision(OwnedInstance &instance, const DeviceState &device, std::size_t index,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
  [[nodiscard]] ControlError edit_local_content(ControlCommand &command, OwnedInstance &instance,
      ControlResult &result) noexcept;
  [[nodiscard]] static ControlError query_adjacencies(const DeviceState &,
      AdjacencyQuery &) noexcept;
  [[nodiscard]] RuntimeClock::time_point stop_local_instance(DeviceState &device, std::size_t index,
      UpdateStatus reason) noexcept;
  [[nodiscard]] RuntimeClock::time_point service_local_instance(DeviceState &device, std::size_t index,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
  [[nodiscard]] RuntimeClock::time_point rebuild_local_instance(DeviceState &device, std::size_t index,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool handle_self_lsp(OwnedCircuit &owned, const packet::isis::PduView &pdu,
      const packet::Frame &frame, UpdateReceiveResult &received, RuntimeClock::time_point now) noexcept;
  void handle_confusion(OwnedCircuit &owned, const packet::isis::PduView &pdu,
      UpdateReceiveResult &received, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] RuntimeClock::time_point emit_updates(OwnedCircuit &circuit,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
  [[nodiscard]] bool complete_update(OwnedCircuit &circuit,
      const protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>::Completion &receipt,
      const packet::isis::PduView &pdu, RuntimeClock::time_point now) noexcept;
  struct LanObserverContext { OwnedCircuit &circuit; std::size_t level; };
  static void event(void *context, const P2pCircuitEvent &event) noexcept;
  static void lan_peer(void *context, const LanPeerEvent &event) noexcept;
  static void lan_designated(void *context, const std::optional<DisSelection> &before,
      const std::optional<DisSelection> &after) noexcept;
  [[nodiscard]] static LanCircuitObserver lan_observer(LanObserverContext &context) noexcept;
  [[nodiscard]] static UpdateStatus project_lan(OwnedCircuit &circuit, OwnedInstance &instance,
      std::size_t slot, std::size_t level) noexcept;
  [[nodiscard]] RuntimeClock::time_point service_previous_pseudonodes(OwnedCircuit &circuit,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
  static void synchronize_lan(OwnedCircuit &circuit, std::size_t level) noexcept;
  [[nodiscard]] static ControlError set_strict_policy(DeviceState &device, std::uint8_t instance, bool enabled) noexcept;
  static void circuit_down(OwnedCircuit &owned) noexcept;
  static void circuit_up(OwnedCircuit &owned, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] static bool valid_transmission(const UpdateTransmissionProgram &program) noexcept;
  [[nodiscard]] static bool valid_medium_transmission(const UpdateTransmissionProgram &program,
      CircuitUpdateView circuit) noexcept;
  void classify_lan_backlog() noexcept;
  [[nodiscard]] RuntimeClock::time_point emit_broadcast_lsp(OwnedCircuit &circuit,
      RuntimeClock::time_point now, std::size_t &budget, std::size_t maximum_pdu) noexcept;
  [[nodiscard]] RuntimeClock::time_point service_lan(OwnedCircuit &circuit,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
  [[nodiscard]] ControlResult apply(ControlCommand &command) noexcept;
  void receive(const protocol::PacketChannel<device_catalog::isis_packet_ring_frames>::Borrowed &packet,
      PointToPointCircuit::Clock::time_point now) noexcept;
  [[nodiscard]] RuntimeClock::time_point service_routes(DeviceState &device,
      RuntimeClock::time_point now) noexcept;
  void complete_routes(RuntimeClock::time_point now) noexcept;
  // Protocol owner only with an acknowledged persistence barrier. Caller owns
  // the destination until the synchronous operation completes. Capture stages
  // every owned value before replacing the destination and can throw allocation,
  // clock-range or invariant errors. No protocol/transport state is consumed.
  [[nodiscard]] ControlWorkerCheckpoint capture_checkpoint(RuntimeClock::time_point now) const;
  // Cold candidate construction only. Normal admission policy and child image
  // validation precede publication; null refuses without touching live owners.
  [[nodiscard]] std::unique_ptr<OwnedInstance> restore_checkpoint_instance(const ControlInstanceCheckpoint &saved,
      RuntimeClock::time_point now) const noexcept;
  // Detached circuit construction rebinds only to candidate instance owners.
  // No live transport is consumed and refusal destroys the entire candidate.
  [[nodiscard]] std::unique_ptr<OwnedCircuit> restore_checkpoint_circuit(const ControlCircuitCheckpoint &saved,
      DeviceState &device, RuntimeClock::time_point now) const noexcept;
  struct PreparedCheckpoint {
    std::array<DeviceState, device_catalog::maximum_routers> devices;
    std::size_t active_circuits{}, first_device{};
    std::uint64_t source_epoch{};
  };
  // All allocation and validation complete before a candidate becomes visible.
  // Commit only swaps owned registries under the unchanged transport barrier.
  [[nodiscard]] std::unique_ptr<PreparedCheckpoint> prepare_checkpoint_restore(
      const ControlWorkerCheckpoint &saved, std::uint64_t source_epoch, RuntimeClock::time_point now) const noexcept;
  std::unique_ptr<PreparedCheckpoint> checkpoint_restore_;
  void run() noexcept;
  ControlChannels &channels_;
  std::size_t forwarding_shards_{};
  std::size_t maximum_circuits_{};
  std::size_t active_circuits_{};
  std::size_t first_device_{};
  // This protocol pthread alone owns the monotonic barrier high water and
  // current token. While active, only barrier release, worker status and shutdown
  // run; protocol timers, channels and route publication remain untouched.
  std::uint64_t checkpoint_barrier_counter_{}, checkpoint_barrier_epoch_{};
  RuntimeClock::time_point checkpoint_barrier_started_{};
  std::array<DeviceState, device_catalog::maximum_routers> devices_;
  std::optional<PreparedGeneration> prepared_;
  protocol::OwnedSpscChannel<ControlCommand, device_catalog::isis_control_generation_slots> commands_;
  // Producer is this pthread, consumer is serialized control. Full retains one
  // pending result and stops command admission on this owner; packet work and
  // holding timers continue. No applied result is discarded.
  SpscRing<ControlResult, device_catalog::network_result_ring_entries> results_;
  PduScratch scratch_;
  packet::Frame output_;
  std::mutex wait_mutex_;
  std::condition_variable wait_condition_;
  std::atomic_bool stop_{};
  std::atomic_bool work_{};
  std::atomic_uint64_t identity_{};
  // Last member: no worker may observe unconstructed queues or wait state.
  std::thread thread_;
};

} // namespace router::isis
