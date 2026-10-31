// Dedicated IS-IS control owner. Serialized control publishes owned generation
// values; forwarding shards exchange encoded frames through independent SPSC
// pairs. All circuit state remains exclusively on this pthread.

#pragma once

#include "router/isis_instance_update.hpp"
#include "router/isis_local_lsp_set.hpp"
#include "router/isis_database_validation.hpp"
#include "router/isis_sequence_recovery.hpp"
#include "router/owned_spsc_channel.hpp"
#include "router/protocol_packet_channel.hpp"
#include "router/protocol_transmission.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace router::isis {

struct ControlChannels {
  // One forwarding producer and this control consumer per ingress pair. Roles
  // reverse for egress; its receipt returns actual port-queue admission.
  // Capacity and FIFO release/acquire semantics belong to PacketChannel.
  std::array<protocol::PacketChannel<device_catalog::isis_packet_ring_frames>,
             device_catalog::high_forwarding_shards> ingress;
  std::array<protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>,
             device_catalog::high_forwarding_shards> egress;
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
  query_sequence_recovery
};
struct CircuitDefinition {
  CircuitIdentity identity;
  P2pCircuitConfiguration configuration;
  std::uint64_t random_state{};
};
// Effective values, not product defaults. Positive PSNP/retry seconds, pacing
// period and transit decrement are mandatory. Zero complete_seconds selects
// ISO startup-only CSNP; zero pacing_burst blocks LSP output while SNPs continue.
// The configuration owner resolves per-interface SR OS burst policy beforehand.
struct UpdateTransmissionProgram {
  std::uint16_t partial_seconds{}, retransmit_seconds{}, complete_seconds{};
  std::chrono::milliseconds pacing_period{};
  std::size_t pacing_burst{};
  std::uint16_t maximum_pdu_octets{}, transit_seconds{};
};
struct LocalOriginProgram {
  LocalLspProgram content;
  // Emulator allocation recovery policy, supplied explicitly by its owner.
  std::chrono::milliseconds resource_retry{};
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
};
struct ControlCommand {
  std::uint64_t id{};
  ControlCommandKind kind{ControlCommandKind::query_worker};
  CircuitIdentity identity;
  P2pCircuitConfiguration configuration;
  std::uint64_t random_state{};
  // Complete router generation, sorted by interface ID then local instance.
  // OwnedSpscChannel transfers these values without copying containers into a
  // ring. Prepare allocates before publication; commit preserves unchanged
  // epochs and consumes no heap storage. Abort leaves every live circuit intact.
  std::vector<CircuitDefinition> circuits;
  // Experimental update admission supplies all effective values and budgets.
  // Raw local PDUs already passed the originator's sequence and key policy.
  std::optional<UpdateInstanceProgram> update;
  std::vector<std::uint8_t> local_lsp;
  std::uint8_t level{};
  // Read-only selected-LSP projection; no retained packet view crosses owners.
  std::optional<packet::isis::LspId> selected_lsp{};
  OriginPurgeReason purge{OriginPurgeReason::none};
};
enum class ControlError : std::uint8_t {
  none, invalid_argument, stale_device, stale_configuration, not_found,
  already_exists, capacity, unsupported_authentication, construction_failed,
  generation_pending, epoch_exhausted, update_refused, unsupported_update_instance, sequence_cooldown,
  unsupported_origination
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
  std::uint64_t lsp_too_large{}, purge_pending{};
};
struct ControlResult {
  std::uint64_t id{};
  ControlError error{ControlError::none};
  P2pSnapshot adjacency{};
  CircuitCounters counters{};
  std::uint64_t thread_identity{};
  std::int64_t holding_deadline_nanoseconds{};
  std::uint32_t active_circuits{};
  bool hello_pending{};
  std::array<std::size_t, 2U> retained_lsps{}, retained_purges{};
  std::array<std::uint32_t, 2U> local_root_sequences{};
  std::array<std::uint64_t, 2U> database_validations{}, decision_revisions{};
  std::optional<packet::isis::LspId> corrupted_lsp{};
  std::optional<packet::isis::LspView> selected_lsp{};
  bool sequence_recovery_pending{};
  UpdateStatus update_status{UpdateStatus::inactive};
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
    // The stable shell outlives a disabled process. Reconstruction can release
    // the old databases before allocating fresh storage within the same budget.
    std::unique_ptr<InstanceUpdateProcess> process;
    std::unique_ptr<LocalLspSet> local;
    std::array<std::optional<DatabaseValidation>, 2U> validation;
    std::array<std::uint64_t, 2U> database_validations{}, decision_revisions{};
    std::optional<packet::isis::LspId> corrupted_lsp;
    UpdateStatus status{UpdateStatus::applied};
    std::array<std::uint64_t, 2U> revision{}, expiration_revision{};
    std::array<std::vector<packet::isis::LspId>, 2U> expiration_blocked;
    OwnedInstance(UpdateInstanceProgram program, std::span<const UpdateCircuitConfiguration> circuits,
        std::uint64_t epoch)
        : configuration(std::move(program)), process(std::make_unique<InstanceUpdateProcess>(
            configuration.local, configuration.maximum_areas, configuration.levels, circuits,
            UpdateInstanceSelector{configuration.format, configuration.wire_instance},
            configuration.maximum_circuits, epoch)) {
      for (std::size_t level{}; level < 2U; ++level)
        if (configuration.levels[level]) expiration_blocked[level].reserve(configuration.levels[level]->database.records);
      if (configuration.origination) {
        local = std::make_unique<LocalLspSet>(configuration.local, configuration.maximum_areas,
            UpdateInstanceSelector{configuration.format, configuration.wire_instance},
            configuration.origination->content, RuntimeClock::now());
        reset_validation(RuntimeClock::now());
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
    UpdateEgress(const OwnedInstance &instance, std::uint64_t seed);
    std::vector<Retry> retries;
    std::array<std::uint64_t, 2U> epochs{};
    std::array<RuntimeClock::time_point, 2U> partial{}, complete{};
    std::array<bool, 2U> complete_started{}, transient_first{};
    std::array<std::size_t, 2U> scan{}, remaining{};
    std::array<std::uint64_t, 2U> revision{};
    std::array<RuntimeClock::time_point, 2U> lsp{}, earliest{};
    RuntimeClock::time_point pacing{};
    std::size_t credits{};
    std::uint64_t random{};
    bool synchronize{true};
  };
  struct OwnedCircuit {
    CircuitIdentity identity;
    std::uint16_t wire_instance{};
    packet::Mac destination{};
    packet::isis::InstanceFormat format{};
    bool physical_point_to_point{};
    PointToPointCircuit circuit;
    protocol::TransmissionWindow transmission;
    CircuitCounters counters;
    OwnedInstance *update{};
    std::size_t update_slot{};
    bool rebind_update{};
    std::unique_ptr<UpdateEgress> update_egress;
    std::uint64_t random_state{};
    OwnedCircuit(ControlCommand &command, PointToPointCircuit::Clock::time_point now)
        : identity(command.identity),
          wire_instance(command.configuration.wire_instance),
          destination(command.configuration.hello_destination),
          format(command.configuration.instance_format.value_or(packet::isis::InstanceFormat::standard)),
          physical_point_to_point(command.configuration.physical_point_to_point),
          circuit(std::move(command.configuration), command.random_state, now),
          transmission(command.identity.configuration_generation), random_state(command.random_state) {}
  };
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
  };
  struct PreparedGeneration {
    PreparedGeneration() = default;
    PreparedGeneration(PreparedGeneration &&) noexcept = default;
    PreparedGeneration(const PreparedGeneration &) = delete;
    ~PreparedGeneration();
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
  static void retire_circuit(DeviceState &device, OwnedCircuit &circuit) noexcept;
  [[nodiscard]] ControlError add_update_instance(ControlCommand &command, DeviceState &device) noexcept;
  [[nodiscard]] static ControlError attach_update_circuit(DeviceState &device, OwnedCircuit &circuit) noexcept;
  static void remove_update_instance(DeviceState &device, std::size_t instance) noexcept;
  static UpdateCircuitConfiguration update_configuration(const OwnedCircuit &circuit) noexcept;
  [[nodiscard]] static bool matches_update_instance(const UpdateInstanceProgram &instance,
      const P2pCircuitConfiguration &circuit) noexcept;
  [[nodiscard]] RuntimeClock::time_point service_update_lifetimes(OwnedInstance &instance,
      RuntimeClock::time_point now, std::size_t &budget) noexcept;
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
  static void event(void *context, const P2pCircuitEvent &event) noexcept;
  [[nodiscard]] ControlResult apply(ControlCommand &command) noexcept;
  void receive(const protocol::PacketChannel<device_catalog::isis_packet_ring_frames>::Borrowed &packet,
      PointToPointCircuit::Clock::time_point now) noexcept;
  void run() noexcept;
  ControlChannels &channels_;
  std::size_t forwarding_shards_{};
  std::size_t maximum_circuits_{};
  std::size_t active_circuits_{};
  std::size_t first_device_{};
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
