// Dedicated OSPF control-plane pthread. The worker is the sole owner of every
// InstanceProcess. Serialized control is the sole command producer, each
// forwarding shard is the sole producer of its ingress PacketChannel, and the
// worker is the sole producer of every reverse egress channel.

#pragma once

#include "router/ospf_packet_channel.hpp"
#include "router/ospf_area_coordinator.hpp"
#include "router/ospf_process.hpp"
#include "router/ospf_route_channel.hpp"
#include "router/spsc_ring.hpp"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <memory>
#include <optional>
#include <span>
#include <thread>
#include <vector>

namespace router::ospf {

using ProtocolPacketChannel =
    PacketChannel<device_catalog::ospf_packet_ring_frames>;

struct ControlChannels {
  // Pair index is the physical forwarding-shard index. Every pair is SPSC and
  // preserves FIFO ordering independently. A full ingress channel drops the
  // received protocol packet; a full egress channel backpressures process
  // execution until forwarding releases a slot.
  std::array<ProtocolPacketChannel,
             device_catalog::high_forwarding_shards>
      ingress;
  std::array<ProtocolPacketChannel,
             device_catalog::high_forwarding_shards>
      egress;
  // Producer: sole OSPF control pthread. Consumer: sole network/link owner.
  // The packet handle and frame bytes are release-published to the selected
  // egress SPSC ring before this callback runs. The callback carries no
  // network information and cannot bypass the ring, port, queue or link; it
  // only closes the condition-variable notify-before-wait race so a periodic
  // Hello or retransmission is drained at its real monotonic deadline.
  void *egress_wakeup_context{};
  void (*egress_wakeup)(void *){};
  // Producer: sole OSPF control pthread. Consumer: sole network/link owner.
  // A generation contains every OSPF and OSPF3 route candidate for one router;
  // the route manager never observes a partially copied SPF result.
  // Large fixed route arrays live in one heap allocation owned by the channel
  // aggregate. Keeping only the stable pointer in NetworkPlane metadata avoids
  // charging protocol route capacity to every fixed shard object while the
  // pointee still outlives producer and consumer pthreads.
  std::unique_ptr<RouteChannel> routes{std::make_unique<RouteChannel>()};
  // NetworkPlane installs this callback before the OSPF pthread is created.
  // Route publication invokes it after the release-published handle enters
  // the ring, so a sleeping route manager cannot miss an empty withdrawal.
  void *route_wakeup_context{};
  void (*route_wakeup)(void *){};
};

enum class ControlCommandKind : std::uint8_t {
  add_process,
  remove_process,
  add_interface,
  add_nbma_neighbor,
  remove_interface,
  begin_generation,
  stage_process,
  stage_interface,
  stage_authentication,
  stage_nbma_neighbor,
  stage_virtual_link,
  stage_range,
  stage_external_route,
  commit_generation,
  abort_generation,
  begin_external_generation,
  commit_external_generation,
  abort_external_generation,
  query_process,
  query_interface,
  query_neighbor,
  query_lsa,
  reset_neighbors,
  reset_database,
  checkpoint,
  restore_checkpoint,
  shutdown
};

struct ProcessIdentity {
  lab::DeviceHandle device{};
  std::uint32_t area_id{};
  std::uint8_t version{};
  std::uint8_t instance_id{};
  bool operator==(const ProcessIdentity &) const = default;
};

struct ControlCommand {
  ProcessInterfaceConfiguration interface{};
  ProcessNbmaNeighborConfiguration nbma_neighbor{};
  ProcessVirtualLinkConfiguration virtual_link{};
  ProcessAuthentication authentication{};
  AreaRangeConfiguration range{};
  CoordinatorAdvertisement external_route{};
  ProcessIdentity process{};
  std::uint64_t id{};
  // Checkpoint transfer is an internal synchronous rendezvous. The producer
  // owns the pointed value and waits for this exact command result before its
  // lifetime can end. No pointer is persisted or published to another queue.
  std::uintptr_t checkpoint_transfer{};
  std::int64_t operation_now_nanoseconds{};
  std::uint32_t router_id{};
  std::uint32_t initial_dd_sequence{};
  std::uint32_t maximum_interfaces{};
  std::uint32_t default_metric{};
  std::uint32_t interface_id{};
  std::uint32_t router_preference{};
  std::uint32_t external_preference{};
  std::uint32_t spf_initial_wait_milliseconds{};
  std::uint32_t spf_second_wait_milliseconds{};
  std::uint32_t spf_maximum_wait_milliseconds{};
  std::uint32_t lsa_initial_wait_milliseconds{};
  std::uint32_t lsa_second_wait_milliseconds{};
  std::uint32_t lsa_maximum_wait_milliseconds{};
  // Begin declares the exact shape of a device generation before any child
  // arrives. These are emulator transaction sizes obtained from the canonical
  // configuration, not OSPF protocol limits or vendor scale claims.
  std::uint32_t expected_processes{};
  std::uint32_t expected_interfaces{};
  std::uint32_t expected_authentications{};
  std::uint32_t expected_nbma_neighbors{};
  std::uint32_t expected_virtual_links{};
  std::uint32_t expected_ranges{};
  std::uint32_t expected_external_routes{};
  // Operational queries use stable ordinals only for the duration of this
  // synchronous owner turn. They are never persisted or exposed as protocol
  // identities, and a later query starts again from the current generation.
  std::uint32_t process_ordinal{};
  std::uint32_t interface_ordinal{};
  std::uint32_t row_ordinal{};
  std::uint32_t neighbor_router_id{};
  AreaType area_type{AreaType::normal};
  ControlCommandKind kind{ControlCommandKind::add_process};
  bool summaries{true};
  bool nssa_translate_always{};
  bool asbr{};
  bool graceful_restart_helper{};
  bool loopfree_alternates{};
  bool overload{};
  bool authentication_receive{true};
  bool authentication_send{};
};

struct ControlResult {
  std::uint64_t id{};
  ProcessIdentity process{};
  ProcessInterfaceSnapshot interface{};
  ProcessNeighborSnapshot neighbor{};
  packet::ospf::LsaHeaderView lsa{};
  std::uint64_t route_generation{};
  std::uint32_t router_id{};
  std::uint32_t process_count{};
  std::uint32_t interface_count{};
  std::uint32_t lsa_count{};
  std::uint32_t route_count{};
  std::uint32_t reset_count{};
  std::uint16_t effective_lsa_age{};
  RouteRecalculationStatus route_status{
      RouteRecalculationStatus::never_run};
  RunReadyStatus run_status{RunReadyStatus::succeeded};
  LocalOriginationStatus origination_status{
      LocalOriginationStatus::succeeded};
  bool present{};
  bool success{};
};

static_assert(std::is_trivially_copyable_v<ControlCommand>);
static_assert(std::is_trivially_copyable_v<ControlResult>);

struct OwnedProcessCheckpoint {
  ControlCommand definition{};
  InstanceProcessCheckpoint process;
  std::vector<AreaRangeConfiguration> ranges;
  std::vector<ProcessVirtualLinkConfiguration> virtual_links;
  std::vector<ControlCommand> authentications;
  std::vector<CoordinatorAdvertisement> external_routes;
  std::uint64_t published_route_generation{};
  std::uint64_t coordinated_route_generation{};
};

struct ControlWorkerCheckpoint {
  std::vector<OwnedProcessCheckpoint> processes;
  std::array<std::uint64_t, device_catalog::maximum_routers>
      next_route_generation{};
  std::array<lab::DeviceHandle, device_catalog::maximum_routers>
      active_devices{};
  std::array<bool, device_catalog::maximum_routers>
      route_publication_pending{};
  std::array<bool, device_catalog::maximum_routers>
      route_coordination_pending{};
};

class ControlWorker final {
public:
  explicit ControlWorker(ControlChannels &channels,
                         std::size_t forwarding_shards);
  ~ControlWorker();
  ControlWorker(const ControlWorker &) = delete;
  ControlWorker &operator=(const ControlWorker &) = delete;

  [[nodiscard]] bool submit(const ControlCommand &command) noexcept;
  [[nodiscard]] bool read(ControlResult &result) noexcept;
  // A forwarding producer calls notify only after release-publishing a packet
  // handle. The condition variable controls sleep, while SPSC acquire/release
  // remains the sole memory guarantee for packet bytes.
  void notify() noexcept;
  [[nodiscard]] std::uint64_t thread_id() const noexcept {
    return thread_id_.load(std::memory_order_acquire);
  }

private:
  struct OwnedProcess {
    ProcessIdentity identity{};
    // Retaining the immutable construction command makes checkpoint restore
    // recreate exactly the same release-profile limits and throttle values.
    // Authentication commands are stored separately and scrubbed on teardown.
    ControlCommand definition{};
    InstanceProcess process;
    // Area policy is immutable for one published configuration generation.
    // The ABR coordinator reads it only on this same pthread, so no borrowed
    // configuration pointer or cross-thread mutable state is introduced.
    AreaType area_type{AreaType::normal};
    std::uint32_t default_metric{};
    std::uint32_t router_preference{};
    std::uint32_t external_preference{};
    bool summaries{true};
    bool nssa_translate_always{};
    bool asbr{};
    bool graceful_restart_helper{};
    bool loopfree_alternates{};
    bool overload{};
    std::vector<AreaRangeConfiguration> ranges;
    // Virtual-link definitions belong to the backbone process. Their live
    // interface transport is resolved from the separate transit-area process
    // during coordination and is never persisted in this vector.
    std::vector<ProcessVirtualLinkConfiguration> virtual_links;
    // Virtual interfaces are materialized only after transit-area SPF can
    // resolve their routed endpoints. Retaining their authentication programs
    // on this same owner lets the newly materialized interface become
    // protected atomically, without reopening the management secret vault.
    std::vector<ControlCommand> authentications;
    // These advertisements already passed the router-owned export policy.
    // Only this protocol pthread mutates the vector or turns its values into
    // LSAs, preserving one owner for sequence and withdrawal state.
    std::vector<CoordinatorAdvertisement> external_routes;
    // Updated only after the aggregate device generation is release-published.
    // A full route channel therefore leaves this value behind the process
    // generation and causes a retry on the next owner turn.
    std::uint64_t published_route_generation{};
    std::uint64_t coordinated_route_generation{};

    OwnedProcess(const ControlCommand &command)
        : identity(command.process),
          definition(command),
          process(command.router_id, command.process.area_id,
                  command.process.version, command.process.instance_id,
                  command.initial_dd_sequence, command.maximum_interfaces,
                  device_catalog::ospf_neighbors_per_interface,
                  device_catalog::ospf_lsas_per_instance,
                  std::chrono::milliseconds{
                      command.lsa_initial_wait_milliseconds},
                  std::chrono::milliseconds{
                      command.lsa_second_wait_milliseconds},
                  std::chrono::milliseconds{
                      command.lsa_maximum_wait_milliseconds},
                  std::chrono::milliseconds{
                      command.spf_initial_wait_milliseconds},
                  std::chrono::milliseconds{
                      command.spf_second_wait_milliseconds},
                  std::chrono::milliseconds{
                      command.spf_maximum_wait_milliseconds}),
          area_type(command.area_type),
          default_metric(command.default_metric),
          router_preference(command.router_preference),
          external_preference(command.external_preference),
          summaries(command.summaries),
          nssa_translate_always(command.nssa_translate_always),
          asbr(command.asbr),
          graceful_restart_helper(command.graceful_restart_helper),
          loopfree_alternates(command.loopfree_alternates),
          overload(command.overload) {
      process.set_route_preferences(router_preference,
                                    external_preference);
      process.set_loop_free_alternates(
          loopfree_alternates, RuntimeClock::now());
      process.set_graceful_restart_helper(graceful_restart_helper);
    }

    OwnedProcess(const OwnedProcess &) = delete;
    OwnedProcess &operator=(const OwnedProcess &) = delete;
    OwnedProcess(OwnedProcess &&) noexcept = default;
    OwnedProcess &operator=(OwnedProcess &&) noexcept = default;
    ~OwnedProcess();
  };

  struct GenerationStaging {
    // Only the OSPF owner pthread mutates these vectors. Begin reserves the
    // exact declared counts, stage only appends value records, and Commit
    // constructs a complete replacement before swapping it into live state.
    // No std::vector pointer crosses either SPSC boundary.
    std::vector<ControlCommand> processes;
    std::vector<ControlCommand> interfaces;
    std::vector<ControlCommand> authentications;
    std::vector<ControlCommand> nbma_neighbors;
    std::vector<ControlCommand> virtual_links;
    std::vector<ControlCommand> ranges;
    std::vector<ControlCommand> external_routes;
    std::uint32_t expected_processes{};
    std::uint32_t expected_interfaces{};
    std::uint32_t expected_authentications{};
    std::uint32_t expected_nbma_neighbors{};
    std::uint32_t expected_virtual_links{};
    std::uint32_t expected_ranges{};
    std::uint32_t expected_external_routes{};

    GenerationStaging() = default;
    GenerationStaging(const GenerationStaging &) = delete;
    GenerationStaging &operator=(const GenerationStaging &) = delete;
    GenerationStaging(GenerationStaging &&) noexcept = default;
    GenerationStaging &operator=(GenerationStaging &&) noexcept = default;
    ~GenerationStaging();
  };

  [[nodiscard]] ControlResult apply(const ControlCommand &command) noexcept;
  void receive_frame(const ProtocolPacketChannel::Borrowed &packet,
                     RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool publish(OwnedProcess &owner,
                             const ProcessOutput &output) noexcept;
  [[nodiscard]] bool publish_routes(
      lab::DeviceHandle device,
      std::span<OwnedProcess> processes) noexcept;
  [[nodiscard]] bool coordinate_routes(
      std::span<OwnedProcess> processes,
      RuntimeClock::time_point now) noexcept;
  void run() noexcept;

  ControlChannels &channels_;
  std::size_t forwarding_shards_{};
  // Each router slot owns an independent process generation. A successful
  // vector swap replaces one router atomically while preserving live neighbor
  // and LSDB state for every unrelated router.
  std::array<std::vector<OwnedProcess>, device_catalog::maximum_routers>
      processes_;
  std::array<std::optional<GenerationStaging>,
             device_catalog::maximum_routers>
      generation_staging_;
  // RIB activity can change redistributed routes without changing OSPF
  // configuration. This separate transaction replaces only AS-external
  // advertisements and deliberately preserves live interfaces, neighbors,
  // DD exchange and LSDB state.
  std::array<std::optional<std::vector<ControlCommand>>,
             device_catalog::maximum_routers>
      external_staging_;
  std::array<std::uint32_t, device_catalog::maximum_routers>
      expected_external_staging_{};
  std::array<std::uint64_t, device_catalog::maximum_routers>
      next_route_generation_{};
  // The registry generation cannot be reconstructed from a bounded slot
  // index. Retain the last configured handle so removing the final process
  // publishes its empty withdrawal to the correct router incarnation.
  std::array<lab::DeviceHandle, device_catalog::maximum_routers>
      active_devices_{};
  // Configuration replacement can withdraw the final process, leaving no
  // InstanceProcess generation to compare. This owner-local bit therefore
  // requests publication of an empty route generation after such a commit.
  std::array<bool, device_catalog::maximum_routers>
      route_publication_pending_{};
  // Configuration replacement and an area SPF publication both dirty only
  // that router's ABR projection. The OSPF owner clears the bit after every
  // version/instance group has reconciled complete semantic LSA generations.
  std::array<bool, device_catalog::maximum_routers>
      route_coordination_pending_{};
  // One heap-owned output batch keeps jumbo fixed envelopes off the pthread
  // stack. Its length is a fairness budget, not a protocol packet limit.
  std::vector<ProcessOutput> output_scratch_;
  SpscRing<ControlCommand, device_catalog::network_command_ring_entries>
      commands_;
  SpscRing<ControlResult, device_catalog::network_result_ring_entries>
      results_;
  std::thread thread_;
  std::mutex wait_mutex_;
  std::condition_variable wait_condition_;
  std::atomic_bool stop_requested_{};
  std::atomic_bool work_pending_{};
  std::atomic_uint64_t thread_id_{};
};

} // namespace router::ospf
