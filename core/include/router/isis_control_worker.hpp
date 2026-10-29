// Dedicated IS-IS control owner. Serialized control publishes owned generation
// values; forwarding shards exchange encoded frames through independent SPSC
// pairs. All circuit state remains exclusively on this pthread.

#pragma once

#include "router/isis_p2p_circuit.hpp"
#include "router/owned_spsc_channel.hpp"
#include "router/protocol_packet_channel.hpp"

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
  void (*egress_wakeup)(void *){};
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
  remove_circuit, query_circuit, shutdown
};
struct ControlCommand {
  std::uint64_t id{};
  ControlCommandKind kind{ControlCommandKind::query_worker};
  CircuitIdentity identity;
  P2pCircuitConfiguration configuration;
  std::uint64_t random_state{};
};
enum class ControlError : std::uint8_t {
  none, invalid_argument, stale_device, stale_configuration, not_found,
  already_exists, capacity, unsupported_authentication, construction_failed
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
};
struct ControlResult {
  std::uint64_t id{};
  ControlError error{ControlError::none};
  P2pSnapshot adjacency;
  CircuitCounters counters;
  std::uint64_t thread_identity{};
  std::int64_t holding_deadline_nanoseconds{};
  std::uint32_t active_circuits{};
  bool hello_pending{};
};

class ControlWorker final {
public:
  // Channels and callbacks outlive this object. A nonzero circuit budget is
  // an emulator admission limit, independent of the configuration ID range.
  // Thread creation failure throws and startup must fail closed.
  ControlWorker(ControlChannels &channels, std::size_t forwarding_shards,
                std::size_t maximum_circuits);
  ~ControlWorker();
  ControlWorker(const ControlWorker &) = delete;
  ControlWorker &operator=(const ControlWorker &) = delete;
  // Exactly one serialized control producer. False preserves command values
  // and applies backpressure. No pointer or container crosses a ring.
  [[nodiscard]] bool submit(ControlCommand &&command) noexcept;
  // Exactly one control consumer. Results are immutable value projections.
  [[nodiscard]] bool read(ControlResult &result) noexcept;
  void notify() noexcept;
private:
  struct OwnedCircuit {
    CircuitIdentity identity;
    std::uint16_t wire_instance{};
    packet::Mac destination{};
    packet::isis::InstanceFormat format{};
    bool physical_point_to_point{};
    PointToPointCircuit circuit;
    CircuitCounters counters;
    OwnedCircuit(ControlCommand &command, PointToPointCircuit::Clock::time_point now)
        : identity(command.identity),
          wire_instance(command.configuration.wire_instance),
          destination(command.configuration.hello_destination),
          format(command.configuration.instance_format.value_or(packet::isis::InstanceFormat::standard)),
          physical_point_to_point(command.configuration.physical_point_to_point),
          circuit(std::move(command.configuration), command.random_state, now) {}
  };
  struct DeviceState {
    lab::DeviceHandle handle{};
    bool active{};
    std::vector<OwnedCircuit> circuits;
    std::size_t first_circuit{};
  };
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
