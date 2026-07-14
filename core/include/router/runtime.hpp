// Multithreaded runtime supervisor and the complete control-to-forwarding ABI.
// Browser, storage and DOM types are intentionally excluded from this layer.

#pragma once

#include "router/cli.hpp"
#include "router/hardware.hpp"
#include "router/packet.hpp"
#include "router/network.hpp"
#include "router/routing.hpp"
#include "router/spsc_ring.hpp"
#include "router/telemetry.hpp"

#include <array>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace router {

class Runtime final {
 public:
  Runtime();
  ~Runtime();
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  std::string command(const std::string& text);
  [[nodiscard]] std::span<const std::uint8_t> prepared_capture() const noexcept {
    return prepared_capture_;
  }
  // Preconditions: Runtime is alive. The returned address remains stable until
  // destruction and is read-only for callers. The telemetry page owns no heap
  // pointers. Its sequence field defines cross-thread consistency.
  [[nodiscard]] const TelemetryPageV1& telemetry_page() const noexcept {
    return telemetry_;
  }
  [[nodiscard]] std::span<const std::uint8_t> export_checkpoint();
  [[nodiscard]] std::span<const std::uint8_t> prepared_checkpoint() const noexcept {
    return prepared_checkpoint_;
  }
  [[nodiscard]] bool import_checkpoint(std::span<const std::uint8_t> bytes);

 private:
  struct CommandMessage {
    // Producer and consumer copy this type through SpscRing. Inline text avoids
    // allocator ownership crossing pthread boundaries and keeps publication a
    // single release operation on the ring head.
    std::uint64_t id{};
    // The longest internal project command is below 256 bytes. 1024 bytes also
    // leaves room for terminal editing without charging every response slot for
    // input capacity that packet and hardware commands never use.
    std::array<char, 1024> text{};
  };

  struct ResponseMessage {
    std::uint64_t id{};
    // One hundred supported ping result lines fit below 16 KiB. Keeping this
    // capacity distinct from CommandMessage fixes truncation while avoiding a
    // second 1 MiB command ring. Responses are still value-owned and bounded.
    std::array<char, 16384> text{};
  };

  struct ForwardJob {
    // ForwardJob is the complete control-to-forwarding protocol. Adding a job
    // kind requires a bounded value payload here, a forwarding owner handler,
    // a result acknowledgement, a source record and a conformance test.
    enum class Kind : std::uint8_t {
      router_to_host_b,
      host_a_to_host_b,
      program_fib,
      configure_hosts,
      configure_links,
      export_capture,
      checkpoint_barrier,
      restore_adjacencies
    };
    std::uint64_t id{};
    Kind kind{};
    routing::FibProgram fib{};
    // Host values are already syntax and subnet validated on control. They are
    // repeated as fixed arrays instead of sharing project or DeviceState memory.
    std::array<packet::Mac, 2> host_macs{};
    std::array<packet::Ipv4, 2> host_addresses{};
    std::array<packet::Ipv4, 2> host_gateways{};
    std::array<std::uint8_t, 2> host_prefix_lengths{};
    // Nanoseconds preserve short local media without floating point or unit
    // ambiguity at the shared-memory boundary.
    std::array<std::uint64_t, 2> propagation_delay_ns{};
    std::array<NetworkArpEntry, 2> restored_arp{};
  };

  struct CaptureRecord {
    // Capture records belong only to forwarding. interface_id is the PCAPNG IDB
    // index of the egress observation point, not a topology editor node index.
    std::uint64_t timestamp_us{};
    std::uint8_t interface_id{};
    packet::Frame frame{};
  };

  struct ForwardResult {
    // One result is published for every accepted job. Even failure includes
    // counters and ARP projection obtained before the terminal condition, so
    // diagnostics never invent state on the control side.
    enum class DropReason : std::uint8_t {
      none,
      ingress_down,
      route_miss,
      queue_full,
      ttl_expired,
      timeout,
      malformed
    };
    std::uint64_t id{};
    bool success{};
    std::uint32_t captured_frames{};
    std::uint32_t capture_drops{};
    std::uint8_t reply_ttl{};
    std::uint64_t rtt_us{};
    DropReason drop_reason{};
    std::array<NetworkArpEntry, 2> arp{};
    std::array<std::uint64_t, 2> rx_delta{};
    std::array<std::uint64_t, 2> tx_delta{};
  };

  void control_loop();
  void forwarding_loop();
  // dispatch runs only on control and is the sole mutation gateway for device,
  // session and connected RIB state.
  std::string dispatch(const std::string& text);
  std::string run_ping(ForwardJob::Kind kind, std::uint32_t count = 1);
  std::string configure_hosts(const std::string& text);
  std::string configure_links(const std::string& text);
  std::string prepare_capture();
  std::span<const std::uint8_t> encode_checkpoint_on_control();
  bool decode_checkpoint_on_control(std::span<const std::uint8_t> bytes);
  ForwardResult submit_forward(ForwardJob job);
  // reconcile_fib publishes a complete immutable generation and waits for its
  // installation acknowledgement before returning a new UI snapshot.
  void reconcile_fib();
  bool record_capture(std::uint8_t interface_id, const packet::Frame& frame,
                      std::uint64_t timestamp_us);
  void encode_capture();
  std::string snapshot();
  void stop();

  // Each ring has one producer and one consumer. Blocking waits only park a
  // worker after a failed pop; they do not protect ring contents or packet data.
  // commands_: browser bridge -> control. responses_: control -> bridge.
  SpscRing<CommandMessage, 64> commands_;
  // Only one browser caller enters command() at a time, but several slots keep
  // shutdown and diagnostic paths independent of a single consumer wakeup.
  SpscRing<ResponseMessage, 8> responses_;
  // forward_jobs_: control -> forwarding. forward_results_: forwarding ->
  // control. Packet handles never enter either cross-thread ring.
  SpscRing<ForwardJob, 16> forward_jobs_;
  SpscRing<ForwardResult, 16> forward_results_;

  std::atomic_bool stopping_{false};
  // Control toggles capture through the stable ABI while forwarding tests the
  // flag before supplying an observer. Relaxed ordering is sufficient because
  // the flag guards diagnostics only and publishes no packet state.
  std::atomic_bool capture_active_{true};
  std::atomic_uint64_t next_id_{1};
  std::thread control_thread_;
  std::thread forwarding_thread_;
  mutable std::mutex wake_mutex_;
  std::condition_variable wake_control_;
  std::condition_variable wake_forward_;
  std::condition_variable wake_response_;
  // Every notification first increments its atomic epoch with release order.
  // A waiter records the epoch after observing an empty ring, checks the ring a
  // second time, then waits for epoch change. This closes the lost-wakeup gap
  // without polling deadlines that would add arbitrary command latency.
  std::atomic_uint64_t command_epoch_{};
  std::atomic_uint64_t forward_epoch_{};
  std::atomic_uint64_t result_epoch_{};
  std::atomic_uint64_t response_epoch_{};
  std::atomic_uint64_t control_thread_id_{};
  std::atomic_uint64_t forwarding_thread_id_{};
  std::atomic_uint64_t control_wakeups_{};
  std::atomic_uint64_t forwarding_wakeups_{};
  std::atomic_uint64_t max_scheduling_lag_ns_{};
  std::mutex submit_mutex_;
  // Public checkpoint import copies caller memory under this mutex, then sends
  // a normal control command. The control owner takes a private copy before
  // decoding, so neither browser memory nor bridge-thread lifetime crosses the
  // shard boundary as a borrowed pointer.
  std::mutex checkpoint_mutex_;
  std::vector<std::uint8_t> pending_checkpoint_import_;

  // Only the forwarding shard mutates captures_. A completed export job
  // publishes prepared_capture_ before its release-store into the result ring.
  static constexpr std::size_t capture_memory_bytes = 32U * 1024U * 1024U;
  // Capacity is derived from the real record layout so the vector cannot grow
  // after reserve. Reaching the limit increments capture_dropped and leaves
  // packet forwarding unaffected.
  static constexpr std::size_t capture_capacity = capture_memory_bytes / sizeof(CaptureRecord);
  std::vector<CaptureRecord> captures_;
  std::vector<std::uint8_t> prepared_capture_;
  std::vector<std::uint8_t> prepared_checkpoint_;

  // Device and CLI state have control-thread affinity. The forwarding shard
  // returns immutable deltas so it never mutates RIB, ARP or session state.
  // rib_ owns route selection. fib_generation_ is monotonic across hardware and
  // link flaps, preventing a delayed old program from restoring withdrawn paths.
  DeviceState state_;
  CliSession session_;
  routing::ConnectedRib rib_;
  std::uint64_t fib_generation_{};
  std::chrono::steady_clock::time_point started_;
  // Only control reads or writes this local deadline. It is the earliest piece
  // of equipped hardware that can change lifecycle without a mailbox message.
  // The condition-variable wait uses it directly, so there is no global event
  // queue, polling timer or simulated clock.
  std::optional<std::chrono::steady_clock::time_point> hardware_deadline_;
  alignas(64) TelemetryPageV1 telemetry_{};
  void publish_telemetry() noexcept;
};

}  // namespace router
