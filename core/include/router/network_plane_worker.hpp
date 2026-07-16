// Dedicated network owner thread. It drains bounded control commands, pumps
// ready packet work against steady_clock and sleeps on notification or the next
// direction-local delivery deadline.

#pragma once

#include "router/network_plane_messages.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <memory>
#include <span>
#include <thread>
#include <utility>

namespace router::lab {

class NetworkPlaneWorker final {
public:
  explicit NetworkPlaneWorker(NetworkPlaneChannels &channels);
  ~NetworkPlaneWorker();
  NetworkPlaneWorker(const NetworkPlaneWorker &) = delete;
  NetworkPlaneWorker &operator=(const NetworkPlaneWorker &) = delete;

  void start();
  void stop() noexcept;
  // submit has exactly one caller on the control owner. false means bounded
  // backpressure and the command was not accepted or partially executed.
  [[nodiscard]] bool submit(const NetworkCommand &command) noexcept;
  [[nodiscard]] bool read(NetworkResult &result) noexcept;
  // Control may borrow the immutable export only after a prepare_capture result
  // has crossed the release/acquire response ring. The next prepare invalidates
  // the span and must not overlap its consumer.
  [[nodiscard]] std::span<const std::uint8_t>
  prepared_capture() const noexcept {
    return plane_.prepared_capture();
  }
  // Prepared image is immutable after the matching result crosses the response
  // ring. Restore staging is written by control before the command release and
  // consumed exactly once by the network owner.
  [[nodiscard]] const NetworkPlaneCheckpoint *prepared_checkpoint() const noexcept {
    return prepared_checkpoint_.get();
  }
  [[nodiscard]] std::unique_ptr<NetworkPlaneCheckpoint>
  take_prepared_checkpoint() noexcept {
    return std::move(prepared_checkpoint_);
  }
  [[nodiscard]] const RouterForwarderCheckpoint *
  prepared_router_checkpoint() const noexcept {
    return prepared_router_checkpoint_.get();
  }
  [[nodiscard]] bool stage_restore(NetworkPlaneCheckpoint state);
  void cancel_staged_restore() noexcept { pending_restore_.reset(); }
  [[nodiscard]] bool running() const noexcept {
    return running_.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::uint64_t owner_thread_id() const noexcept {
    // Zero is reserved for a worker that has not entered its run loop. The
    // telemetry smoke gate can therefore distinguish startup from failure.
    return owner_thread_id_.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::uint64_t owner_turns() const noexcept {
    // The monotonic diagnostic counter lets tests and telemetry distinguish a
    // sleeping owner from a hidden periodic poll loop. It has no network-time
    // meaning and is never persisted in a checkpoint.
    return owner_turns_.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::size_t forwarding_owner_count() const noexcept {
    return plane_.forwarding_owner_count();
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_thread_id(std::size_t index) const noexcept {
    return plane_.forwarding_owner_thread_id(index);
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_turns(std::size_t index) const noexcept {
    return plane_.forwarding_owner_turns(index);
  }

private:
  static void wake_link_owner(void *context) noexcept;
  void run() noexcept;
  [[nodiscard]] NetworkResult apply(const NetworkCommand &command) noexcept;

  NetworkPlaneChannels &channels_;
  std::unique_ptr<NetworkPlaneCheckpoint> prepared_checkpoint_;
  std::unique_ptr<RouterForwarderCheckpoint> prepared_router_checkpoint_;
  std::unique_ptr<NetworkPlaneCheckpoint> pending_restore_;
  std::thread thread_;
  std::atomic_bool stop_requested_{};
  std::atomic_bool running_{};
  std::atomic_uint64_t owner_thread_id_{};
  std::atomic_uint64_t owner_turns_{};
  // The mutex protects only sleeping and notification. Queue bytes and owner
  // state remain synchronized exclusively by SpscRing acquire and release.
  std::mutex wait_mutex_;
  std::condition_variable wait_condition_;
  // Declared last so it is destroyed first. Its forwarding pthreads may use
  // the wake callback and therefore must join while the mutex and condition
  // variable above are still alive.
  NetworkPlane plane_;
};

} // namespace router::lab
