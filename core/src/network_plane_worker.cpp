// Network owner pthread implementation. No command handler touches control
// registries or returns pointers across the SPSC boundary.

#include "router/network_plane_worker.hpp"

#include <chrono>
#include <functional>
#include <new>
#include <optional>
#include <utility>

namespace router::lab {

NetworkPlaneWorker::NetworkPlaneWorker(NetworkPlaneChannels &channels)
    : channels_(channels) {
  // Forwarding owners publish egress into SPSC transfer rings. Their callback
  // wakes this link owner if it is sleeping without a physical deadline.
  plane_.set_link_wakeup(this, wake_link_owner);
}

NetworkPlaneWorker::~NetworkPlaneWorker() { stop(); }

void NetworkPlaneWorker::wake_link_owner(void *context) noexcept {
  auto &worker = *static_cast<NetworkPlaneWorker *>(context);
  { std::lock_guard lock(worker.wait_mutex_); }
  worker.wait_condition_.notify_one();
}

void NetworkPlaneWorker::start() {
  // A worker instance has one physical lifetime. Restarting would retain plane
  // state while changing thread affinity, so a joined worker is not reusable.
  if (thread_.joinable() || running_.load(std::memory_order_acquire))
    return;
  stop_requested_.store(false, std::memory_order_release);
  thread_ = std::thread([this] { run(); });
}

void NetworkPlaneWorker::stop() noexcept {
  stop_requested_.store(true, std::memory_order_release);
  // The producer-side lock closes the condition-variable handoff window. The
  // worker releases this mutex atomically when it begins waiting.
  { std::lock_guard lock(wait_mutex_); }
  wait_condition_.notify_one();
  if (thread_.joinable())
    thread_.join();
}

bool NetworkPlaneWorker::submit(const NetworkCommand &command) noexcept {
  // Version mismatch is rejected before consuming shared ring capacity. The
  // network thread never has to infer the layout of an unknown command.
  if (command.version != network_plane_message_version ||
      !channels_.commands.try_push(command))
    return false;
  { std::lock_guard lock(wait_mutex_); }
  wait_condition_.notify_one();
  return true;
}

bool NetworkPlaneWorker::read(NetworkResult &result) noexcept {
  // Control is the only consumer. Acquire ordering makes the complete result
  // visible before the caller matches its monotonically assigned command ID.
  if (!channels_.results.try_pop(result))
    return false;
  // A consumed result can release a worker blocked by response backpressure.
  { std::lock_guard lock(wait_mutex_); }
  wait_condition_.notify_one();
  return true;
}

bool NetworkPlaneWorker::stage_restore(NetworkPlaneCheckpoint state) {
  // Synchronous supervisor dispatch permits one pending restore. Allocating and
  // copying happen on control before release-publishing the command.
  if (pending_restore_)
    return false;
  try {
    pending_restore_ =
        std::make_unique<NetworkPlaneCheckpoint>(std::move(state));
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

NetworkResult NetworkPlaneWorker::apply(
    const NetworkCommand &command) noexcept {
  NetworkResult result{.version = network_plane_message_version,
                       .id = command.id,
                       .kind = command.kind};
  if (command.version != network_plane_message_version)
    return result;
  switch (command.kind) {
  case NetworkCommandKind::add_router:
    result.success = plane_.add_router(command.device);
    break;
  case NetworkCommandKind::remove_router:
    result.success = plane_.remove_router(command.device);
    break;
  case NetworkCommandKind::add_host:
    result.success = plane_.add_host(command.host);
    break;
  case NetworkCommandKind::remove_host:
    result.success = plane_.remove_host(command.host);
    break;
  case NetworkCommandKind::configure_port:
    result.success = plane_.configure_port(command.device, command.port);
    break;
  case NetworkCommandKind::remove_port:
    result.success =
        plane_.remove_port(command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::program_fib:
    result.success = plane_.program_fib(command.device, command.fib);
    break;
  case NetworkCommandKind::configure_host:
    result.success = plane_.configure_host(command.host_program);
    break;
  case NetworkCommandKind::configure_link:
    result.success = plane_.configure_link(command.link_program);
    break;
  case NetworkCommandKind::remove_link:
    result.success = plane_.remove_link(command.link);
    break;
  case NetworkCommandKind::router_ping:
    result.success = plane_.start_router_ping(
        command.device, command.destination, command.sequence,
        NetworkPlane::Clock::now(), command.payload_octets,
        command.dont_fragment);
    break;
  case NetworkCommandKind::host_ping:
    result.success = plane_.start_host_ping(
        command.host, command.host_destination, command.sequence);
    break;
  case NetworkCommandKind::router_ping_status:
    // Control validates the handle in DeviceRegistry before issuing the query.
    // The payload therefore reports completion without exposing a forwarding
    // pointer or copying the router's adjacency state across the shard.
    result.success = true;
    result.value = plane_.router_ping_reply(command.device, command.sequence);
    break;
  case NetworkCommandKind::host_ping_status:
    result.success = true;
    result.value = plane_.host_ping_reply(command.host, command.sequence);
    break;
  case NetworkCommandKind::active_link_count:
    result.success = true;
    result.value = plane_.active_links();
    break;
  case NetworkCommandKind::configure_capture_point:
    result.success = plane_.configure_capture_point(command.capture_program);
    break;
  case NetworkCommandKind::prepare_capture:
    plane_.prepare_capture();
    result.success = true;
    result.value = plane_.prepared_capture().size();
    break;
  case NetworkCommandKind::capture_frame_count:
    result.success = true;
    result.value = plane_.captured_frames();
    break;
  case NetworkCommandKind::capture_drop_count:
    result.success = true;
    result.value = plane_.capture_dropped();
    break;
  case NetworkCommandKind::packet_drop_count:
    result.success = true;
    result.value = plane_.dropped_packets();
    break;
  case NetworkCommandKind::prepare_router_checkpoint:
    try {
      const auto state = plane_.router_checkpoint(
          command.device, NetworkPlane::Clock::now());
      if (state) {
        prepared_router_checkpoint_ =
            std::make_unique<RouterForwarderCheckpoint>(*state);
        result.success = true;
      } else {
        prepared_router_checkpoint_.reset();
      }
    } catch (const std::bad_alloc &) {
      prepared_router_checkpoint_.reset();
    }
    break;
  case NetworkCommandKind::prepare_checkpoint:
    try {
      prepared_checkpoint_ = std::make_unique<NetworkPlaneCheckpoint>(
          plane_.checkpoint(NetworkPlane::Clock::now()));
      result.success = true;
    } catch (const std::bad_alloc &) {
      prepared_checkpoint_.reset();
    }
    break;
  case NetworkCommandKind::restore_checkpoint:
    result.success = pending_restore_ &&
                     plane_.restore(*pending_restore_,
                                    NetworkPlane::Clock::now());
    pending_restore_.reset();
    break;
  case NetworkCommandKind::shutdown:
    // Shutdown acknowledgment is published before the run loop observes the
    // stop word, allowing control to distinguish clean stop from worker loss.
    result.success = true;
    stop_requested_.store(true, std::memory_order_release);
    break;
  }
  return result;
}

void NetworkPlaneWorker::run() noexcept {
  // std::thread::id is process-local and never enters a checkpoint. Hashing it
  // produces the opaque nonzero health token already used by telemetry ABI 5.
  auto owner = static_cast<std::uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  if (!owner)
    owner = 1U;
  owner_thread_id_.store(owner, std::memory_order_release);
  running_.store(true, std::memory_order_release);
  std::optional<NetworkResult> pending_result;
  while (!stop_requested_.load(std::memory_order_acquire)) {
    owner_turns_.fetch_add(1U, std::memory_order_relaxed);
    // A result owns its command completion until control accepts it. No later
    // command executes while the bounded response path is applying backpressure.
    if (pending_result && channels_.results.try_push(*pending_result))
      pending_result.reset();

    std::size_t budget = 64;
    NetworkCommand command;
    while (!pending_result && budget-- &&
           channels_.commands.try_pop(command)) {
      auto result = apply(command);
      if (!channels_.results.try_push(result))
        pending_result = result;
      if (stop_requested_.load(std::memory_order_acquire))
        break;
    }

    const auto now = NetworkPlane::Clock::now();
    plane_.pump(now);
    if (stop_requested_.load(std::memory_order_acquire))
      break;
    const auto medium = plane_.next_deadline();
    std::unique_lock lock(wait_mutex_);
    const auto ready = [&] {
      return stop_requested_.load(std::memory_order_acquire) ||
             !channels_.commands.empty() ||
             (pending_result && !channels_.results.full());
    };
    // The predicate closes the notify-before-wait race using the ring's
    // release/acquire publication. Without an in-flight frame there is no
    // periodic maintenance task, so an idle laboratory sleeps indefinitely.
    if (medium)
      static_cast<void>(wait_condition_.wait_until(lock, *medium, ready));
    else
      wait_condition_.wait(lock, ready);
  }
  running_.store(false, std::memory_order_release);
  owner_thread_id_.store(0U, std::memory_order_release);
}

} // namespace router::lab
