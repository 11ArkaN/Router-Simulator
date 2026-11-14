// This fixture owns both serialized command roles and the reverse SPSC producer.
// It verifies cold bank admission, transactional abort, quiescent persistence and
// stale feedback credit return without supplying any foreign protocol state.
#include "router/isis_control_checkpoint.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("Interlevel control invariant at " + std::to_string(at.line()));
}
}
void isis_interlevel_control_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels,1U,2U);
  const lab::DeviceHandle device{0U,1U};
  std::uint64_t serial{};
  const auto command = [&](ControlCommand request) {
    request.id = ++serial; request.identity.device = device;
    const auto until = RuntimeClock::now()+3s;
    while (!worker->submit(std::move(request))) { require(RuntimeClock::now()<until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now()<until); std::this_thread::yield(); }
    require(result.id == serial); return result;
  };
  const auto operation = [&](ControlCommandKind kind) {
    ControlCommand request; request.kind = kind; return command(std::move(request));
  };
  const auto capture = [&] {
    const auto barrier = operation(ControlCommandKind::begin_checkpoint_barrier);
    require(barrier.error == ControlError::none);
    ControlWorkerCheckpoint image;
    ControlCommand request; request.kind = ControlCommandKind::capture_checkpoint;
    request.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
    request.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
    request.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&image);
    require(command(request).error == ControlError::none);
    return std::pair{barrier,std::move(image)};
  };
  const auto resume = [&](const ControlResult &barrier) {
    ControlCommand request; request.kind = ControlCommandKind::end_checkpoint_barrier;
    request.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
    require(command(request).error == ControlError::none);
  };
  require(operation(ControlCommandKind::register_device).error == ControlError::none);
  ControlCommand admission; admission.kind = ControlCommandKind::prepare_generation;
  admission.interlevel_export = InterlevelTemplateBudget{8U,512U,16U};
  require(command(admission).error == ControlError::none);
  require(operation(ControlCommandKind::abort_generation).error == ControlError::none);
  auto [first,image] = capture();
  require(image.devices.size() == 1U && !image.devices[0U].interlevel);
  resume(first);
  require(command(admission).error == ControlError::none);
  require(operation(ControlCommandKind::commit_generation).error == ControlError::none);
  auto [second,saved] = capture();
  require(saved.devices.size() == 1U && saved.devices[0U].interlevel &&
      saved.devices[0U].interlevel->active.budget == *admission.interlevel_export &&
      !saved.devices[0U].interlevel->active.publication && !saved.devices[0U].interlevel->pending.publication);
  const auto valid = saved;
  saved.devices[0U].interlevel->pending.publication = 1U;
  ControlCommand restore; restore.kind = ControlCommandKind::prepare_checkpoint_restore;
  restore.checkpoint_barrier_epoch = second.checkpoint_barrier_epoch;
  restore.checkpoint_source_epoch = saved.barrier_epoch;
  restore.checkpoint_now_nanoseconds = second.checkpoint_anchor_nanoseconds;
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&saved);
  require(command(restore).error != ControlError::none);
  saved = valid;
  require(command(restore).error == ControlError::none);
  restore.kind = ControlCommandKind::commit_checkpoint_restore;
  require(command(restore).error == ControlError::none);
  resume(second);
  admission.interlevel_export->prefixes = 9U;
  require(command(admission).error == ControlError::invalid_argument);
  require(operation(ControlCommandKind::prepare_generation).error == ControlError::none);
  require(operation(ControlCommandKind::abort_generation).error == ControlError::none);
  const auto lease = channels->selections->acquire();
  require(lease.has_value());
  lease->value->identity = {device,1U,1U,1U};
  require(channels->selections->publish(lease->handle));
  worker->notify();
  const auto until = RuntimeClock::now()+3s;
  while (!channels->selections->empty()) { require(RuntimeClock::now()<until); std::this_thread::yield(); }
  // A command round trip orders after the consumer's completed drain and return.
  require(operation(ControlCommandKind::query_sequence_recovery).error == ControlError::none);
  const auto returned = channels->selections->acquire(), other = channels->selections->acquire();
  require(returned && other);
  require(channels->selections->cancel(returned->handle) && channels->selections->cancel(other->handle));
}
