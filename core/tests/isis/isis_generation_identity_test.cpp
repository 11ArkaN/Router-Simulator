// The control owner reserves complete configuration identities without changing
// live state until commit. Quiescent restoration keeps exhaustion monotonic;
// this fixture owns both command roles and never supplies peer routing state.
#include "router/isis_control_checkpoint.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS generation identity invariant at " + std::to_string(where.line()));
}
}
void isis_generation_identity_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels,1U,2U);
  const lab::DeviceHandle device{0U,1U};
  std::uint64_t serial{};
  const auto command = [&](ControlCommand request) {
    request.id = ++serial;
    const auto until = RuntimeClock::now() + 3s;
    while (!worker->submit(std::move(request))) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    require(result.id == serial); return result;
  };
  const auto operation = [&](ControlCommandKind kind) {
    ControlCommand request; request.kind = kind; request.identity.device = device; return command(std::move(request));
  };
  require(operation(ControlCommandKind::register_device).error == ControlError::none);
  require(operation(ControlCommandKind::query_sequence_recovery).configuration_epoch == 0U);
  auto prepare = operation(ControlCommandKind::prepare_generation);
  require(prepare.error == ControlError::none && prepare.configuration_epoch == 1U);
  require(operation(ControlCommandKind::abort_generation).configuration_epoch == 0U);
  prepare = operation(ControlCommandKind::prepare_generation);
  require(prepare.error == ControlError::none && prepare.configuration_epoch == 1U);
  const auto committed = operation(ControlCommandKind::commit_generation);
  require(committed.error == ControlError::none && committed.configuration_epoch == 1U);
  require(operation(ControlCommandKind::query_sequence_recovery).configuration_epoch == 1U);
  prepare = operation(ControlCommandKind::prepare_generation);
  require(prepare.error == ControlError::none && prepare.configuration_epoch == 2U);
  require(operation(ControlCommandKind::abort_generation).configuration_epoch == 1U);
  const auto barrier = operation(ControlCommandKind::begin_checkpoint_barrier);
  require(barrier.error == ControlError::none && barrier.checkpoint_barrier_epoch);
  ControlWorkerCheckpoint image;
  ControlCommand capture; capture.kind = ControlCommandKind::capture_checkpoint;
  capture.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  capture.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
  capture.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&image);
  require(command(capture).error == ControlError::none && image.devices.size() == 1U &&
      image.devices[0U].configuration_epoch == 1U);
  image.devices[0U].configuration_epoch = UINT64_MAX;
  ControlCommand restore; restore.kind = ControlCommandKind::prepare_checkpoint_restore;
  restore.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  restore.checkpoint_source_epoch = image.barrier_epoch;
  restore.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&image);
  require(command(restore).error == ControlError::none);
  restore.kind = ControlCommandKind::commit_checkpoint_restore;
  require(command(restore).error == ControlError::none);
  ControlCommand resume; resume.kind = ControlCommandKind::end_checkpoint_barrier;
  resume.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  require(command(resume).error == ControlError::none);
  require(operation(ControlCommandKind::query_sequence_recovery).configuration_epoch == UINT64_MAX);
  require(operation(ControlCommandKind::prepare_generation).error == ControlError::epoch_exhausted);
  require(operation(ControlCommandKind::query_sequence_recovery).configuration_epoch == UINT64_MAX);
  require(operation(ControlCommandKind::remove_device).error == ControlError::none);
  const auto retained = operation(ControlCommandKind::register_device);
  require(retained.error == ControlError::none && retained.configuration_epoch == UINT64_MAX);
  require(operation(ControlCommandKind::remove_device).error == ControlError::none);
  ControlCommand replacement; replacement.kind = ControlCommandKind::register_device;
  replacement.identity.device = {0U,2U};
  const auto fresh = command(std::move(replacement));
  require(fresh.error == ControlError::none && fresh.configuration_epoch == 0U);
  require(operation(ControlCommandKind::query_sequence_recovery).error == ControlError::stale_device);
}
