// Protocol shutdown retains callback targets until forwarding has joined.
// Real notification producers race with stop, then continue using the stopped
// object's live notification storage. No protocol datastore crosses threads.

#include "router/isis_control_worker.hpp"
#include "router/ospf_control_worker.hpp"
#include "router/network_plane.hpp"

#include <atomic>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
template <typename Command, typename Worker> void exercise(Worker &worker) {
  std::atomic_bool finished{};
  std::atomic_uint64_t notifications{};
  std::thread forwarding([&] {
    while (!finished.load(std::memory_order_acquire)) {
      worker.notify();
      notifications.fetch_add(1U, std::memory_order_release);
      std::this_thread::yield();
    }
  });
  while (!notifications.load(std::memory_order_acquire)) std::this_thread::yield();
  worker.stop();
  worker.stop();
  // These notifications model outstanding frame credits after protocol join.
  for (std::size_t index{}; index < 1024U; ++index) worker.notify();
  Command command;
  command.id = 42U;
  const bool accepted = worker.submit(std::move(command));
  const auto identity = worker.thread_id();
  finished.store(true, std::memory_order_release);
  forwarding.join();
  if (accepted || command.id != 42U || identity != 0U)
    throw std::runtime_error("Stopped protocol owner accepted work or retained a live thread identity");
}
}

void protocol_owner_lifecycle_tests() {
  {
    using namespace router::ospf;
    auto channels = std::make_unique<ControlChannels>();
    ControlWorker worker(*channels, 1U);
    std::uint64_t next_id{};
    const auto execute = [&](ControlCommand command) {
      command.id = ++next_id;
      const auto deadline = RuntimeClock::now() + std::chrono::seconds{2};
      while (!worker.submit(command)) {
        if (RuntimeClock::now() >= deadline)
          throw std::runtime_error("OSPF export command admission timed out");
        std::this_thread::yield();
      }
      ControlResult result;
      while (!worker.read(result)) {
        if (RuntimeClock::now() >= deadline)
          throw std::runtime_error("OSPF export result timed out");
        std::this_thread::yield();
      }
      if (result.id != command.id)
        throw std::runtime_error("OSPF export result identity mismatch");
      return result.success;
    };
    const ProcessIdentity identity{.device = {0U, 1U}};
    const auto transaction = [&](ControlCommandKind kind) {
      return execute({.process = identity, .kind = kind});
    };
    if (transaction(ControlCommandKind::prepare_external_generation) ||
        !transaction(ControlCommandKind::begin_external_generation) ||
        !transaction(ControlCommandKind::prepare_external_generation) ||
        !transaction(ControlCommandKind::prepare_external_generation) ||
        transaction(ControlCommandKind::begin_external_generation) ||
        transaction(ControlCommandKind::remove_process))
      throw std::runtime_error("Prepared OSPF export did not pin process layout");
    auto checkpoint = std::make_unique<ControlWorkerCheckpoint>();
    const auto capture = [&] {
      return execute({.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(checkpoint.get()),
                      .kind = ControlCommandKind::checkpoint});
    };
    if (capture() || !transaction(ControlCommandKind::commit_external_generation) ||
        !capture() || transaction(ControlCommandKind::commit_external_generation))
      throw std::runtime_error("OSPF export preparation crossed checkpoint or committed twice");
    if (!transaction(ControlCommandKind::begin_external_generation) ||
        !transaction(ControlCommandKind::prepare_external_generation) ||
        !transaction(ControlCommandKind::abort_external_generation) || !capture() ||
        transaction(ControlCommandKind::commit_external_generation))
      throw std::runtime_error("Aborted OSPF export retained its prepared lease");
    if (!execute({.process = identity, .expected_external_routes = 1U,
                  .kind = ControlCommandKind::begin_external_generation}) ||
        transaction(ControlCommandKind::prepare_external_generation) ||
        !transaction(ControlCommandKind::abort_external_generation))
      throw std::runtime_error("Incomplete OSPF export preparation was accepted");
  }
  {
    auto channels = std::make_unique<router::isis::ControlChannels>();
    router::isis::ControlWorker worker(*channels, 1U, 1U);
    exercise<router::isis::ControlCommand>(worker);
  }
  {
    auto channels = std::make_unique<router::ospf::ControlChannels>();
    router::ospf::ControlWorker worker(*channels, 1U);
    exercise<router::ospf::ControlCommand>(worker);
  }
  for (std::size_t iteration{}; iteration < 8U; ++iteration) {
    auto plane = std::make_unique<router::lab::NetworkPlane>(8U);
    const auto deadline = router::lab::NetworkPlane::Clock::now() + std::chrono::seconds{2};
    while (!plane->isis_owner_thread_id() || !plane->ospf_owner_thread_id() ||
        !plane->forwarding_owner_thread_id(0U) || !plane->forwarding_owner_thread_id(1U)) {
      if (router::lab::NetworkPlane::Clock::now() >= deadline)
        throw std::runtime_error("Repeated network startup did not publish every owner: iteration=" +
            std::to_string(iteration) + " isis=" + std::to_string(plane->isis_owner_thread_id()) +
            " ospf=" + std::to_string(plane->ospf_owner_thread_id()) + " forwarding0=" +
            std::to_string(plane->forwarding_owner_thread_id(0U)) + " forwarding1=" +
            std::to_string(plane->forwarding_owner_thread_id(1U)));
      std::this_thread::yield();
    }
  }
}
