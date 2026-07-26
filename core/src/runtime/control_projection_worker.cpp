// Implementation of the high-CPU secondary control projection owner. It has
// no timer and no periodic poll. Work begins only after an SPSC release and the
// owner sleeps on a condition variable between commands.

#include "router/control_projection_worker.hpp"

#include <functional>

namespace router::lab {

// The global fixed-memory proof budgets this actor inside the generated 32 MiB
// control reserve. Keeping a local ceiling makes any later command payload or
// ring-capacity increase fail where its owner type is complete.
static_assert(sizeof(ControlProjectionWorker) <= 1024U * 1024U,
              "secondary control projection exceeds its Wasm reserve");

ControlProjectionWorker::ControlProjectionWorker()
    : thread_([this] { run(); }) {}

ControlProjectionWorker::~ControlProjectionWorker() {
  // Primary control has stopped publishing before destruction begins. The
  // stop word releases an empty wait and join proves no projection references
  // remain before the containing LabRuntime releases telemetry storage.
  stop_requested_.store(true, std::memory_order_release);
  notify();
  if (thread_.joinable())
    thread_.join();
}

bool ControlProjectionWorker::submit(
    const ControlProjectionCommand &command) noexcept {
  if (!commands_.try_push(command))
    return false;
  notify();
  return true;
}

bool ControlProjectionWorker::read(ControlProjectionResult &result) noexcept {
  const bool consumed = results_.try_pop(result);
  if (consumed)
    notify();
  return consumed;
}

void ControlProjectionWorker::notify() noexcept {
  // Taking the wait mutex closes the notify-before-sleep race. Ring payload
  // visibility still comes exclusively from SpscRing release and acquire.
  { std::lock_guard lock(wait_mutex_); }
  wait_condition_.notify_one();
}

void ControlProjectionWorker::run() noexcept {
  auto identity = static_cast<std::uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  thread_id_.store(identity ? identity : 1U, std::memory_order_release);
  while (!stop_requested_.load(std::memory_order_acquire)) {
    ControlProjectionCommand command;
    if (!commands_.try_pop(command)) {
      std::unique_lock lock(wait_mutex_);
      wait_condition_.wait(lock, [&] {
        return stop_requested_.load(std::memory_order_acquire) ||
               !commands_.empty();
      });
      continue;
    }
    turns_.fetch_add(1U, std::memory_order_relaxed);
    ControlProjectionResult result{.id = command.id,
                                   .device_index = command.device_index,
                                   .device_generation =
                                       command.device_generation};
    // Operational means all three independently owned conditions are true.
    // This mirrors the existing device projection but assigns odd stable
    // device indexes to a distinct real control owner on high-CPU hosts.
    constexpr auto operational = ControlPortProjectionInput::present |
                                 ControlPortProjectionInput::admin_enabled |
                                 ControlPortProjectionInput::link_signal;
    for (std::size_t ordinal = 0; ordinal < command.ports.size(); ++ordinal) {
      const auto flags = command.ports[ordinal].flags;
      if (flags & ControlPortProjectionInput::present)
        ++result.inventory_ports;
      if ((flags & operational) == operational) {
        ++result.operational_ports;
        result.operational_bitset[ordinal / 8U] |=
            static_cast<std::uint8_t>(1U << (ordinal % 8U));
      }
    }
    // Backpressure is lossless: the worker waits for its sole consumer rather
    // than discarding a projection and allowing telemetry to mix generations.
    while (!results_.try_push(result) &&
           !stop_requested_.load(std::memory_order_acquire)) {
      std::unique_lock lock(wait_mutex_);
      wait_condition_.wait(lock, [&] {
        return stop_requested_.load(std::memory_order_acquire) ||
               !results_.full();
      });
    }
  }
  thread_id_.store(0U, std::memory_order_release);
}

} // namespace router::lab
