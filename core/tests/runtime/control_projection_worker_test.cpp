// Secondary control-owner contract test. It verifies value-only transfer,
// operational port semantics and owner-thread health without constructing a
// complete laboratory or borrowing hardware state between threads.

#include "router/control_projection_worker.hpp"

#include <stdexcept>
#include <thread>

void control_projection_worker_tests() {
  using namespace router::lab;
  ControlProjectionWorker worker;
  ControlProjectionCommand command{.id = 41,
                                   .device_index = 3,
                                   .device_generation = 7};
  command.ports[0].flags = ControlPortProjectionInput::present |
                           ControlPortProjectionInput::admin_enabled |
                           ControlPortProjectionInput::link_signal;
  command.ports[1].flags = ControlPortProjectionInput::present |
                           ControlPortProjectionInput::admin_enabled;
  if (!worker.submit(command))
    throw std::runtime_error("secondary control ring rejected its first item");
  ControlProjectionResult result;
  for (std::size_t attempt = 0; attempt < 100000U && !worker.read(result);
       ++attempt)
    std::this_thread::yield();
  if (result.id != command.id || result.device_index != command.device_index ||
      result.device_generation != command.device_generation ||
      result.inventory_ports != 2 || result.operational_ports != 1 ||
      result.operational_bitset[0] != 1U || !worker.thread_id() ||
      !worker.turns())
    throw std::runtime_error(
        "secondary control owner produced an invalid port projection");
}
