// Hardware reconciler for profile-driven inventory, provisioning and lifecycle.
// It receives only running config, physical state and operational projections,
// so hardware code cannot mutate candidate config or project endpoint state.

#pragma once

#include "router/device.hpp"

#include <chrono>
#include <optional>

namespace router::hardware {

struct ReconcileResult {
  // operational_change tells Runtime to publish a new FIB generation. A mere
  // reason-text refresh does not need to cross into the forwarding shard.
  bool operational_change{};
  std::optional<std::chrono::steady_clock::time_point> next_deadline;
};

// Preconditions: all three values belong to the calling control shard and now
// comes from steady_clock. Postconditions: lifecycle, reasons, alarms and
// deadlines agree with inventory and running provisioning. This function does
// not allocate or block. Unsupported inventory becomes mismatch state.
[[nodiscard]] ReconcileResult
reconcile(const DeviceConfiguration &running, HardwareState &hardware,
          OperationalState &operational,
          std::chrono::steady_clock::time_point now) noexcept;

[[nodiscard]] bool operational(const DeviceConfiguration &running,
                               const HardwareState &hardware) noexcept;
[[nodiscard]] std::size_t
inventory_port_count(const HardwareState &hardware) noexcept;
[[nodiscard]] bool port_operational(const DeviceConfiguration &running,
                                    const HardwareState &hardware,
                                    std::size_t index) noexcept;

[[nodiscard]] const char *lifecycle_name(EquipmentLifecycle value) noexcept;

} // namespace router::hardware
