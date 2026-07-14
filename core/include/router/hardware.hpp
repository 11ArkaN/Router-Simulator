// Hardware reconciler for profile-driven inventory, provisioning and lifecycle.
// DeviceState remains control-shard owned. This module has no packet-path or UI
// dependency and mutates hardware fields only when called by that owner.

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

// Preconditions: state belongs to the calling control shard and now comes from
// steady_clock. Postconditions: lifecycle, reason and deadlines agree with
// inventory and running provisioning. This function allocates no memory and
// never blocks. There are no error codes because unsupported inventory is
// represented by mismatch state and a stable reason.
[[nodiscard]] ReconcileResult reconcile(
    DeviceState& state, std::chrono::steady_clock::time_point now) noexcept;

[[nodiscard]] const char* lifecycle_name(EquipmentLifecycle value) noexcept;

}  // namespace router::hardware
