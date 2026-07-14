// Common hardware lifecycle implementation shared by CLI, runtime and tests.
// The control shard is the only caller allowed to mutate DeviceState. Profile
// timing values are explicitly experimental and never presented as Nokia boot
// time measurements.

#include "router/hardware.hpp"

#include <algorithm>

namespace router::hardware {
namespace {

using Clock = std::chrono::steady_clock;

void begin_initialization(EquipmentLifecycle& lifecycle,
                          Clock::time_point& deadline,
                          Clock::time_point now,
                          Clock::duration delay) noexcept {
  lifecycle = EquipmentLifecycle::initializing;
  deadline = now + delay;
}

}  // namespace

ReconcileResult reconcile(DeviceState& state, Clock::time_point now) noexcept {
  const bool was_operational = state.hardware_operational();
  std::optional<Clock::time_point> next;

  if (!state.card_present) {
    state.card_lifecycle = EquipmentLifecycle::absent;
    state.card_reason = "not-equipped";
    state.card_deadline = {};
  } else if (!state.card_provisioned || !state.card_admin_enabled) {
    state.card_lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    state.card_reason = state.card_admin_enabled ? "not-provisioned" : "admin-down";
    state.card_deadline = {};
  } else {
    if (state.card_lifecycle != EquipmentLifecycle::initializing &&
        state.card_lifecycle != EquipmentLifecycle::ready) {
      begin_initialization(state.card_lifecycle, state.card_deadline, now,
                           profile::card_initialization);
    }
    if (state.card_lifecycle == EquipmentLifecycle::initializing &&
        now >= state.card_deadline) {
      state.card_lifecycle = EquipmentLifecycle::ready;
    }
    state.card_reason = state.card_lifecycle == EquipmentLifecycle::ready
                            ? "none"
                            : "initializing-experimental";
    if (state.card_lifecycle == EquipmentLifecycle::initializing) next = state.card_deadline;
  }

  if (!state.mda_present) {
    state.mda_lifecycle = EquipmentLifecycle::absent;
    state.mda_reason = "not-equipped";
    state.mda_deadline = {};
  } else if (!state.mda_compatible) {
    state.mda_lifecycle = EquipmentLifecycle::mismatch;
    state.mda_reason = "inventory-provisioning-mismatch";
    state.mda_deadline = {};
  } else if (!state.mda_provisioned || !state.mda_admin_enabled) {
    state.mda_lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    state.mda_reason = state.mda_admin_enabled ? "not-provisioned" : "admin-down";
    state.mda_deadline = {};
  } else if (state.card_lifecycle != EquipmentLifecycle::ready) {
    state.mda_lifecycle = EquipmentLifecycle::waiting_for_parent;
    state.mda_reason = "parent-not-ready";
    state.mda_deadline = {};
  } else {
    if (state.mda_lifecycle != EquipmentLifecycle::initializing &&
        state.mda_lifecycle != EquipmentLifecycle::ready) {
      begin_initialization(state.mda_lifecycle, state.mda_deadline, now,
                           profile::mda_initialization);
    }
    if (state.mda_lifecycle == EquipmentLifecycle::initializing &&
        now >= state.mda_deadline) {
      state.mda_lifecycle = EquipmentLifecycle::ready;
    }
    state.mda_reason = state.mda_lifecycle == EquipmentLifecycle::ready
                           ? "none"
                           : "initializing-experimental";
    if (state.mda_lifecycle == EquipmentLifecycle::initializing) {
      next = next ? std::min(*next, state.mda_deadline) : state.mda_deadline;
    }
  }

  state.alarm_count = 0;
  const auto alarm = [&state](const char* id, const char* reason) {
    if (state.alarm_count < state.alarms.size()) {
      state.alarms[state.alarm_count++] = {id, "minor", reason};
    }
  };
  if (state.card_lifecycle != EquipmentLifecycle::ready) alarm("card-1", state.card_reason);
  if (state.card_present && state.mda_lifecycle != EquipmentLifecycle::ready) {
    alarm("mda-1/1", state.mda_reason);
  }
  for (std::size_t index = 0; index < 2 && index < state.inventory_port_count(); ++index) {
    if (!state.port_operational(index)) {
      alarm(index ? "port-1/1/2" : "port-1/1/1",
            !state.ports[index].admin_enabled ? "admin-down" :
            (!state.ports[index].link_signal ? "link-down" : "hardware-not-ready"));
    }
  }

  return {.operational_change = was_operational != state.hardware_operational(),
          .next_deadline = next};
}

const char* lifecycle_name(EquipmentLifecycle value) noexcept {
  switch (value) {
    case EquipmentLifecycle::absent: return "absent";
    case EquipmentLifecycle::waiting_for_provisioning: return "waiting-provisioning";
    case EquipmentLifecycle::waiting_for_parent: return "waiting-parent";
    case EquipmentLifecycle::initializing: return "initializing";
    case EquipmentLifecycle::ready: return "ready";
    case EquipmentLifecycle::mismatch: return "mismatch";
  }
  return "unknown";
}

}  // namespace router::hardware
