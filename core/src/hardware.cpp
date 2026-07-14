// Profile-driven hardware lifecycle and alarm projection. The control shard is
// the sole caller and owner. This module depends on device values but has no
// dependency on CLI, routing, forwarding, capture or UI representations.

#include "router/hardware.hpp"

#include <algorithm>

namespace router::hardware {
namespace {

using Clock = std::chrono::steady_clock;

void begin_initialization(EquipmentState &equipment, Clock::time_point now,
                          Clock::duration delay) noexcept {
  equipment.lifecycle = EquipmentLifecycle::initializing;
  equipment.deadline = now + delay;
}

} // namespace

bool operational(const DeviceConfiguration &running,
                 const HardwareState &hardware) noexcept {
  return running.card_provisioned && running.mda_provisioned &&
         hardware.card.present && hardware.mda.present &&
         running.card_admin_enabled && running.mda_admin_enabled &&
         hardware.mda.compatible &&
         hardware.card.lifecycle == EquipmentLifecycle::ready &&
         hardware.mda.lifecycle == EquipmentLifecycle::ready;
}

std::size_t inventory_port_count(const HardwareState &hardware) noexcept {
  return hardware.mda.present && hardware.mda.compatible ? profile::port_count
                                                         : 0U;
}

bool port_operational(const DeviceConfiguration &running,
                      const HardwareState &hardware,
                      std::size_t index) noexcept {
  return index < inventory_port_count(hardware) &&
         operational(running, hardware) && running.ports[index].admin_enabled &&
         hardware.link_signal[index];
}

ReconcileResult reconcile(const DeviceConfiguration &running,
                          HardwareState &hardware, OperationalState &state,
                          Clock::time_point now) noexcept {
  const bool was_operational = operational(running, hardware);
  std::optional<Clock::time_point> next;

  if (!hardware.card.present) {
    hardware.card.lifecycle = EquipmentLifecycle::absent;
    hardware.card.reason = "not-equipped";
    hardware.card.deadline = {};
  } else if (!running.card_provisioned || !running.card_admin_enabled) {
    hardware.card.lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    hardware.card.reason =
        running.card_admin_enabled ? "not-provisioned" : "admin-down";
    hardware.card.deadline = {};
  } else {
    if (hardware.card.lifecycle != EquipmentLifecycle::initializing &&
        hardware.card.lifecycle != EquipmentLifecycle::ready) {
      begin_initialization(hardware.card, now, profile::card_initialization);
    }
    if (hardware.card.lifecycle == EquipmentLifecycle::initializing &&
        now >= hardware.card.deadline) {
      hardware.card.lifecycle = EquipmentLifecycle::ready;
    }
    hardware.card.reason = hardware.card.lifecycle == EquipmentLifecycle::ready
                               ? "none"
                               : "initializing-experimental";
    if (hardware.card.lifecycle == EquipmentLifecycle::initializing) {
      next = hardware.card.deadline;
    }
  }

  if (!hardware.mda.present) {
    hardware.mda.lifecycle = EquipmentLifecycle::absent;
    hardware.mda.reason = "not-equipped";
    hardware.mda.deadline = {};
  } else if (!hardware.mda.compatible) {
    hardware.mda.lifecycle = EquipmentLifecycle::mismatch;
    hardware.mda.reason = "inventory-provisioning-mismatch";
    hardware.mda.deadline = {};
  } else if (!running.mda_provisioned || !running.mda_admin_enabled) {
    hardware.mda.lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    hardware.mda.reason =
        running.mda_admin_enabled ? "not-provisioned" : "admin-down";
    hardware.mda.deadline = {};
  } else if (hardware.card.lifecycle != EquipmentLifecycle::ready) {
    hardware.mda.lifecycle = EquipmentLifecycle::waiting_for_parent;
    hardware.mda.reason = "parent-not-ready";
    hardware.mda.deadline = {};
  } else {
    if (hardware.mda.lifecycle != EquipmentLifecycle::initializing &&
        hardware.mda.lifecycle != EquipmentLifecycle::ready) {
      begin_initialization(hardware.mda, now, profile::mda_initialization);
    }
    if (hardware.mda.lifecycle == EquipmentLifecycle::initializing &&
        now >= hardware.mda.deadline) {
      hardware.mda.lifecycle = EquipmentLifecycle::ready;
    }
    hardware.mda.reason = hardware.mda.lifecycle == EquipmentLifecycle::ready
                              ? "none"
                              : "initializing-experimental";
    if (hardware.mda.lifecycle == EquipmentLifecycle::initializing) {
      next =
          next ? std::min(*next, hardware.mda.deadline) : hardware.mda.deadline;
    }
  }

  state.alarm_count = 0;
  const auto alarm = [&state](const char *id, const char *reason) {
    if (state.alarm_count < state.alarms.size()) {
      state.alarms[state.alarm_count++] = {id, "minor", reason};
    }
  };
  if (hardware.card.lifecycle != EquipmentLifecycle::ready) {
    alarm("card-1", hardware.card.reason);
  }
  if (hardware.card.present &&
      hardware.mda.lifecycle != EquipmentLifecycle::ready) {
    alarm("mda-1/1", hardware.mda.reason);
  }
  // Every port exposed by the equipped MDA participates in operational alarm
  // projection. This avoids silently treating ports beyond the starter links
  // as nonexistent while retaining fixed bounded storage.
  for (std::size_t index = 0; index < inventory_port_count(hardware); ++index) {
    if (!port_operational(running, hardware, index)) {
      alarm(profile::port_ids[index],
            !running.ports[index].admin_enabled
                ? "admin-down"
                : (!hardware.link_signal[index] ? "link-down"
                                                : "hardware-not-ready"));
    }
  }

  return {.operational_change =
              was_operational != operational(running, hardware),
          .next_deadline = next};
}

const char *lifecycle_name(EquipmentLifecycle value) noexcept {
  switch (value) {
  case EquipmentLifecycle::absent:
    return "absent";
  case EquipmentLifecycle::waiting_for_provisioning:
    return "waiting-provisioning";
  case EquipmentLifecycle::waiting_for_parent:
    return "waiting-parent";
  case EquipmentLifecycle::initializing:
    return "initializing";
  case EquipmentLifecycle::ready:
    return "ready";
  case EquipmentLifecycle::mismatch:
    return "mismatch";
  }
  return "unknown";
}

} // namespace router::hardware
