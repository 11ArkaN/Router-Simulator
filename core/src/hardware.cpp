// Profile-driven hardware lifecycle and alarm projection. The control shard is
// the sole caller and owner. This module depends on device values but has no
// dependency on CLI, routing, forwarding, capture or UI representations.

#include "router/hardware.hpp"

#include <algorithm>
#include <cstring>

namespace router::hardware {
namespace {

using Clock = std::chrono::steady_clock;

void begin_initialization(EquipmentState &equipment, Clock::time_point now,
                          Clock::duration delay) noexcept {
  // Initialization owns a real steady-clock deadline. Reconciliation may poll
  // it but cannot advance, scale or replace host time.
  equipment.lifecycle = EquipmentLifecycle::initializing;
  equipment.deadline = now + delay;
}

} // namespace

bool operational(const DeviceConfiguration &running,
                 const HardwareState &hardware) noexcept {
  // A usable forwarding complex requires matching provisioned and equipped
  // parent and child inventory, admin enablement and completed lifecycles.
  const auto &card = profile_card(running);
  const auto &mda = profile_mda(running);
  const auto &card_hardware = profile_card(hardware);
  const auto &mda_hardware = profile_mda(hardware);
  return card.type && mda.type && card_hardware.type && mda_hardware.type &&
         card.admin_enabled && mda.admin_enabled && card_hardware.compatible &&
         mda_hardware.compatible &&
         card_hardware.equipment.lifecycle == EquipmentLifecycle::ready &&
         mda_hardware.equipment.lifecycle == EquipmentLifecycle::ready;
}

std::size_t inventory_port_count(const HardwareState &hardware) noexcept {
  // Port inventory belongs to compatible equipped MDA hardware. Provisioning
  // alone retains config but does not manufacture physical ports.
  const auto &mda = profile_mda(hardware);
  return mda.type && mda.compatible ? profile::port_count : 0U;
}

bool port_operational(const DeviceConfiguration &running,
                      const HardwareState &hardware,
                      std::size_t index) noexcept {
  // A port is operational only when inventory, parent hardware, port admin and
  // physical carrier all agree. No editor edge directly sets this result.
  return index < inventory_port_count(hardware) &&
         operational(running, hardware) && running.ports[index].admin_enabled &&
         hardware.link_signal[index];
}

ReconcileResult reconcile(const DeviceConfiguration &running,
                          HardwareState &hardware, OperationalState &state,
                          Clock::time_point now) noexcept {
  // Control is the sole caller and owner of every mutated field. The function
  // computes one deterministic lifecycle projection from current time and
  // state.
  const bool was_operational = operational(running, hardware);
  std::optional<Clock::time_point> next;
  const auto &card_config = profile_card(running);
  const auto &mda_config = profile_mda(running);
  auto &card = profile_card(hardware);
  auto &mda = profile_mda(hardware);
  card.compatible = !card.type || !card_config.type ||
                    std::strcmp(card.type, card_config.type) == 0;
  mda.compatible = !mda.type || !mda_config.type ||
                   std::strcmp(mda.type, mda_config.type) == 0;

  if (!card.type) {
    // Absence clears old deadlines so reinsertion starts a fresh generation.
    card.equipment.lifecycle = EquipmentLifecycle::absent;
    card.equipment.reason = "not-equipped";
    card.equipment.deadline = {};
  } else if (!card.compatible) {
    // Equipped inventory is retained in mismatch for diagnostics but cannot
    // create forwarding ports or progress through initialization.
    card.equipment.lifecycle = EquipmentLifecycle::mismatch;
    card.equipment.reason = "inventory-provisioning-mismatch";
    card.equipment.deadline = {};
  } else if (!card_config.type || !card_config.admin_enabled) {
    card.equipment.lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    card.equipment.reason =
        card_config.admin_enabled ? "not-provisioned" : "admin-down";
    card.equipment.deadline = {};
  } else {
    if (card.equipment.lifecycle != EquipmentLifecycle::initializing &&
        card.equipment.lifecycle != EquipmentLifecycle::ready) {
      begin_initialization(card.equipment, now, profile::card_initialization);
    }
    if (card.equipment.lifecycle == EquipmentLifecycle::initializing &&
        now >= card.equipment.deadline) {
      card.equipment.lifecycle = EquipmentLifecycle::ready;
    }
    card.equipment.reason =
        card.equipment.lifecycle == EquipmentLifecycle::ready
            ? "none"
            : "initializing-experimental";
    if (card.equipment.lifecycle == EquipmentLifecycle::initializing) {
      next = card.equipment.deadline;
    }
  }

  if (!mda.type) {
    // Child absence is independent from retained MDA provisioning.
    mda.equipment.lifecycle = EquipmentLifecycle::absent;
    mda.equipment.reason = "not-equipped";
    mda.equipment.deadline = {};
  } else if (!mda.compatible) {
    mda.equipment.lifecycle = EquipmentLifecycle::mismatch;
    mda.equipment.reason = "inventory-provisioning-mismatch";
    mda.equipment.deadline = {};
  } else if (!mda_config.type || !mda_config.admin_enabled) {
    mda.equipment.lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    mda.equipment.reason =
        mda_config.admin_enabled ? "not-provisioned" : "admin-down";
    mda.equipment.deadline = {};
  } else if (card.equipment.lifecycle != EquipmentLifecycle::ready) {
    // Child initialization cannot overlap parent initialization. Waiting has no
    // deadline until the next reconciliation observes a ready parent.
    mda.equipment.lifecycle = EquipmentLifecycle::waiting_for_parent;
    mda.equipment.reason = "parent-not-ready";
    mda.equipment.deadline = {};
  } else {
    if (mda.equipment.lifecycle != EquipmentLifecycle::initializing &&
        mda.equipment.lifecycle != EquipmentLifecycle::ready) {
      begin_initialization(mda.equipment, now, profile::mda_initialization);
    }
    if (mda.equipment.lifecycle == EquipmentLifecycle::initializing &&
        now >= mda.equipment.deadline) {
      mda.equipment.lifecycle = EquipmentLifecycle::ready;
    }
    mda.equipment.reason = mda.equipment.lifecycle == EquipmentLifecycle::ready
                               ? "none"
                               : "initializing-experimental";
    if (mda.equipment.lifecycle == EquipmentLifecycle::initializing) {
      next = next ? std::min(*next, mda.equipment.deadline)
                  : mda.equipment.deadline;
    }
  }

  state.alarm_count = 0;
  const auto alarm = [&state](const char *id, const char *reason) {
    // Alarm storage is bounded by generated ports plus equipment records. The
    // guard remains defensive and never writes beyond the control projection.
    if (state.alarm_count < state.alarms.size()) {
      state.alarms[state.alarm_count++] = {id, "minor", reason};
    }
  };
  if (card.equipment.lifecycle != EquipmentLifecycle::ready) {
    alarm(profile::line_card_alarm_id, card.equipment.reason);
  }
  if (card.type && mda.equipment.lifecycle != EquipmentLifecycle::ready) {
    alarm(profile::mda_alarm_id, mda.equipment.reason);
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
  // JSON and CLI share one stable spelling for every internal lifecycle value.
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
