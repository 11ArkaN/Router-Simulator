// Profile-driven hardware lifecycle and alarm projection. The control shard is
// the sole caller and owner. This module depends on device values but has no
// dependency on CLI, routing, forwarding, capture or UI representations.

#include "router/hardware.hpp"

#include <algorithm>
#include <chrono>
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

  const auto previous_alarms = state.alarms;
  const auto previous_alarm_count = state.alarm_count;
  state.alarm_count = 0;
  const auto alarm = [&state, &previous_alarms, previous_alarm_count](
                         const char *id, const char *severity, const char *code,
                         const char *reason) {
    // Alarm storage is bounded by generated ports plus equipment records. The
    // guard remains defensive and never writes beyond the control projection.
    if (state.alarm_count < state.alarms.size()) {
      std::uint64_t raised_at{};
      for (std::size_t index = 0; index < previous_alarm_count; ++index) {
        const auto &previous = previous_alarms[index];
        if (previous.id && previous.reason &&
            std::strcmp(previous.id, id) == 0 &&
            std::strcmp(previous.reason, reason) == 0) {
          raised_at = previous.raised_at_epoch_ms;
          break;
        }
      }
      if (!raised_at) {
        raised_at = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
      }
      state.alarms[state.alarm_count++] = {id, severity, code, reason,
                                           raised_at};
    }
  };
  if (card_config.type && card_config.admin_enabled &&
      (card.equipment.lifecycle == EquipmentLifecycle::absent ||
       card.equipment.lifecycle == EquipmentLifecycle::mismatch)) {
    // Source: nokia.sros.26_7.hardware_alarm_events. The two conditions use
    // distinct default severities even though they share equipment storage.
    alarm(profile::line_card_alarm_id,
          card.equipment.lifecycle == EquipmentLifecycle::mismatch ? "minor"
                                                                   : "major",
          card.equipment.lifecycle == EquipmentLifecycle::mismatch ? "7-2004-1"
                                                                   : "7-2003-1",
          card.equipment.reason);
  }
  if (mda_config.type && mda_config.admin_enabled &&
      (mda.equipment.lifecycle == EquipmentLifecycle::absent ||
       mda.equipment.lifecycle == EquipmentLifecycle::mismatch)) {
    alarm(profile::mda_alarm_id,
          mda.equipment.lifecycle == EquipmentLifecycle::mismatch ? "minor"
                                                                  : "major",
          mda.equipment.lifecycle == EquipmentLifecycle::mismatch ? "7-2004-1"
                                                                  : "7-2003-1",
          mda.equipment.reason);
  }

  // Source: nokia.sros.26_7.facility_alarms. Alarm 59-2004-1 is
  // raised only after ifOperStatus leaves an operational state, never merely
  // because a newly discovered or administratively disabled port is Down.
  // Parent failures mask an existing child alarm without destroying it.
  const auto parent_operational = operational(running, hardware);
  const auto inventory_count = inventory_port_count(hardware);
  for (std::size_t index = 0; index < running.ports.size(); ++index) {
    const auto admin_up = running.ports[index].admin_enabled;
    const auto parent_visible = parent_operational && index < inventory_count;
    const auto currently_up =
        parent_visible && admin_up && hardware.link_signal[index];
    if (!admin_up) {
      state.port_seen_operational[index] = false;
      state.port_link_alarm_active[index] = false;
    } else if (currently_up) {
      state.port_seen_operational[index] = true;
      state.port_link_alarm_active[index] = false;
    } else if (parent_visible && state.port_seen_operational[index]) {
      state.port_link_alarm_active[index] = true;
    }
    if (parent_visible && state.port_link_alarm_active[index]) {
      alarm(profile::port_ids[index], "warning", "59-2004-1", "link-down");
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
