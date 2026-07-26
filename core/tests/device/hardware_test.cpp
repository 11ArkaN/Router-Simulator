// Direct hardware boundary tests. They exercise lifecycle and all profile ports
// without entering CLI, runtime mailboxes, routing or forwarding.

#include "router/hardware.hpp"

#include <stdexcept>
#include <string_view>

void hardware_tests() {
  // Configuration expresses desired equipment while HardwareState represents
  // independent physical inventory. Reconcile is the sole owner of lifecycle.
  router::ConfigurationState configuration;
  router::HardwareState hardware;
  router::OperationalState operational;
  router::profile_card(configuration.running).type =
      router::profile::line_card_type;
  router::profile_mda(configuration.running).type =
      router::profile::modeled_mda_type;
  router::profile_card(hardware).type = router::profile::line_card_type;
  router::profile_mda(hardware).type = router::profile::modeled_mda_type;
  hardware.link_signal[0] = true;
  hardware.link_signal[1] = true;

  // A zero time point makes every expected deadline exact and reproducible.
  const auto origin = std::chrono::steady_clock::time_point{};
  const auto initial = router::hardware::reconcile(
      configuration.running, hardware, operational, origin);
  if (!initial.next_deadline ||
      router::profile_card(hardware).equipment.lifecycle !=
          router::EquipmentLifecycle::initializing ||
      router::profile_mda(hardware).equipment.lifecycle !=
          router::EquipmentLifecycle::waiting_for_parent) {
    throw std::runtime_error(
        "Hardware lifecycle did not respect parent readiness");
  }

  // At the card deadline the parent becomes ready and only then may the MDA
  // start its own initialization interval.
  const auto card_ready = router::hardware::reconcile(
      configuration.running, hardware, operational,
      origin + router::profile::card_initialization);
  if (!card_ready.next_deadline ||
      router::profile_card(hardware).equipment.lifecycle !=
          router::EquipmentLifecycle::ready ||
      router::profile_mda(hardware).equipment.lifecycle !=
          router::EquipmentLifecycle::initializing) {
    throw std::runtime_error("MDA initialization did not follow ready card");
  }

  // The final reconciliation exposes every modeled port. A port that has
  // never been Up does not raise linkDown merely because carrier is absent.
  const auto mda_ready = router::hardware::reconcile(
      configuration.running, hardware, operational,
      origin + router::profile::card_initialization +
          router::profile::mda_initialization);
  if (mda_ready.next_deadline ||
      !router::hardware::operational(configuration.running, hardware) ||
      router::hardware::inventory_port_count(hardware) !=
          router::profile::port_count ||
      operational.alarm_count != 0) {
    throw std::runtime_error(
        "Hardware inventory or facility-alarm separation is invalid");
  }

  // Facility alarm 59-2004-1 represents a real Up-to-Down transition. It is a
  // Warning by default and clears when the operator administratively disables
  // the port, because that down state is then deliberate.
  hardware.link_signal[0] = false;
  const auto link_down = router::hardware::reconcile(
      configuration.running, hardware, operational,
      origin + router::profile::card_initialization +
          router::profile::mda_initialization);
  (void)link_down;
  if (operational.alarm_count != 1 ||
      std::string_view{operational.alarms[0].code} != "59-2004-1" ||
      std::string_view{operational.alarms[0].severity} != "warning") {
    throw std::runtime_error("linkDown transition alarm was not preserved");
  }
  configuration.running.ports[0].admin_enabled = false;
  const auto admin_down = router::hardware::reconcile(
      configuration.running, hardware, operational,
      origin + router::profile::card_initialization +
          router::profile::mda_initialization);
  (void)admin_down;
  if (operational.alarm_count != 0 || operational.port_link_alarm_active[0]) {
    throw std::runtime_error("Administrative shutdown did not clear linkDown");
  }

  // The CHASSIS event catalog assigns different default severities to removal
  // and wrong-type insertion. Mismatch is MINOR even though removal is MAJOR.
  router::profile_mda(hardware).type = router::profile::supported_mda_types[1];
  router::profile_mda(configuration.running).admin_enabled = true;
  const auto mismatch = router::hardware::reconcile(
      configuration.running, hardware, operational,
      origin + router::profile::card_initialization +
          router::profile::mda_initialization);
  (void)mismatch;
  if (operational.alarm_count != 1 ||
      std::string_view{operational.alarms[0].code} != "7-2004-1" ||
      std::string_view{operational.alarms[0].severity} != "minor") {
    throw std::runtime_error("Wrong-card alarm did not retain MINOR severity");
  }
  // Reconciliation receives no candidate reference. This assertion guards the
  // datastore boundary against future broad DeviceState parameters.
  if (router::profile_card(configuration.candidate).type ||
      router::profile_mda(configuration.candidate).type) {
    throw std::runtime_error(
        "Hardware reconciliation mutated candidate configuration");
  }
}
