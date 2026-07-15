// Direct hardware boundary tests. They exercise lifecycle and all profile ports
// without entering CLI, runtime mailboxes, routing or forwarding.

#include "router/hardware.hpp"

#include <stdexcept>

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

  // The final reconciliation exposes all modeled ports. Only the two signaled
  // links are up, so remaining ports must contribute explicit alarms.
  const auto mda_ready = router::hardware::reconcile(
      configuration.running, hardware, operational,
      origin + router::profile::card_initialization +
          router::profile::mda_initialization);
  if (mda_ready.next_deadline ||
      !router::hardware::operational(configuration.running, hardware) ||
      router::hardware::inventory_port_count(hardware) !=
          router::profile::port_count ||
      operational.alarm_count != router::profile::port_count - 2) {
    throw std::runtime_error(
        "Hardware did not expose or alarm every profile port");
  }
  // Reconciliation receives no candidate reference. This assertion guards the
  // datastore boundary against future broad DeviceState parameters.
  if (router::profile_card(configuration.candidate).type ||
      router::profile_mda(configuration.candidate).type) {
    throw std::runtime_error(
        "Hardware reconciliation mutated candidate configuration");
  }
}
