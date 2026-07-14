// Direct hardware boundary tests. They exercise lifecycle and all profile ports
// without entering CLI, runtime mailboxes, routing or forwarding.

#include "router/hardware.hpp"

#include <stdexcept>

void hardware_tests() {
  router::ConfigurationState configuration;
  router::HardwareState hardware;
  router::OperationalState operational;
  configuration.running.card_provisioned = true;
  configuration.running.mda_provisioned = true;
  hardware.card.present = true;
  hardware.mda.present = true;
  hardware.link_signal[0] = true;
  hardware.link_signal[1] = true;
  const auto origin = std::chrono::steady_clock::time_point{};
  const auto initial = router::hardware::reconcile(
      configuration.running, hardware, operational, origin);
  if (!initial.next_deadline ||
      hardware.card.lifecycle != router::EquipmentLifecycle::initializing ||
      hardware.mda.lifecycle !=
          router::EquipmentLifecycle::waiting_for_parent) {
    throw std::runtime_error(
        "Hardware lifecycle did not respect parent readiness");
  }
  const auto card_ready = router::hardware::reconcile(
      configuration.running, hardware, operational,
      origin + router::profile::card_initialization);
  if (!card_ready.next_deadline ||
      hardware.card.lifecycle != router::EquipmentLifecycle::ready ||
      hardware.mda.lifecycle != router::EquipmentLifecycle::initializing) {
    throw std::runtime_error("MDA initialization did not follow ready card");
  }
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
  if (configuration.candidate.card_provisioned ||
      configuration.candidate.mda_provisioned) {
    throw std::runtime_error(
        "Hardware reconciliation mutated candidate configuration");
  }
}
