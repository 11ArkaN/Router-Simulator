// Local AF value events update instance-owned assignment and Hello gates.
// One IS-IS control writer owns every mutation; forwarding state is never read.
// The network subscriber owner filters obsolete configuration generations.
#include "router/isis_control_worker.hpp"
#include <algorithm>
#include <limits>
#include <tuple>
namespace router::isis {
ControlError ControlWorker::validate_local_af_subscription(ControlCommand &command, const DeviceState &device) noexcept {
  if (!command.local_ipv6_watches) return ControlError::none;
  if (command.new_instances.size() > device.instances.size() ||
      command.local_ipv6_watches->size() > device_catalog::ipv6_dad_entries_per_node) return ControlError::capacity;
  const auto origin = [&](std::size_t index) -> const LocalOriginProgram * {
    const auto replacement = std::find_if(command.new_instances.begin(), command.new_instances.end(),
        [index](const auto &entry) { return entry.instance == index; });
    if (replacement != command.new_instances.end())
      return replacement->program.origination ? &*replacement->program.origination : nullptr;
    if (std::binary_search(command.retired_instances.begin(), command.retired_instances.end(), index) ||
        !device.instances[index] || !device.instances[index]->configuration.origination) return nullptr;
    return &*device.instances[index]->configuration.origination;
  };
  const auto key = [](const lab::Ipv6ReadinessWatch &watch) { return std::tie(watch.interface_id, watch.address); };
  try {
    std::vector<lab::Ipv6ReadinessWatch> expected;
    expected.reserve(device_catalog::ipv6_dad_entries_per_node);
    for (std::size_t index{}; index < device.instances.size(); ++index) {
      const auto *program = origin(index);
      if (!program || !program->ipv6_addresses) continue;
      for (const auto &unit : program->ipv6_addresses->units) if (unit.source.physical_port) {
        const lab::Ipv6ReadinessWatch watch{unit.source.interface_id, *unit.source.physical_port, unit.source.address};
        const auto at = std::lower_bound(expected.begin(), expected.end(), watch,
            [&](const auto &a, const auto &b) { return key(a) < key(b); });
        if (at != expected.end() && key(*at) == key(watch)) { if (*at != watch) return ControlError::invalid_argument; }
        else {
          if (expected.size() == device_catalog::ipv6_dad_entries_per_node) return ControlError::capacity;
          expected.insert(at, watch);
        }
      }
    }
    auto &supplied = *command.local_ipv6_watches;
    std::sort(supplied.begin(), supplied.end(), [&](const auto &a, const auto &b) { return key(a) < key(b); });
    if (supplied != expected) return ControlError::invalid_argument;
    for (auto &circuit : command.circuits) {
      if (circuit.identity.instance >= device.instances.size()) return ControlError::invalid_argument;
      const auto *program = origin(circuit.identity.instance);
      if (!program || !program->ipv6_addresses) continue;
      const auto *hello = circuit.common();
      if (!hello) return ControlError::invalid_argument;
      for (const auto &address : hello->ipv6_addresses)
        if (std::none_of(program->ipv6_addresses->units.begin(), program->ipv6_addresses->units.end(), [&](const auto &unit) {
          return unit.source.interface_id == circuit.identity.interface_id && unit.source.address == address &&
              unit.source.physical_port == circuit.identity.physical_port_ordinal;
        })) return ControlError::invalid_argument;
      const bool ready = circuit.carrier && local_ipv6_hello_available(*program->ipv6_addresses,
          circuit.identity.interface_id, hello->ipv6_addresses);
      // Readiness may advance after the datastore captures a retained circuit.
      // Derive this mutable AF gate from the selected owner, preserving its
      // immutable circuit identity and the exact configured address candidates.
      if (circuit.broadcast) {
        for (auto &level : circuit.broadcast->levels) if (level) level->ipv6_addresses_ready = ready;
      } else circuit.configuration.ipv6_addresses_ready = ready;
    }
    return ControlError::none;
  } catch (const std::bad_alloc &) { return ControlError::capacity; }
}

void ControlWorker::refresh_local_ipv6_hello(DeviceState &device, std::size_t index,
    std::uint64_t interface_id) noexcept {
  auto &instance = *device.instances[index];
  const auto &origin = *instance.configuration.origination;
  if (!origin.ipv6_addresses) return;
  for (auto &owned : device.circuits) if (owned.identity.instance == index && owned.identity.interface_id == interface_id) {
    const bool ready = owned.carrier && local_ipv6_hello_available(*origin.ipv6_addresses, interface_id, owned.common().ipv6_addresses);
    bool changed{};
    if (auto *lan = owned.lan()) {
      for (std::size_t level{}; level < 2U; ++level) if (auto *circuit = lan->at(level))
        changed = circuit->set_ipv6_addresses_ready(ready) || changed;
    } else changed = owned.p2p().set_ipv6_addresses_ready(ready);
    if (changed) for (std::size_t level{}; level < 2U; ++level) if (instance.configuration.levels[level]) {
      if (instance.decision_revisions[level] == std::numeric_limits<std::uint64_t>::max())
        instance.status = UpdateStatus::epoch_exhausted;
      else ++instance.decision_revisions[level];
    }
  }
}
ControlError ControlWorker::apply_local_ipv6_readiness(DeviceState &device,
    const lab::Ipv6ReadinessChange &change) noexcept {
  if (change.version != 1U || change.device != device.handle || !change.configuration_generation ||
      !change.source.interface_id || change.source.port_ordinal >= device_catalog::maximum_ports_per_router)
    return ControlError::invalid_argument;
  bool found{};
  for (std::size_t index{}; index < device.instances.size(); ++index) {
    auto &instance = device.instances[index];
    if (!instance || !instance->configuration.origination) continue;
    auto &origin = *instance->configuration.origination;
    if (!origin.ipv6_addresses || !origin.prefixes) continue;
    const auto address = std::find_if(origin.ipv6_addresses->units.begin(), origin.ipv6_addresses->units.end(), [&](const auto &unit) {
      return unit.source.interface_id == change.source.interface_id && unit.source.physical_port == change.source.port_ordinal &&
          unit.source.address == change.source.address;
    });
    if (address == origin.ipv6_addresses->units.end()) continue;
    found = true;
    const auto interface = std::lower_bound(origin.prefixes->interfaces.begin(), origin.prefixes->interfaces.end(),
        change.source.interface_id, [](const auto &entry, auto id) { return entry.interface_id < id; });
    if (interface == origin.prefixes->interfaces.end() || interface->interface_id != change.source.interface_id)
      return ControlError::invalid_argument;
    // Assignment and carrier are independent owner projections. A DAD-disabled
    // address can become assigned in the forwarding command before its carrier
    // acknowledgement reaches this owner. Composition still ANDs both gates.
    const bool preferred = change.preferred;
    if (set_local_ipv6_address_ready(*origin.ipv6_addresses, change.source.interface_id,
        change.source.port_ordinal, change.source.address, preferred)) {
      instance->local_roots_dirty.fill(true);
      refresh_local_ipv6_hello(device, index, change.source.interface_id);
    }
  }
  return found ? ControlError::none : ControlError::not_found;
}
}
