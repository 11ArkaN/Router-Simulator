// Control-owned device aggregates split by lifetime and mutation authority.
// Management may mutate configuration, hardware reconciliation may mutate
// inventory, and forwarding may return value projections into operational.

#pragma once

#include "router/generated_profile.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace router {

enum class CliEngine : std::uint8_t { md, classic };
enum class EquipmentLifecycle : std::uint8_t {
  absent,
  waiting_for_provisioning,
  waiting_for_parent,
  initializing,
  ready,
  mismatch
};

struct PortConfiguration {
  // Configuration contains no physical carrier or counters. A complete value
  // can therefore be copied between running and candidate atomically on the
  // control shard without copying runtime observations.
  bool admin_enabled{true};
  std::uint16_t mtu{1500};
  std::array<char, 65> description{};
  bool operator==(const PortConfiguration &) const = default;
};

struct InterfaceConfiguration {
  // valid separates configured interfaces from fixed-capacity storage. The
  // port index is a stable profile handle and never points into movable memory.
  bool valid{};
  const char *name{};
  const char *address{};
  const char *prefix{};
  packet::Mac mac{};
  packet::Ipv4 ipv4{};
  std::uint32_t network{};
  std::uint8_t prefix_length{};
  std::uint8_t port_index{};
  bool admin_enabled{true};
};

struct StaticRouteConfiguration {
  bool valid{};
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint8_t prefix_length{};
  bool operator==(const StaticRouteConfiguration &) const = default;
};

struct DeviceConfiguration {
  // Provisioning is configuration, while presence and lifecycle belong to
  // HardwareState. Keeping them separate prevents a CLI command from equipping
  // hardware or a physical action from silently changing running config.
  bool card_provisioned{};
  bool mda_provisioned{};
  bool card_admin_enabled{true};
  bool mda_admin_enabled{true};
  std::array<char, 65> system_name{'R', '1', '\0'};
  std::array<PortConfiguration, profile::port_count> ports{};
  std::array<InterfaceConfiguration, profile::port_count> interfaces{};
  std::uint8_t interface_count{};
  std::array<StaticRouteConfiguration, 8> static_routes{};

  DeviceConfiguration() noexcept {
    // The initial routed interfaces are profile data, not a two-port limit in
    // the model. Remaining fixed-capacity slots can be filled by later CLI
    // commands without changing the configuration ABI or reallocating storage.
    interface_count =
        static_cast<std::uint8_t>(profile::interface_names.size());
    for (std::size_t index = 0; index < interface_count; ++index) {
      interfaces[index] = {.valid = true,
                           .name = profile::interface_names[index],
                           .address = profile::interface_addresses[index],
                           .prefix = profile::interface_prefixes[index],
                           .mac = profile::router_macs[index],
                           .ipv4 = profile::router_addresses[index],
                           .network = profile::router_networks[index],
                           .prefix_length = profile::host_prefix_lengths[index],
                           .port_index = static_cast<std::uint8_t>(index),
                           .admin_enabled = true};
    }
  }
};

struct ConfigurationState {
  // Both datastores belong to control. MD-CLI mutates candidate and commits by
  // one bounded copy. Classic CLI mutates running and rebases candidate only
  // when the shared terminal session has no uncommitted MD changes.
  DeviceConfiguration running{};
  DeviceConfiguration candidate{running};
};

struct EquipmentState {
  bool present{};
  bool compatible{true};
  EquipmentLifecycle lifecycle{EquipmentLifecycle::absent};
  const char *reason{"not-equipped"};
  std::chrono::steady_clock::time_point deadline{};
};

struct HardwareState {
  // Physical carrier is stored for every port the equipped profile can expose.
  // Topology updates change this array through control and never mutate config.
  EquipmentState card{};
  EquipmentState mda{};
  std::array<bool, profile::port_count> link_signal{};
};

struct LabHostConfiguration {
  std::array<std::uint8_t, 6> mac{};
  std::array<std::uint8_t, 4> address{};
  std::uint8_t prefix_length{};
  std::array<std::uint8_t, 4> gateway{};
};

struct LabLinkConfiguration {
  // A link binds one endpoint to a router port. Forwarding builds directions
  // from these values instead of relying on host-a and host-b enum constants.
  bool connected{};
  std::uint8_t router_port{};
  std::chrono::nanoseconds propagation{profile::default_link_propagation};
};

struct ProjectState {
  // The starter profile has two endpoints, but code derives capacity from the
  // generated profile arrays and does not embed the number in data-plane APIs.
  static constexpr std::size_t endpoint_count = profile::host_macs.size();
  std::array<LabHostConfiguration, endpoint_count> hosts{};
  std::array<LabLinkConfiguration, endpoint_count> links{};

  ProjectState() noexcept {
    for (std::size_t index = 0; index < endpoint_count; ++index) {
      hosts[index] = {profile::host_macs[index], profile::host_addresses[index],
                      profile::host_prefix_lengths[index],
                      profile::host_gateways[index]};
      links[index] = {.connected = true,
                      .router_port = static_cast<std::uint8_t>(index),
                      .propagation = profile::default_link_propagation};
    }
  }
};

struct PortCounters {
  std::uint64_t rx_packets{};
  std::uint64_t tx_packets{};
};

struct ArpEntry {
  bool valid{};
  std::array<std::uint8_t, 4> address{};
  std::array<std::uint8_t, 6> mac{};
  std::uint8_t port_index{};
};

struct AlarmRecord {
  const char *id{};
  const char *severity{};
  const char *reason{};
};

struct OperationalState {
  // Operational projections are never copied into candidate configuration.
  // Their fixed capacities make forwarding acknowledgements bounded and keep
  // telemetry publication independent of heap allocation.
  std::array<PortCounters, profile::port_count> port_counters{};
  std::array<ArpEntry, profile::port_count> arp{};
  std::array<AlarmRecord, profile::port_count + 2> alarms{};
  std::uint8_t alarm_count{};
  std::uint64_t capture_count{};
  std::uint64_t dropped_packets{};
  std::uint64_t capture_dropped{};
  const char *last_drop_reason{};
};

struct DeviceState {
  // DeviceState is the control-shard aggregate root, not a flat shared state
  // bag. Callers should accept the narrow substate they need whenever possible.
  ConfigurationState configuration{};
  HardwareState hardware{};
  ProjectState project{};
  OperationalState operational{};

  DeviceState() noexcept {
    // Initial carrier follows the persisted starter topology. Unequipped ports
    // remain invisible even when a project link is already present.
    for (const auto &link : project.links) {
      if (link.connected && link.router_port < hardware.link_signal.size()) {
        hardware.link_signal[link.router_port] = true;
      }
    }
  }

  [[nodiscard]] bool hardware_operational() const noexcept {
    const auto &running = configuration.running;
    return running.card_provisioned && running.mda_provisioned &&
           hardware.card.present && hardware.mda.present &&
           running.card_admin_enabled && running.mda_admin_enabled &&
           hardware.mda.compatible &&
           hardware.card.lifecycle == EquipmentLifecycle::ready &&
           hardware.mda.lifecycle == EquipmentLifecycle::ready;
  }

  [[nodiscard]] std::size_t inventory_port_count() const noexcept {
    // Port identities come from equipped compatible hardware. Removing an MDA
    // hides its ports but retains running config for later reinsertion.
    return hardware.mda.present && hardware.mda.compatible ? profile::port_count
                                                           : 0U;
  }

  [[nodiscard]] bool port_operational(std::size_t index) const noexcept {
    return index < inventory_port_count() && hardware_operational() &&
           configuration.running.ports[index].admin_enabled &&
           hardware.link_signal[index];
  }

  [[nodiscard]] bool interface_operational(std::size_t index) const noexcept {
    if (index >= configuration.running.interface_count)
      return false;
    const auto &interface = configuration.running.interfaces[index];
    return interface.valid && interface.admin_enabled &&
           port_operational(interface.port_index);
  }

  [[nodiscard]] bool routed_path_operational() const noexcept {
    // The starter diagnostic requires every configured endpoint-facing routed
    // interface. Generic forwarding itself evaluates ports independently.
    for (std::size_t index = 0; index < project.links.size(); ++index) {
      if (project.links[index].connected && !interface_operational(index))
        return false;
    }
    return true;
  }
};

struct CliSession {
  // MD and classic are engines in one router terminal session. Switching does
  // not create another device or a global application mode.
  CliEngine engine{CliEngine::md};
  bool candidate_dirty{};
  // Classic writes may advance running while an MD candidate is dirty. The
  // flag rejects a stale commit rather than silently rebasing or discarding it.
  bool candidate_outdated{};
};

} // namespace router
