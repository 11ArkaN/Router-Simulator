// Control-owned device aggregates split by lifetime and mutation authority.
// Management may mutate configuration, hardware reconciliation may mutate
// inventory, and forwarding may return value projections into operational.

#pragma once

#include "router/cli_session.hpp"
#include "router/generated_profile.hpp"
#include "router/ospf_configuration.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace router {

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
  bool admin_enabled{};
  std::uint16_t mtu{profile::default_port_mtu};
  // One extra byte guarantees NUL termination for CLI and JSON projections.
  std::array<char, profile::port_description_bytes + 1U> description{};
  bool operator==(const PortConfiguration &) const = default;
};

struct InterfaceConfiguration {
  // valid separates configured interfaces from fixed-capacity storage. The
  // first milestone keeps the two profile-owned interface names, while port
  // binding and IPv4 addressing are ordinary datastore leaves. Storing their
  // numeric values avoids self-referential text pointers when candidate and
  // running configurations are copied during commit.
  bool valid{};
  const char *name{};
  packet::Mac mac{};
  packet::Ipv4 ipv4{};
  std::uint32_t network{};
  std::uint8_t prefix_length{};
  std::uint8_t port_index{};
  bool admin_enabled{};
  bool operator==(const InterfaceConfiguration &) const = default;
};

struct StaticRouteConfiguration {
  bool valid{};
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint8_t prefix_length{};
  // The classic next-hop context is administratively enabled by default.
  // Shutdown retains the configured path but removes it from route selection;
  // deletion is a separate operation and is accepted only for a disabled
  // path. The configured bit lets MD info distinguish an explicit leaf from
  // the effective default.
  bool admin_enabled{true};
  bool admin_state_configured{};
  bool operator==(const StaticRouteConfiguration &) const = default;
};

struct MdaConfiguration {
  // A null type means that the slot is not provisioned. The pointer always
  // targets generated profile storage, so candidate copies retain stable
  // identity without allocating or owning text.
  const char *type{};
  bool admin_enabled{true};
  bool operator==(const MdaConfiguration &) const = default;
};

struct CardConfiguration {
  // Card and MDA slots are fixed-capacity profile resources. Adding another
  // modeled slot changes generated dimensions instead of the configuration
  // object layout by hand.
  const char *type{};
  bool admin_enabled{true};
  std::array<MdaConfiguration, profile::mda_slots_per_card> mdas{};
  bool operator==(const CardConfiguration &) const = default;
};

struct DeviceConfiguration {
  // Provisioning is configuration, while presence and lifecycle belong to
  // HardwareState. Keeping them separate prevents a CLI command from equipping
  // hardware or a physical action from silently changing running config.
  std::array<CardConfiguration, profile::chassis_slots> cards{};
  std::array<char, profile::system_name_bytes + 1U> system_name{};
  std::array<PortConfiguration, profile::port_count> ports{};
  std::array<InterfaceConfiguration, profile::port_count> interfaces{};
  std::uint8_t interface_count{};
  std::array<StaticRouteConfiguration, profile::static_route_capacity>
      static_routes{};
  // OSPF instances are sparse configuration objects. Dynamic storage avoids
  // embedding all 96 release instance identifiers and every area in each
  // candidate copy while preserving ordinary value semantics at commit.
  ospf::RouterConfiguration ospf{};

  DeviceConfiguration() noexcept {
    std::copy_n(profile::default_system_name,
                std::char_traits<char>::length(profile::default_system_name),
                system_name.begin());
    // The initial routed interfaces are profile data, not a two-port limit in
    // the model. Remaining fixed-capacity slots can be filled by later CLI
    // commands without changing the configuration ABI or reallocating storage.
    interface_count =
        static_cast<std::uint8_t>(profile::interface_names.size());
    // Hardware discovery never enables ports. The saved starter project lists
    // its intentional no-shutdown state in profile data, while every other
    // port retains the SR OS administrative default of disabled.
    for (std::size_t index = 0; index < ports.size(); ++index)
      ports[index].admin_enabled = profile::initial_port_admin_enabled[index];
    for (std::size_t index = 0; index < interface_count; ++index) {
      interfaces[index] = {.valid = true,
                           .name = profile::interface_names[index],
                           .mac = profile::router_macs[index],
                           .ipv4 = profile::router_addresses[index],
                           .network = profile::router_networks[index],
                           .prefix_length = profile::host_prefix_lengths[index],
                           .port_index = profile::interface_port_indices[index],
                           .admin_enabled =
                               profile::initial_interface_admin_enabled[index]};
    }
  }

  bool operator==(const DeviceConfiguration &) const = default;
};

struct ConfigurationState {
  // Both datastores belong to control. MD-CLI mutates candidate and commits by
  // one bounded copy. Classic CLI mutates running and rebases candidate only
  // when the shared terminal session has no uncommitted MD changes.
  DeviceConfiguration running{};
  DeviceConfiguration candidate{running};
  // This is the device's running-versus-persisted indication used by the
  // classic prompt and system report. It is independent from MD candidate
  // dirtiness and remains true until a future admin save implementation.
  bool running_unsaved{};
};

struct EquipmentState {
  EquipmentLifecycle lifecycle{EquipmentLifecycle::absent};
  const char *reason{"not-equipped"};
  std::chrono::steady_clock::time_point deadline{};
};

struct MdaHardwareState {
  EquipmentState equipment{};
  const char *type{};
  bool compatible{true};
};

struct CardHardwareState {
  EquipmentState equipment{};
  const char *type{};
  bool compatible{true};
  std::array<MdaHardwareState, profile::mda_slots_per_card> mdas{};
};

struct HardwareState {
  // Physical carrier is stored for every port the equipped profile can expose.
  // Topology updates change this array through control and never mutate config.
  std::array<CardHardwareState, profile::chassis_slots> cards{};
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
  // from these values instead of relying on topology-specific endpoint enums.
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
                      .router_port = profile::link_port_indices[index],
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
  // Control reconstructs this monotonic deadline from the forwarding owner's
  // remaining-duration projection. No wall-clock adjustment can extend or
  // shorten adjacency lifetime.
  std::chrono::steady_clock::time_point expires_at{};
};

struct AlarmRecord {
  // Facility alarms retain their first raise time while the same condition is
  // active. Code and severity use Nokia's documented facility-alarm identity;
  // resource text is derived from the stable equipment ID at presentation.
  const char *id{};
  const char *severity{};
  const char *code{};
  const char *reason{};
  std::uint64_t raised_at_epoch_ms{};
};

struct OperationalState {
  // Operational projections are never copied into candidate configuration.
  // Their fixed capacities make forwarding acknowledgements bounded and keep
  // telemetry publication independent of heap allocation.
  std::array<PortCounters, profile::port_count> port_counters{};
  std::array<ArpEntry, profile::port_count> arp{};
  // Route age begins when a selected route first becomes active. Separate
  // fixed arrays follow the configuration keys, so rebuilding an unchanged
  // RIB retains age while withdrawal clears only the affected route clock.
  std::array<std::chrono::steady_clock::time_point, profile::port_count>
      connected_route_since{};
  std::array<std::chrono::steady_clock::time_point,
             profile::static_route_capacity>
      static_route_since{};
  // linkDown is a transition alarm, not a static reflection of carrier. The
  // first bit records that the admin-up facility has previously reached Up;
  // the second retains an active fault while a parent alarm temporarily masks
  // the child in the facility hierarchy.
  std::array<bool, profile::port_count> port_seen_operational{};
  std::array<bool, profile::port_count> port_link_alarm_active{};
  std::array<AlarmRecord, profile::port_count + 2> alarms{};
  std::uint8_t alarm_count{};
  std::uint64_t capture_count{};
  std::uint64_t dropped_packets{};
  std::uint64_t capture_dropped{};
  const char *last_drop_reason{};
  // Device uptime uses a local monotonic origin and is never restored as an
  // absolute host timestamp. A restored runtime therefore starts a new boot
  // interval, matching the lifecycle of the active emulator process.
  std::chrono::steady_clock::time_point started_at{
      std::chrono::steady_clock::now()};
};

// These accessors translate the active profile's external slot numbers to
// zero-based storage exactly once. Modules never encode slot 1 or MDA 1/1 in
// their own field names or array arithmetic.
inline CardConfiguration &
profile_card(DeviceConfiguration &configuration) noexcept {
  return configuration.cards[profile::line_card_index];
}
inline const CardConfiguration &
profile_card(const DeviceConfiguration &configuration) noexcept {
  return configuration.cards[profile::line_card_index];
}
inline MdaConfiguration &
profile_mda(DeviceConfiguration &configuration) noexcept {
  return profile_card(configuration).mdas[profile::mda_index];
}
inline const MdaConfiguration &
profile_mda(const DeviceConfiguration &configuration) noexcept {
  return profile_card(configuration).mdas[profile::mda_index];
}
inline CardHardwareState &profile_card(HardwareState &hardware) noexcept {
  return hardware.cards[profile::line_card_index];
}
inline const CardHardwareState &
profile_card(const HardwareState &hardware) noexcept {
  return hardware.cards[profile::line_card_index];
}
inline MdaHardwareState &profile_mda(HardwareState &hardware) noexcept {
  return profile_card(hardware).mdas[profile::mda_index];
}
inline const MdaHardwareState &
profile_mda(const HardwareState &hardware) noexcept {
  return profile_card(hardware).mdas[profile::mda_index];
}

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
    const auto &card = profile_card(configuration.running);
    const auto &mda = profile_mda(configuration.running);
    const auto &card_hardware = profile_card(hardware);
    const auto &mda_hardware = profile_mda(hardware);
    return card.type && mda.type && card_hardware.type && mda_hardware.type &&
           card.admin_enabled && mda.admin_enabled &&
           card_hardware.compatible && mda_hardware.compatible &&
           card_hardware.equipment.lifecycle == EquipmentLifecycle::ready &&
           mda_hardware.equipment.lifecycle == EquipmentLifecycle::ready;
  }

  [[nodiscard]] std::size_t inventory_port_count() const noexcept {
    // Port identities come from equipped compatible hardware. Removing an MDA
    // hides its ports but retains running config for later reinsertion.
    const auto &mda = profile_mda(hardware);
    return mda.type && mda.compatible ? profile::port_count : 0U;
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

} // namespace router
