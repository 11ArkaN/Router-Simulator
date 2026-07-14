// Control-owned canonical device, hardware, configuration and CLI session data.
// Forwarding receives immutable value programs and never mutates these objects.

#pragma once

#include "router/generated_profile.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

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

struct DeviceState {
  // DeviceState belongs exclusively to the control shard. Forwarding reports
  // immutable counter and adjacency deltas instead of mutating this object.
  struct Port {
    const char* id;
    bool admin_enabled{true};
    bool link_signal{};
    std::uint16_t mtu{1500};
    std::array<char, 65> description{};
    bool candidate_admin_enabled{true};
    std::uint16_t candidate_mtu{1500};
    std::array<char, 65> candidate_description{};
    std::uint64_t rx_packets{};
    std::uint64_t tx_packets{};
  };

  struct Interface {
    // port_index is stable within a release profile and avoids pointers that
    // would become invalid if the platform profile storage moved.
    const char* name;
    const char* address;
    const char* prefix;
    std::uint8_t port_index;
    bool admin_enabled{true};
    bool candidate_admin_enabled{true};
  };

  struct ArpEntry {
    bool valid{};
    std::array<std::uint8_t, 4> address{};
    std::array<std::uint8_t, 6> mac{};
    std::uint8_t port_index{};
  };

  struct LabHost {
    // This is the control-plane copy of project endpoint configuration. The
    // forwarding owner receives value messages and keeps independent protocol
    // state such as ARP caches and pending packets.
    std::array<std::uint8_t, 6> mac{};
    std::array<std::uint8_t, 4> address{};
    std::uint8_t prefix_length{};
    std::array<std::uint8_t, 4> gateway{};
  };

  struct StaticRoute {
    bool valid{};
    bool candidate_valid{};
    std::uint32_t network{};
    std::uint32_t candidate_network{};
    std::uint32_t next_hop{};
    std::uint32_t candidate_next_hop{};
    std::uint8_t prefix_length{};
    std::uint8_t candidate_prefix_length{};
  };

  struct AlarmRecord {
    const char* id{};
    const char* severity{};
    const char* reason{};
  };

  // Provisioning and physical equipment are separate. CLI changes provisioning
  // while hardware actions change only equipped state.
  bool card_provisioned{};
  bool mda_provisioned{};
  bool card_present{};
  bool mda_present{};
  bool mda_compatible{true};
  bool candidate_card{};
  bool candidate_mda{};
  bool card_admin_enabled{true};
  bool mda_admin_enabled{true};
  EquipmentLifecycle card_lifecycle{EquipmentLifecycle::absent};
  EquipmentLifecycle mda_lifecycle{EquipmentLifecycle::absent};
  const char* card_reason{"not-equipped"};
  const char* mda_reason{"not-equipped"};
  std::chrono::steady_clock::time_point card_deadline{};
  std::chrono::steady_clock::time_point mda_deadline{};
  std::array<char, 65> system_name{'R', '1', '\0'};
  std::array<char, 65> candidate_system_name{'R', '1', '\0'};
  std::array<Port, profile::port_count> ports{{
      {profile::port_ids[0]}, {profile::port_ids[1]}, {profile::port_ids[2]},
      {profile::port_ids[3]}, {profile::port_ids[4]}, {profile::port_ids[5]},
      {profile::port_ids[6]}, {profile::port_ids[7]}, {profile::port_ids[8]},
      {profile::port_ids[9]},
  }};
  std::array<Interface, 2> interfaces{{
      {profile::interface_names[0], profile::interface_addresses[0],
       profile::interface_prefixes[0], 0},
      {profile::interface_names[1], profile::interface_addresses[1],
       profile::interface_prefixes[1], 1},
  }};
  std::array<LabHost, 2> lab_hosts{{
      {profile::host_macs[0], profile::host_addresses[0],
       profile::host_prefix_lengths[0], profile::host_gateways[0]},
      {profile::host_macs[1], profile::host_addresses[1],
       profile::host_prefix_lengths[1], profile::host_gateways[1]},
  }};
  std::array<StaticRoute, 8> static_routes{};
  std::uint64_t capture_count{};
  std::uint64_t dropped_packets{};
  std::uint64_t capture_dropped{};
  const char* last_drop_reason{};
  std::array<AlarmRecord, 8> alarms{};
  std::uint8_t alarm_count{};
  // Bit 0 belongs to Host A and bit 1 to Host B. The adjacency manager is part
  // of the control owner, while forwarding reports learned entries as deltas.
  std::array<ArpEntry, 2> arp{};

  DeviceState() noexcept {
    // The starter project wires only the first two physical ports. Remaining
    // ports appear when the MDA is equipped but have no carrier until a user
    // adds a physical link to them.
    ports[0].link_signal = true;
    ports[1].link_signal = true;
  }

  [[nodiscard]] bool hardware_operational() const noexcept {
    // Administrative port state alone is insufficient. Card presence, MDA
    // presence, and profile compatibility gate every dependent port.
    return card_provisioned && mda_provisioned && card_present && mda_present &&
           card_admin_enabled && mda_admin_enabled && mda_compatible &&
           card_lifecycle == EquipmentLifecycle::ready &&
           mda_lifecycle == EquipmentLifecycle::ready;
  }
  [[nodiscard]] std::size_t inventory_port_count() const noexcept {
    // Port identities come from equipped hardware, not from the chassis. The
    // backing array preserves running configuration across a physical remove,
    // while callers expose no ports until a compatible MDA is present.
    return mda_present && mda_compatible ? profile::port_count : 0U;
  }
  [[nodiscard]] bool port_operational(std::size_t index) const noexcept {
    return index < inventory_port_count() && hardware_operational() &&
           ports[index].admin_enabled && ports[index].link_signal;
  }
  [[nodiscard]] bool interface_operational(std::size_t index) const noexcept {
    // A routed interface follows its bound physical port, matching the required
    // dependency from hardware through port to IP forwarding.
    const auto& interface = interfaces[index];
    return interface.admin_enabled && port_operational(interface.port_index);
  }
  [[nodiscard]] bool routed_path_operational() const noexcept {
    return interface_operational(0) && interface_operational(1);
  }
};

struct CliSession {
  // Both engines belong to one router terminal session. Switching engines does
  // not create another device or global application mode.
  CliEngine engine{CliEngine::md};
  bool candidate_dirty{};
  // A classic CLI write can change running configuration while MD-CLI retains
  // an uncommitted candidate. The exclamation indicator records that baseline
  // divergence instead of silently rebasing or discarding either datastore.
  bool candidate_outdated{};
};

}  // namespace router
