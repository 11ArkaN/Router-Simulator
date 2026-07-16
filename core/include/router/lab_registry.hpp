// Stable multi-device registries for control-owned laboratory identity. These
// containers do not process packets or expose mutable storage across shards.

#pragma once

#include "router/cli_session.hpp"
#include "router/generated_device_catalog.hpp"

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace router::lab {

template <typename Tag> struct Handle {
  // Generation zero is never issued. A stale handle therefore cannot become
  // valid after a slot is removed and later allocated to another object.
  std::uint16_t index{0xffffU};
  std::uint16_t generation{};
  [[nodiscard]] constexpr explicit operator bool() const noexcept {
    return index != 0xffffU && generation != 0U;
  }
  auto operator<=>(const Handle &) const = default;
};

struct DeviceTag;
struct HostTag;
struct LinkTag;
struct SessionTag;
using DeviceHandle = Handle<DeviceTag>;
using HostHandle = Handle<HostTag>;
using LinkHandle = Handle<LinkTag>;
using SessionHandle = Handle<SessionTag>;

enum class NodeKind : std::uint8_t { router, host };

struct NodeHandle {
  NodeKind kind{};
  std::uint16_t index{0xffffU};
  std::uint16_t generation{};
  auto operator<=>(const NodeHandle &) const = default;
};

struct PortHandle {
  // Port ordinal is local to one NodeHandle generation. Port generation changes
  // whenever hardware removal destroys and later recreates that physical port.
  // Link intent keeps its textual port ID, while the live fabric uses this
  // compact value and therefore cannot deliver to replaced hardware silently.
  NodeHandle node;
  std::uint16_t ordinal{0xffffU};
  std::uint16_t generation{};
  [[nodiscard]] constexpr explicit operator bool() const noexcept {
    return static_cast<bool>(node.generation) && ordinal != 0xffffU &&
           generation != 0U;
  }
  auto operator<=>(const PortHandle &) const = default;
};

struct DeviceRecord {
  // The control shard owning DeviceRegistry is the sole writer. Profile points
  // into generated immutable storage and remains valid for the process life.
  std::string node_id;
  std::string system_name;
  const device_catalog::DeviceProfile *profile{};
  bool quiescing{};
};

struct HostRecord {
  std::string node_id;
  std::string name;
};

struct LinkEndpoint {
  NodeHandle node;
  std::string port_id;
};

struct LinkRecord {
  std::string link_id;
  std::array<LinkEndpoint, 2> endpoints;
  bool admin_enabled{true};
  // The supervisor is the only writer of operational media state. carrier is
  // true only after both endpoints resolve, rates agree and the forwarding
  // shard accepts the link program. speed_mbps is zero while no compatible
  // physical medium exists and remains observable when administration alone
  // withdraws carrier.
  bool carrier{};
  std::uint32_t speed_mbps{};
  std::uint64_t propagation_ns{100};
};

enum class CandidateMode : std::uint8_t {
  operational,
  global,
  exclusive,
  private_candidate,
  read_only
};

struct SessionRecord {
  DeviceHandle device;
  std::string session_id;
  CandidateMode mode{CandidateMode::operational};
  std::uint64_t base_generation{};
  // The registry is the persistence owner for CLI semantics. Browser editor
  // rendering remains a separate terminal-presentation contract, while this
  // value preserves the meaning of command input across checkpoint restore.
  CliSession cli{};
  bool closing{};
};

struct DeviceRegistryCheckpointEntry {
  DeviceHandle handle{};
  std::string node_id;
  std::string system_name;
  std::string profile_id;
  bool quiescing{};
};

struct HostRegistryCheckpointEntry {
  HostHandle handle{};
  std::string node_id;
  std::string name;
};

struct TopologyRegistryCheckpointEntry {
  LinkHandle handle{};
  LinkRecord record;
};

struct SessionRegistryCheckpointEntry {
  SessionHandle handle{};
  SessionRecord record;
};

struct DeviceRegistryCheckpoint {
  std::array<std::uint16_t, device_catalog::maximum_routers> generations{};
  std::vector<DeviceRegistryCheckpointEntry> entries;
};
struct HostRegistryCheckpoint {
  std::array<std::uint16_t, device_catalog::maximum_hosts> generations{};
  std::vector<HostRegistryCheckpointEntry> entries;
};
struct TopologyRegistryCheckpoint {
  std::array<std::uint16_t, device_catalog::maximum_links> generations{};
  std::vector<TopologyRegistryCheckpointEntry> entries;
};
struct SessionRegistryCheckpoint {
  static constexpr std::size_t capacity =
      device_catalog::maximum_routers *
      device_catalog::maximum_sessions_per_router;
  std::array<std::uint16_t, capacity> generations{};
  std::vector<SessionRegistryCheckpointEntry> entries;
};

class DeviceRegistry final {
public:
  // Preconditions: node_id is a validated project identifier and profile_id
  // names a generated profile. nullopt means duplicate identity, bad profile
  // or capacity exhaustion. No partial slot is published on failure.
  [[nodiscard]] std::optional<DeviceHandle>
  create(std::string_view node_id, std::string_view profile_id,
         std::string_view system_name);
  // erase requires topology and sessions to be detached by the supervisor.
  // false reports a stale handle without changing the current slot owner.
  [[nodiscard]] bool erase(DeviceHandle handle) noexcept;
  [[nodiscard]] DeviceRecord *get(DeviceHandle handle) noexcept;
  [[nodiscard]] const DeviceRecord *get(DeviceHandle handle) const noexcept;
  [[nodiscard]] std::optional<DeviceHandle>
  find(std::string_view node_id) const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] DeviceRegistryCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const DeviceRegistryCheckpoint &state);

private:
  struct Slot {
    std::uint16_t generation{1};
    bool occupied{};
    DeviceRecord value;
  };
  std::array<Slot, device_catalog::maximum_routers> slots_{};
  std::size_t size_{};
};

class HostRegistry final {
public:
  [[nodiscard]] std::optional<HostHandle>
  create(std::string_view node_id, std::string_view name);
  [[nodiscard]] bool erase(HostHandle handle) noexcept;
  [[nodiscard]] HostRecord *get(HostHandle handle) noexcept;
  [[nodiscard]] const HostRecord *get(HostHandle handle) const noexcept;
  [[nodiscard]] std::optional<HostHandle>
  find(std::string_view node_id) const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] HostRegistryCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const HostRegistryCheckpoint &state);

private:
  struct Slot {
    std::uint16_t generation{1};
    bool occupied{};
    HostRecord value;
  };
  std::array<Slot, device_catalog::maximum_hosts> slots_{};
  std::size_t size_{};
};

class TopologyRegistry final {
public:
  struct AttachedLinks {
    // A node can be incident to at most every laboratory link. Fixed storage
    // lets deletion and hardware reconciliation collect handles without heap
    // allocation while topology is in a transitional owner turn.
    std::array<LinkHandle, device_catalog::maximum_links> handles{};
    std::size_t count{};
  };
  // Each physical port can belong to one link. The registry stores intent even
  // when a compatible card or MDA is absent, allowing carrier to recover after
  // hardware reinsertion without changing the project graph.
  [[nodiscard]] std::optional<LinkHandle>
  create(std::string_view link_id, const LinkEndpoint &first,
         const LinkEndpoint &second, std::uint64_t propagation_ns);
  [[nodiscard]] bool erase(LinkHandle handle) noexcept;
  [[nodiscard]] LinkRecord *get(LinkHandle handle) noexcept;
  [[nodiscard]] const LinkRecord *get(LinkHandle handle) const noexcept;
  [[nodiscard]] std::optional<LinkHandle>
  find(std::string_view link_id) const noexcept;
  [[nodiscard]] bool port_bound(const LinkEndpoint &endpoint) const noexcept;
  [[nodiscard]] AttachedLinks attached(NodeHandle node) const noexcept;
  // Removes every incident link during confirmed node deletion. Handles are
  // invalidated before another create can reuse those slots.
  [[nodiscard]] std::size_t detach(NodeHandle node) noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] TopologyRegistryCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const TopologyRegistryCheckpoint &state);

private:
  struct Slot {
    std::uint16_t generation{1};
    bool occupied{};
    LinkRecord value;
  };
  std::array<Slot, device_catalog::maximum_links> slots_{};
  std::size_t size_{};
};

class SessionRegistry final {
public:
  struct DeviceSessions {
    // A router can own at most four sessions in this release. Returning a
    // bounded value snapshot lets workflow teardown avoid exposing registry
    // slots or retaining pointers across an erase operation.
    std::array<SessionHandle,
               device_catalog::maximum_sessions_per_router> handles{};
    std::size_t count{};
  };
  [[nodiscard]] std::optional<SessionHandle>
  create(DeviceHandle device, std::string_view session_id);
  [[nodiscard]] bool erase(SessionHandle handle) noexcept;
  [[nodiscard]] SessionRecord *get(SessionHandle handle) noexcept;
  [[nodiscard]] const SessionRecord *get(SessionHandle handle) const noexcept;
  [[nodiscard]] std::size_t close_device(DeviceHandle device) noexcept;
  [[nodiscard]] std::size_t count(DeviceHandle device) const noexcept;
  [[nodiscard]] std::size_t count(DeviceHandle device,
                                  CandidateMode mode) const noexcept;
  [[nodiscard]] DeviceSessions sessions(DeviceHandle device) const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] SessionRegistryCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const SessionRegistryCheckpoint &state);

private:
  struct Slot {
    std::uint16_t generation{1};
    bool occupied{};
    SessionRecord value;
  };
  static constexpr std::size_t capacity =
      device_catalog::maximum_routers *
      device_catalog::maximum_sessions_per_router;
  std::array<Slot, capacity> slots_{};
  std::size_t size_{};
};

[[nodiscard]] constexpr NodeHandle node(DeviceHandle handle) noexcept {
  return {NodeKind::router, handle.index, handle.generation};
}
[[nodiscard]] constexpr NodeHandle node(HostHandle handle) noexcept {
  return {NodeKind::host, handle.index, handle.generation};
}

} // namespace router::lab
