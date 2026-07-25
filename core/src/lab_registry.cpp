// Control-owned registry implementation. Linear scans are bounded by 16, 64
// or 64 records and avoid mutable secondary indexes that could become stale.

#include "router/lab_registry.hpp"

#include <algorithm>
#include <new>
#include <utility>

namespace router::lab {
namespace {

template <typename Slot, typename HandleType>
bool valid(const Slot &slot, HandleType handle) noexcept {
  // Index bounds are checked by each public caller before this helper. Keeping
  // the generation check beside occupancy prevents a freed slot from matching
  // merely because its old payload bytes have not been reused yet.
  return slot.occupied && slot.generation == handle.generation;
}

template <typename Slot>
void release(Slot &slot) noexcept {
  // Clear owned strings before publishing the free slot. Generation skips zero
  // on wrap because zero is reserved as the invalid handle generation.
  slot.value = {};
  slot.occupied = false;
  ++slot.generation;
  if (slot.generation == 0U)
    slot.generation = 1U;
}

bool same_endpoint(const LinkEndpoint &left,
                   const LinkEndpoint &right) noexcept {
  // Node generation participates in equality. A newly created router reusing
  // the same registry index does not inherit a cable from the deleted router.
  return left.node == right.node && left.port_id == right.port_id;
}

} // namespace

std::optional<DeviceHandle>
DeviceRegistry::create(std::string_view node_id, std::string_view profile_id,
                       std::string_view system_name) {
  // Identity and system name are separate on purpose. Renaming an SR OS system
  // must not break links, sessions, layout entries or checkpoint references.
  if (node_id.empty() || system_name.empty() || find(node_id))
    return std::nullopt;
  // Profile lookup occurs before reserving a slot. An unsupported profile
  // cannot consume capacity or advance a generation counter.
  const auto *profile = device_catalog::find_profile(profile_id);
  if (!profile)
    return std::nullopt;
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    auto &slot = slots_[index];
    // First-free allocation is deterministic. Checkpoint restore and tests do
    // not depend on hash-table bucket order or allocator address randomization.
    if (slot.occupied)
      continue;
    // Build the complete record before setting occupied. Allocation failure
    // leaves the slot unpublished and preserves its generation.
    slot.value = {std::string{node_id}, std::string{system_name}, profile,
                  false};
    slot.occupied = true;
    ++size_;
    return DeviceHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

bool DeviceRegistry::erase(DeviceHandle handle) noexcept {
  // Erasing through a stale handle is an observational failure. It cannot
  // advance the current owner's generation or clear the replacement device.
  if (handle.index >= slots_.size() || !valid(slots_[handle.index], handle))
    return false;
  release(slots_[handle.index]);
  --size_;
  return true;
}

DeviceRecord *DeviceRegistry::get(DeviceHandle handle) noexcept {
  // Mutable access remains on the registry owner. The returned pointer is not
  // stable across erase and must never be placed in a cross-shard message.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

const DeviceRecord *DeviceRegistry::get(DeviceHandle handle) const noexcept {
  // The const overload supports projections without granting mutation rights
  // to snapshot encoders or validators.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

std::optional<DeviceHandle>
DeviceRegistry::find(std::string_view node_id) const noexcept {
  // Sixteen slots make a linear lookup bounded and cache-local. A second map
  // would duplicate mutable identity state and require rollback on every edit.
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    if (slot.occupied && slot.value.node_id == node_id)
      return DeviceHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

std::optional<HostHandle> HostRegistry::create(std::string_view node_id,
                                               std::string_view name) {
  // Host and router ID uniqueness is enforced by the supervisor across both
  // registries. This local check prevents duplicates within the host domain.
  if (node_id.empty() || name.empty() || find(node_id))
    return std::nullopt;
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    auto &slot = slots_[index];
    // Payload construction precedes the occupied flag for the same atomic
    // publication rule used by DeviceRegistry.
    if (slot.occupied)
      continue;
    slot.value = {std::string{node_id}, std::string{name}};
    slot.occupied = true;
    ++size_;
    return HostHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

bool HostRegistry::erase(HostHandle handle) noexcept {
  // The supervisor detaches topology before calling erase. This function
  // limits its responsibility to identity lifetime and stale-handle safety.
  if (handle.index >= slots_.size() || !valid(slots_[handle.index], handle))
    return false;
  release(slots_[handle.index]);
  --size_;
  return true;
}

HostRecord *HostRegistry::get(HostHandle handle) noexcept {
  // Callers must finish using this pointer before the next host deletion on
  // the owner shard. Cross-shard code carries HostHandle instead.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

const HostRecord *HostRegistry::get(HostHandle handle) const noexcept {
  // Failed lookup returns null instead of a default host. Inventing a host here
  // would turn a dangling project reference into a magic network endpoint.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

std::optional<HostHandle>
HostRegistry::find(std::string_view node_id) const noexcept {
  // Capacity is fixed at sixteen, so worst-case work is independent from user
  // traffic and cannot grow during a long-running laboratory.
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    if (slot.occupied && slot.value.node_id == node_id)
      return HostHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

std::optional<SwitchHandle>
SwitchRegistry::create(std::string_view node_id, std::string_view profile_id,
                       std::string_view name) {
  if (node_id.empty() || name.empty() || find(node_id))
    return std::nullopt;
  const auto *profile =
      device_catalog::find_ethernet_switch_profile(profile_id);
  if (!profile)
    return std::nullopt;
  for (std::size_t index{}; index < slots_.size(); ++index) {
    auto &slot = slots_[index];
    if (slot.occupied)
      continue;
    // Strings and profile resolution are complete before occupancy publishes
    // the new generation to topology validation.
    std::vector<SwitchPortIntent> ports(
        profile->port_count,
        {.speed_mbps = profile->default_speed_mbps,
         .mtu = profile->default_mtu,
         .admin_enabled = profile->default_admin_enabled});
    slot.value = {std::string{node_id}, std::string{name}, profile,
                  std::move(ports)};
    slot.occupied = true;
    ++size_;
    return SwitchHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

bool SwitchRegistry::erase(SwitchHandle handle) noexcept {
  if (handle.index >= slots_.size() || !valid(slots_[handle.index], handle))
    return false;
  release(slots_[handle.index]);
  --size_;
  return true;
}

SwitchRecord *SwitchRegistry::get(SwitchHandle handle) noexcept {
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

const SwitchRecord *SwitchRegistry::get(SwitchHandle handle) const noexcept {
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

std::optional<SwitchHandle>
SwitchRegistry::find(std::string_view node_id) const noexcept {
  for (std::size_t index{}; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    if (slot.occupied && slot.value.node_id == node_id)
      return SwitchHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

std::optional<LinkHandle>
TopologyRegistry::create(std::string_view link_id, const LinkEndpoint &first,
                         const LinkEndpoint &second,
                         std::uint64_t propagation_ns,
                         std::uint32_t configured_speed_mbps) {
  // Validation is complete before any slot mutation. In particular, checking
  // both port bindings first prevents a failed second endpoint from leaving a
  // half-created cable attached to the first endpoint.
  if (link_id.empty() || first.port_id.empty() || second.port_id.empty() ||
      first.node == second.node || find(link_id) || port_bound(first) ||
      port_bound(second))
    return std::nullopt;
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    auto &slot = slots_[index];
    // The link record owns endpoint strings. No reference to a temporary
    // project parser buffer survives this assignment.
    if (slot.occupied)
      continue;
    slot.value = {std::string{link_id}, {first, second}, true,
                  configured_speed_mbps, false, 0U, propagation_ns};
    slot.occupied = true;
    ++size_;
    return LinkHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

bool TopologyRegistry::erase(LinkHandle handle) noexcept {
  // Link deletion changes only topology intent. Port carrier reconciliation is
  // a separate supervisor step and cannot run through a hidden callback here.
  if (handle.index >= slots_.size() || !valid(slots_[handle.index], handle))
    return false;
  release(slots_[handle.index]);
  --size_;
  return true;
}

LinkRecord *TopologyRegistry::get(LinkHandle handle) noexcept {
  // Generation validation keeps a delayed link-state command from modifying a
  // different cable that later reused the same compact index.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

const LinkRecord *TopologyRegistry::get(LinkHandle handle) const noexcept {
  // Packet and projection code receive const access unless executing an
  // explicit topology transaction on the control owner.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

std::optional<LinkHandle>
TopologyRegistry::find(std::string_view link_id) const noexcept {
  // Stable project IDs are compared as text only on the control path. Packet
  // forwarding uses compact LinkHandle values and never scans these strings.
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    if (slot.occupied && slot.value.link_id == link_id)
      return LinkHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

bool TopologyRegistry::port_bound(const LinkEndpoint &endpoint) const noexcept {
  // Full NodeHandle comparison makes this safe during deletion and recreation.
  // A port name alone is not unique across routers.
  for (const auto &slot : slots_) {
    if (slot.occupied &&
        (same_endpoint(slot.value.endpoints[0], endpoint) ||
         same_endpoint(slot.value.endpoints[1], endpoint)))
      return true;
  }
  return false;
}

TopologyRegistry::AttachedLinks
TopologyRegistry::attached(NodeHandle node_handle) const noexcept {
  AttachedLinks result;
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    if (!slot.occupied || (slot.value.endpoints[0].node != node_handle &&
                           slot.value.endpoints[1].node != node_handle))
      continue;
    // The registry is bounded, so the result array always has room for every
    // possible match and no silent truncation branch is necessary.
    result.handles[result.count++] = {
        static_cast<std::uint16_t>(index), slot.generation};
  }
  return result;
}

std::size_t TopologyRegistry::detach(NodeHandle node_handle) noexcept {
  // All matching slots are invalidated in one owner turn. The rest of the lab
  // remains available and no unrelated link receives a new generation.
  std::size_t removed{};
  for (auto &slot : slots_) {
    if (!slot.occupied || (slot.value.endpoints[0].node != node_handle &&
                           slot.value.endpoints[1].node != node_handle))
      continue;
    // release clears endpoint strings before the slot can be reused, so a
    // following port_bound call cannot observe a detached endpoint.
    release(slot);
    ++removed;
  }
  size_ -= removed;
  return removed;
}

std::optional<SessionHandle>
SessionRegistry::create(DeviceHandle device, std::string_view session_id) {
  // The per-router limit is checked before the global free-slot scan. One
  // router cannot consume capacity reserved for the other fifteen routers.
  if (!device || session_id.empty() ||
      count(device) == device_catalog::maximum_sessions_per_router)
    return std::nullopt;
  for (const auto &slot : slots_)
    // Session IDs are router-local. The same text may be used on another
    // router, but never twice for the same DeviceHandle generation.
    if (slot.occupied && slot.value.device == device &&
        slot.value.session_id == session_id)
      return std::nullopt;
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    auto &slot = slots_[index];
    // Session editor, pager and candidate payloads will be attached to this
    // owner slot. Publishing occupancy last remains required when those fields
    // gain non-trivial constructors.
    if (slot.occupied)
      continue;
    slot.value = {device, std::string{session_id}};
    slot.occupied = true;
    ++size_;
    return SessionHandle{static_cast<std::uint16_t>(index), slot.generation};
  }
  return std::nullopt;
}

bool SessionRegistry::erase(SessionHandle handle) noexcept {
  // A terminal close arriving after router deletion is harmless. The stale
  // generation cannot close a session belonging to a replacement router.
  if (handle.index >= slots_.size() || !valid(slots_[handle.index], handle))
    return false;
  release(slots_[handle.index]);
  --size_;
  return true;
}

SessionRecord *SessionRegistry::get(SessionHandle handle) noexcept {
  // Candidate mutation is legal only through this owner-side lookup. The UI
  // and forwarding shard carry SessionHandle, never SessionRecord pointers.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

const SessionRecord *SessionRegistry::get(SessionHandle handle) const noexcept {
  // Read-only prompt and tab projections use this overload so presentation
  // cannot acquire configuration write access accidentally.
  return handle.index < slots_.size() && valid(slots_[handle.index], handle)
             ? &slots_[handle.index].value
             : nullptr;
}

std::size_t SessionRegistry::close_device(DeviceHandle device) noexcept {
  // Router deletion closes all four possible sessions before the device slot
  // generation advances. Matching the complete handle prevents cross-device
  // cleanup when an index has already been reused.
  std::size_t removed{};
  for (auto &slot : slots_) {
    if (!slot.occupied || slot.value.device != device)
      continue;
    release(slot);
    ++removed;
  }
  size_ -= removed;
  return removed;
}

std::size_t SessionRegistry::count(DeviceHandle device) const noexcept {
  // The fixed 64-slot scan is a control-plane admission check. It avoids a
  // mutable per-device counter that could drift during bulk close or restore.
  return static_cast<std::size_t>(std::count_if(
      slots_.begin(), slots_.end(), [device](const auto &slot) {
        return slot.occupied && slot.value.device == device;
      }));
}

std::size_t SessionRegistry::count(DeviceHandle device,
                                   CandidateMode mode) const noexcept {
  // Mode arbitration is a control-plane operation over at most 64 slots. It is
  // never performed on the packet path and remains exact during session close.
  return static_cast<std::size_t>(std::count_if(
      slots_.begin(), slots_.end(), [device, mode](const auto &slot) {
        return slot.occupied && slot.value.device == device &&
               slot.value.mode == mode;
      }));
}

SessionRegistry::DeviceSessions
SessionRegistry::sessions(DeviceHandle device) const noexcept {
  DeviceSessions result;
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    if (!slot.occupied || slot.value.device != device)
      continue;
    // Admission enforces the per-router maximum, so this fixed snapshot cannot
    // truncate a valid session or require a fallback allocation.
    result.handles[result.count++] = {
        static_cast<std::uint16_t>(index), slot.generation};
  }
  return result;
}

DeviceRegistryCheckpoint DeviceRegistry::checkpoint() const {
  DeviceRegistryCheckpoint state;
  state.entries.reserve(size_);
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    state.generations[index] = slot.generation;
    if (slot.occupied)
      state.entries.push_back(
           {{static_cast<std::uint16_t>(index), slot.generation},
           slot.value.node_id, slot.value.system_name,
           std::string{slot.value.profile->id},
           slot.value.quiescing});
  }
  return state;
}

bool DeviceRegistry::restore(const DeviceRegistryCheckpoint &state) {
  if (state.entries.size() > slots_.size() ||
      std::any_of(state.generations.begin(), state.generations.end(),
                  [](auto generation) { return generation == 0U; }))
    return false;
  std::array<bool, device_catalog::maximum_routers> occupied{};
  for (const auto &entry : state.entries) {
    if (!entry.handle || entry.handle.index >= occupied.size() ||
        occupied[entry.handle.index] ||
        state.generations[entry.handle.index] != entry.handle.generation ||
        entry.node_id.empty() || entry.system_name.empty() ||
        !device_catalog::find_profile(entry.profile_id))
      return false;
    for (const auto &other : state.entries)
      if (&entry != &other && entry.node_id == other.node_id)
        return false;
    occupied[entry.handle.index] = true;
  }
  try {
    DeviceRegistry replacement;
    for (std::size_t index = 0; index < replacement.slots_.size(); ++index)
      replacement.slots_[index].generation = state.generations[index];
    for (const auto &entry : state.entries) {
      auto &slot = replacement.slots_[entry.handle.index];
      slot.value = {entry.node_id, entry.system_name,
                    device_catalog::find_profile(entry.profile_id),
                    entry.quiescing};
      slot.occupied = true;
    }
    replacement.size_ = state.entries.size();
    *this = std::move(replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

HostRegistryCheckpoint HostRegistry::checkpoint() const {
  HostRegistryCheckpoint state;
  state.entries.reserve(size_);
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    state.generations[index] = slot.generation;
    if (slot.occupied)
      state.entries.push_back(
          {{static_cast<std::uint16_t>(index), slot.generation},
           slot.value.node_id, slot.value.name});
  }
  return state;
}

bool HostRegistry::restore(const HostRegistryCheckpoint &state) {
  if (state.entries.size() > slots_.size() ||
      std::any_of(state.generations.begin(), state.generations.end(),
                  [](auto generation) { return generation == 0U; }))
    return false;
  std::array<bool, device_catalog::maximum_hosts> occupied{};
  for (const auto &entry : state.entries) {
    if (!entry.handle || entry.handle.index >= occupied.size() ||
        occupied[entry.handle.index] ||
        state.generations[entry.handle.index] != entry.handle.generation ||
        entry.node_id.empty() || entry.name.empty())
      return false;
    for (const auto &other : state.entries)
      if (&entry != &other && entry.node_id == other.node_id)
        return false;
    occupied[entry.handle.index] = true;
  }
  try {
    HostRegistry replacement;
    for (std::size_t index = 0; index < replacement.slots_.size(); ++index)
      replacement.slots_[index].generation = state.generations[index];
    for (const auto &entry : state.entries) {
      auto &slot = replacement.slots_[entry.handle.index];
      slot.value = {entry.node_id, entry.name};
      slot.occupied = true;
    }
    replacement.size_ = state.entries.size();
    *this = std::move(replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

SwitchRegistryCheckpoint SwitchRegistry::checkpoint() const {
  SwitchRegistryCheckpoint state;
  state.entries.reserve(size_);
  for (std::size_t index{}; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    state.generations[index] = slot.generation;
    if (slot.occupied)
      state.entries.push_back(
          {{static_cast<std::uint16_t>(index), slot.generation},
           slot.value.node_id, slot.value.name,
           std::string{slot.value.profile->id}, slot.value.ports});
  }
  return state;
}

bool SwitchRegistry::restore(const SwitchRegistryCheckpoint &state) {
  if (state.entries.size() > slots_.size() ||
      std::any_of(state.generations.begin(), state.generations.end(),
                  [](auto generation) { return generation == 0U; }))
    return false;
  std::array<bool, device_catalog::maximum_switches> occupied{};
  for (const auto &entry : state.entries) {
    if (!entry.handle || entry.handle.index >= occupied.size() ||
        occupied[entry.handle.index] ||
        state.generations[entry.handle.index] != entry.handle.generation ||
        entry.node_id.empty() || entry.name.empty() ||
        !device_catalog::find_ethernet_switch_profile(entry.profile_id))
      return false;
    const auto *profile =
        device_catalog::find_ethernet_switch_profile(entry.profile_id);
    if (entry.ports.size() != profile->port_count)
      return false;
    for (const auto &port : entry.ports) {
      const auto supported =
          std::find(profile->supported_speeds_mbps.begin(),
                    profile->supported_speeds_mbps.begin() +
                        profile->speed_count,
                    port.speed_mbps) !=
          profile->supported_speeds_mbps.begin() + profile->speed_count;
      if (!supported || port.mtu < profile->minimum_mtu ||
          port.mtu > profile->maximum_mtu)
        return false;
    }
    for (const auto &other : state.entries)
      if (&entry != &other && entry.node_id == other.node_id)
        return false;
    occupied[entry.handle.index] = true;
  }
  try {
    SwitchRegistry replacement;
    for (std::size_t index{}; index < replacement.slots_.size(); ++index)
      replacement.slots_[index].generation = state.generations[index];
    for (const auto &entry : state.entries) {
      auto &slot = replacement.slots_[entry.handle.index];
      slot.value = {
          entry.node_id, entry.name,
          device_catalog::find_ethernet_switch_profile(entry.profile_id),
          entry.ports};
      slot.occupied = true;
    }
    replacement.size_ = state.entries.size();
    *this = std::move(replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

TopologyRegistryCheckpoint TopologyRegistry::checkpoint() const {
  TopologyRegistryCheckpoint state;
  state.entries.reserve(size_);
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    state.generations[index] = slot.generation;
    if (slot.occupied)
      state.entries.push_back(
          {{static_cast<std::uint16_t>(index), slot.generation}, slot.value});
  }
  return state;
}

bool TopologyRegistry::restore(const TopologyRegistryCheckpoint &state) {
  if (state.entries.size() > slots_.size() ||
      std::any_of(state.generations.begin(), state.generations.end(),
                  [](auto generation) { return generation == 0U; }))
    return false;
  std::array<bool, device_catalog::maximum_links> occupied{};
  for (const auto &entry : state.entries) {
    if (!entry.handle || entry.handle.index >= occupied.size() ||
        occupied[entry.handle.index] ||
        state.generations[entry.handle.index] != entry.handle.generation ||
        entry.record.link_id.empty() ||
        entry.record.endpoints[0].port_id.empty() ||
        entry.record.endpoints[1].port_id.empty() ||
        entry.record.endpoints[0].node == entry.record.endpoints[1].node)
      return false;
    for (const auto &other : state.entries) {
      if (&entry == &other)
        continue;
      if (entry.record.link_id == other.record.link_id)
        return false;
      for (const auto &left : entry.record.endpoints)
        for (const auto &right : other.record.endpoints)
          if (same_endpoint(left, right))
            return false;
    }
    occupied[entry.handle.index] = true;
  }
  try {
    TopologyRegistry replacement;
    for (std::size_t index = 0; index < replacement.slots_.size(); ++index)
      replacement.slots_[index].generation = state.generations[index];
    for (const auto &entry : state.entries) {
      auto &slot = replacement.slots_[entry.handle.index];
      slot.value = entry.record;
      slot.occupied = true;
    }
    replacement.size_ = state.entries.size();
    *this = std::move(replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

SessionRegistryCheckpoint SessionRegistry::checkpoint() const {
  SessionRegistryCheckpoint state;
  state.entries.reserve(size_);
  for (std::size_t index = 0; index < slots_.size(); ++index) {
    const auto &slot = slots_[index];
    state.generations[index] = slot.generation;
    if (slot.occupied)
      state.entries.push_back(
          {{static_cast<std::uint16_t>(index), slot.generation}, slot.value});
  }
  return state;
}

bool SessionRegistry::restore(const SessionRegistryCheckpoint &state) {
  if (state.entries.size() > slots_.size() ||
      std::any_of(state.generations.begin(), state.generations.end(),
                  [](auto generation) { return generation == 0U; }))
    return false;
  std::array<bool, capacity> occupied{};
  for (const auto &entry : state.entries) {
    if (!entry.handle || entry.handle.index >= occupied.size() ||
        occupied[entry.handle.index] ||
        state.generations[entry.handle.index] != entry.handle.generation ||
        !entry.record.device || entry.record.session_id.empty() ||
        entry.record.mode < CandidateMode::operational ||
        entry.record.mode > CandidateMode::read_only)
      return false;
    std::size_t device_sessions{};
    for (const auto &other : state.entries) {
      if (other.record.device == entry.record.device) {
        ++device_sessions;
        if (&entry != &other &&
            other.record.session_id == entry.record.session_id)
          return false;
      }
    }
    if (device_sessions > device_catalog::maximum_sessions_per_router)
      return false;
    occupied[entry.handle.index] = true;
  }
  try {
    SessionRegistry replacement;
    for (std::size_t index = 0; index < replacement.slots_.size(); ++index)
      replacement.slots_[index].generation = state.generations[index];
    for (const auto &entry : state.entries) {
      auto &slot = replacement.slots_[entry.handle.index];
      slot.value = entry.record;
      slot.occupied = true;
    }
    replacement.size_ = state.entries.size();
    *this = std::move(replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::lab
