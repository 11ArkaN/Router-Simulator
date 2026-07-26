// RFC 4861 Neighbor Unreachability Detection implementation. This module
// emits protocol actions but never sends frames itself, so the forwarding and
// link owners retain queueing, capture and physical transmission semantics.

#include "router/ipv6_neighbor_cache.hpp"

#include <algorithm>

namespace router::lab {
namespace {

std::chrono::seconds
normalized_stale_time(std::chrono::seconds candidate) noexcept {
  // Every ingress path, including direct unit callers, receives the same
  // release-owned range check. This keeps checkpoint invariants independent
  // from whether the value arrived through CLI, persistence or an internal
  // protocol action.
  if (candidate < std::chrono::seconds{
                      device_catalog::nd_minimum_stale_time_seconds} ||
      candidate > std::chrono::seconds{
                      device_catalog::nd_maximum_stale_time_seconds})
    return std::chrono::seconds{
        device_catalog::nd_default_stale_time_seconds};
  return candidate;
}

} // namespace

Ipv6NeighborCache::Ipv6NeighborCache() = default;

std::uint64_t Ipv6NeighborCache::key_hash(
    std::uint64_t interface_id, const ip::Ipv6 &address) noexcept {
  // FNV-1a is used only as a table spread function. The complete scoped key is
  // compared after a hash match, so collisions cannot alias two neighbors.
  std::uint64_t value{1469598103934665603ULL};
  const auto mix = [&](std::uint8_t byte) {
    value ^= byte;
    value *= 1099511628211ULL;
  };
  // Feed all eight identity octets. Hashing only a former 16-bit ordinal
  // would preserve correctness after the equality check, but collapse every
  // large logical ID with the same suffix into the same probe sequence.
  for (std::uint8_t shift = 0U; shift < 64U; shift += 8U)
    mix(static_cast<std::uint8_t>(interface_id >> shift));
  for (const auto byte : address)
    mix(byte);
  return value;
}

std::optional<std::size_t> Ipv6NeighborCache::index_lookup(
    std::uint64_t interface_id, const ip::Ipv6 &address) const noexcept {
  if (index_.empty())
    return std::nullopt;
  const auto hash = key_hash(interface_id, address);
  const auto mask = index_.size() - 1U;
  for (std::size_t probe = 0U; probe < index_.size(); ++probe) {
    const auto &slot = index_[(hash + probe) & mask];
    if (slot.state == IndexState::empty)
      return std::nullopt;
    if (slot.state != IndexState::occupied || slot.hash != hash ||
        slot.entry_index >= entries_.size())
      continue;
    const auto &candidate = entries_[slot.entry_index];
    if (candidate.valid && candidate.interface_id == interface_id &&
        candidate.address == address)
      return slot.entry_index;
  }
  return std::nullopt;
}

bool Ipv6NeighborCache::ensure_index_capacity(std::size_t active) noexcept {
  // A 50 percent maximum live load makes the probe bound insensitive to the
  // documented 102400-entry ceiling. Churn may add tombstones, so rebuilding
  // also occurs when there is no empty slot left for an unsuccessful lookup.
  constexpr std::size_t minimum_slots{16U};
  std::size_t target = index_.empty() ? minimum_slots : index_.size();
  while (active > target / 2U)
    target *= 2U;
  const auto occupied_or_tombstone = static_cast<std::size_t>(std::count_if(
      index_.begin(), index_.end(), [](const IndexSlot &slot) {
        return slot.state != IndexState::empty;
      }));
  if (target == index_.size() && occupied_or_tombstone < target)
    return true;

  try {
    std::vector<IndexSlot> replacement(target);
    const auto mask = target - 1U;
    std::size_t rebuilt_entries{};
    for (std::size_t entry_index = 0U; entry_index < entries_.size();
         ++entry_index) {
      const auto &entry = entries_[entry_index];
      if (!entry.valid)
        continue;
      const auto hash = key_hash(entry.interface_id, entry.address);
      bool inserted{};
      for (std::size_t probe = 0U; probe < target; ++probe) {
        auto &slot = replacement[(hash + probe) & mask];
        if (slot.state != IndexState::empty)
          continue;
        slot = {.hash = hash,
                .entry_index = static_cast<std::uint32_t>(entry_index),
                .state = IndexState::occupied};
        inserted = true;
        break;
      }
      if (!inserted)
        return false;
      ++rebuilt_entries;
    }
    index_.swap(replacement);
    indexed_entries_ = rebuilt_entries;
    return true;
  } catch (...) {
    // Index allocation failure is reported as neighbor-table exhaustion. The
    // existing authoritative entries and old index remain fully usable.
    return false;
  }
}

bool Ipv6NeighborCache::index_insert(std::size_t entry_index) noexcept {
  if (index_.empty() || entry_index >= entries_.size())
    return false;
  const auto &entry = entries_[entry_index];
  const auto hash = key_hash(entry.interface_id, entry.address);
  const auto mask = index_.size() - 1U;
  std::optional<std::size_t> tombstone;
  for (std::size_t probe = 0U; probe < index_.size(); ++probe) {
    const auto slot_index = (hash + probe) & mask;
    auto &slot = index_[slot_index];
    if (slot.state == IndexState::tombstone && !tombstone)
      tombstone = slot_index;
    if (slot.state != IndexState::empty)
      continue;
    auto &target = index_[tombstone.value_or(slot_index)];
    target = {.hash = hash,
              .entry_index = static_cast<std::uint32_t>(entry_index),
              .state = IndexState::occupied};
    ++indexed_entries_;
    return true;
  }
  if (!tombstone)
    return false;
  index_[*tombstone] = {
      .hash = hash,
      .entry_index = static_cast<std::uint32_t>(entry_index),
      .state = IndexState::occupied};
  ++indexed_entries_;
  return true;
}

void Ipv6NeighborCache::index_erase(
    std::uint64_t interface_id, const ip::Ipv6 &address) noexcept {
  if (const auto found = index_lookup(interface_id, address)) {
    const auto hash = key_hash(interface_id, address);
    const auto mask = index_.size() - 1U;
    for (std::size_t probe = 0U; probe < index_.size(); ++probe) {
      auto &slot = index_[(hash + probe) & mask];
      if (slot.state == IndexState::empty)
        break;
      if (slot.state == IndexState::occupied &&
          slot.entry_index == *found) {
        slot.state = IndexState::tombstone;
        --indexed_entries_;
        return;
      }
    }
  }
}

void Ipv6NeighborCache::erase_entry(Entry &target) noexcept {
  if (!target.valid)
    return;
  index_erase(target.interface_id, target.address);
  target = Entry{};
}

Ipv6NeighborCache::Entry *
Ipv6NeighborCache::entry(std::uint64_t interface_id,
                         const ip::Ipv6 &address) noexcept {
  const auto found = index_lookup(interface_id, address);
  return found ? &entries_[*found] : nullptr;
}

const Ipv6NeighborCache::Entry *
Ipv6NeighborCache::entry(std::uint64_t interface_id,
                         const ip::Ipv6 &address) const noexcept {
  const auto found = index_lookup(interface_id, address);
  return found ? &entries_[*found] : nullptr;
}

void Ipv6NeighborCache::touch(Entry &target) noexcept {
  // Zero is reserved for never-used entries. Natural uint64 wrap would require
  // more successful lookups than the process can execute in its lifetime; if
  // it occurs, resetting to one still preserves valid ordering for eviction.
  if (++use_generation_ == 0)
    use_generation_ = 1;
  target.use_generation = use_generation_;
}

Ipv6NeighborCache::Entry *
Ipv6NeighborCache::allocate(Clock::time_point now) noexcept {
  if (const auto available =
          std::find_if(entries_.begin(), entries_.end(),
                       [](const Entry &candidate) { return !candidate.valid; });
      available != entries_.end()) {
    *available = Entry{};
    return &*available;
  }

  // Growing is confined to creation of a new neighbor. Existing-neighbor
  // forwarding only searches stable values and never allocates. std::vector's
  // geometric capacity growth avoids one allocation per discovered address,
  // and the release-owned maximum remains an exact hard boundary.
  if (entries_.size() <
      device_catalog::ipv6_neighbor_entries_per_router) {
    try {
      entries_.emplace_back();
      return &entries_.back();
    } catch (...) {
      // The forwarding contract reports resource exhaustion as table_full.
      // Exceptions must not cross the shard command boundary or terminate the
      // WebAssembly worker under host-memory pressure.
      return nullptr;
    }
  }

  // Under capacity pressure only a STALE entry may be replaced. INCOMPLETE,
  // DELAY and PROBE entries have active protocol work, while REACHABLE entries
  // are still confirmed forwarding state. The least recently used STALE entry
  // provides deterministic overload behavior without evicting active work.
  Entry *oldest{};
  for (auto &candidate : entries_) {
    if (candidate.state != Ipv6NeighborState::stale)
      continue;
    if (!oldest || candidate.use_generation < oldest->use_generation)
      oldest = &candidate;
  }
  if (!oldest)
    return nullptr;
  erase_entry(*oldest);
  oldest->deadline = now;
  return oldest;
}

void Ipv6NeighborCache::mark_reachable(
    Entry &target, std::chrono::milliseconds reachable_time,
    Clock::time_point now) noexcept {
  // A zero or negative interval would immediately oscillate REACHABLE to
  // STALE. Interface validation must supply the positive RFC-derived value.
  if (reachable_time <= std::chrono::milliseconds::zero())
    reachable_time = device_catalog::nd_base_reachable_time;
  target.state = Ipv6NeighborState::reachable;
  target.probes_sent = 0;
  target.deadline = now + reachable_time;
  touch(target);
}

void Ipv6NeighborCache::mark_stale(Entry &target,
                                   std::chrono::seconds stale_time,
                                   bool proactive_refresh,
                                   Clock::time_point now) noexcept {
  // The release profile validates configuration before it reaches this owner.
  // Clamp defensively because checkpoint restore and future protocol callers
  // are separate trust boundaries and must not create an immediate timer loop.
  stale_time = normalized_stale_time(stale_time);
  target.state = Ipv6NeighborState::stale;
  target.probes_sent = 0U;
  target.stale_time = stale_time;
  target.proactive_refresh = proactive_refresh;
  target.deadline = now + stale_time;
  touch(target);
}

Ipv6Resolution Ipv6NeighborCache::resolve(std::uint64_t interface_id,
                                          const ip::Ipv6 &address,
                                          Clock::time_point now,
                                          std::chrono::seconds stale_time,
                                          bool proactive_refresh) noexcept {
  stale_time = normalized_stale_time(stale_time);
  if (interface_id == 0U ||
      ip::is_unspecified(address) || ip::is_multicast(address))
    return {.status = Ipv6ResolutionStatus::table_full};
  auto *target = entry(interface_id, address);
  if (!target) {
    if (!ensure_index_capacity(indexed_entries_ + 1U))
      return {.status = Ipv6ResolutionStatus::table_full};
    target = allocate(now);
    if (!target)
      return {.status = Ipv6ResolutionStatus::table_full};
    target->valid = true;
    target->interface_id = interface_id;
    target->address = address;
    target->state = Ipv6NeighborState::incomplete;
    target->probes_sent = 1;
    target->deadline = now + device_catalog::nd_retrans_timer;
    target->stale_time = stale_time;
    target->proactive_refresh = proactive_refresh;
    const auto entry_index =
        static_cast<std::size_t>(target - entries_.data());
    if (!index_insert(entry_index)) {
      *target = Entry{};
      return {.status = Ipv6ResolutionStatus::table_full};
    }
    touch(*target);
    return {.status = Ipv6ResolutionStatus::solicitation_required};
  }

  if (target->state == Ipv6NeighborState::reachable &&
      target->deadline <= now) {
    mark_stale(*target, stale_time, proactive_refresh, now);
  }
  if (target->state == Ipv6NeighborState::incomplete)
    return {.status = Ipv6ResolutionStatus::pending};
  if (target->is_static) {
    touch(*target);
    return {.status = Ipv6ResolutionStatus::resolved, .mac = target->mac};
  }
  if (target->state == Ipv6NeighborState::stale) {
    // The first packet may use the cached address immediately. DELAY gives
    // upper layers time to confirm reachability before an active probe.
    target->state = Ipv6NeighborState::delay;
    target->deadline = now + device_catalog::nd_delay_first_probe;
  }
  target->stale_time = stale_time;
  target->proactive_refresh = proactive_refresh;
  touch(*target);
  return {.status = Ipv6ResolutionStatus::resolved, .mac = target->mac};
}

bool Ipv6NeighborCache::receive_advertisement(
    std::uint64_t interface_id, const ip::Ipv6 &address,
    std::optional<packet::Mac> target_link_layer, bool solicited,
    bool override_flag, bool is_router, bool learn_unsolicited,
    std::chrono::milliseconds reachable_time, Clock::time_point now,
    std::chrono::seconds stale_time, bool proactive_refresh) noexcept {
  stale_time = normalized_stale_time(stale_time);
  auto *target = entry(interface_id, address);
  // RFC 4861 discards an NA for which no Neighbor Cache entry exists. SR OS
  // can explicitly relax that rule per interface and address scope. Even when
  // the received S flag is set, a policy-created entry is STALE because no
  // locally initiated resolution proved two-way reachability.
  if (!target)
    return learn_unsolicited && target_link_layer &&
           learn_stale(interface_id, address, *target_link_layer, is_router,
                       now, stale_time, proactive_refresh);
  // Received advertisements can neither replace nor age configured static
  // intent. Returning true acknowledges a valid message without changing its
  // administrator-owned mapping.
  if (target->is_static)
    return true;
  target->stale_time = stale_time;
  target->proactive_refresh = proactive_refresh;

  if (target->state == Ipv6NeighborState::incomplete) {
    if (!target_link_layer)
      return false;
    target->mac = *target_link_layer;
    target->is_router = is_router;
    if (solicited)
      mark_reachable(*target, reachable_time, now);
    else
      mark_stale(*target, stale_time, proactive_refresh, now);
    return true;
  }

  const bool address_changed =
      target_link_layer && *target_link_layer != target->mac;
  if (address_changed && !override_flag) {
    // With Override clear, a conflicting link-layer address cannot replace a
    // valid cache value. A REACHABLE entry becomes STALE so normal NUD can
    // determine which mapping is usable.
    if (target->state == Ipv6NeighborState::reachable) {
      mark_stale(*target, stale_time, proactive_refresh, now);
      return true;
    }
    return false;
  }

  if (address_changed)
    target->mac = *target_link_layer;
  target->is_router = is_router;
  if (solicited) {
    mark_reachable(*target, reachable_time, now);
  } else if (address_changed) {
    mark_stale(*target, stale_time, proactive_refresh, now);
  }
  target->stale_time = stale_time;
  target->proactive_refresh = proactive_refresh;
  return true;
}

bool Ipv6NeighborCache::learn_stale(std::uint64_t interface_id,
                                    const ip::Ipv6 &address, packet::Mac mac,
                                    bool is_router,
                                    Clock::time_point now,
                                    std::chrono::seconds stale_time,
                                    bool proactive_refresh) noexcept {
  stale_time = normalized_stale_time(stale_time);
  // RFC 4861 link-layer options carry an Ethernet unicast identity for a
  // neighbor. Validate it at the cache boundary as well as in packet parsers:
  // restore paths and future protocol callers must not be able to install the
  // all-zero address or a multicast destination as a usable next hop.
  const bool mac_usable = (mac[0U] & 1U) == 0U &&
                          std::any_of(mac.begin(), mac.end(),
                                      [](auto byte) { return byte != 0U; });
  if (interface_id == 0U ||
      ip::is_unspecified(address) || ip::is_multicast(address) || !mac_usable)
    return false;
  auto *target = entry(interface_id, address);
  if (target && target->is_static)
    return target->mac == mac;
  if (!target) {
    if (!ensure_index_capacity(indexed_entries_ + 1U))
      return false;
    target = allocate(now);
    if (!target)
      return false;
    target->valid = true;
    target->interface_id = interface_id;
    target->address = address;
    const auto entry_index =
        static_cast<std::size_t>(target - entries_.data());
    if (!index_insert(entry_index)) {
      *target = Entry{};
      return false;
    }
  }
  if (target->state == Ipv6NeighborState::incomplete || target->mac != mac) {
    target->mac = mac;
    mark_stale(*target, stale_time, proactive_refresh, now);
  } else if (target->state == Ipv6NeighborState::stale) {
    // A valid link-layer option refreshes the vendor stale aging interval even
    // when the MAC is unchanged. It still does not prove reachability.
    mark_stale(*target, stale_time, proactive_refresh, now);
  }
  target->is_router = is_router;
  touch(*target);
  return true;
}

bool Ipv6NeighborCache::apply_batch(
    std::span<const Ipv6NeighborBatchEdit> edits,
    Clock::time_point now) noexcept {
  std::size_t creating{};
  for (std::size_t index = 0; index < edits.size(); ++index) {
    const auto &edit = edits[index];
    const bool mac_usable =
        (edit.mac[0U] & 1U) == 0U &&
        std::any_of(edit.mac.begin(), edit.mac.end(),
                    [](auto byte) { return byte != 0U; });
    if (edit.interface_id == 0U || ip::is_unspecified(edit.address) ||
        ip::is_multicast(edit.address) ||
        (edit.kind == Ipv6NeighborBatchKind::learn_stale && !mac_usable) ||
        std::any_of(edits.begin(), edits.begin() + index,
                    [&](const auto &previous) {
                      return previous.interface_id == edit.interface_id &&
                             previous.address == edit.address;
                    }))
      return false;
    const auto *existing = entry(edit.interface_id, edit.address);
    if (edit.kind == Ipv6NeighborBatchKind::learn_stale) {
      // DHCP-derived state cannot override an administrator-owned static
      // mapping with a different MAC. An identical static mapping already
      // satisfies the requested adjacency and remains static.
      if (existing && existing->is_static && existing->mac != edit.mac)
        return false;
      if (!existing)
        ++creating;
    }
  }

  const auto vacant = static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(),
      [](const Entry &candidate) { return !candidate.valid; }));
  const auto growable = device_catalog::ipv6_neighbor_entries_per_router -
                        std::min(entries_.size(),
                                 device_catalog::ipv6_neighbor_entries_per_router);
  const auto evictable = static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(), [](const Entry &candidate) {
        return candidate.valid && !candidate.is_static &&
               candidate.state == Ipv6NeighborState::stale;
      }));
  if (creating > vacant + growable + evictable)
    return false;

  try {
    // Reserve only entries that cannot reuse existing holes. Index capacity is
    // prepared for the conservative pre-removal active count, so subsequent
    // erase/insert churn cannot allocate after live mutation begins.
    const auto append_count = creating > vacant ? creating - vacant : 0U;
    if (append_count != 0U)
      entries_.reserve(std::min(
          device_catalog::ipv6_neighbor_entries_per_router,
          entries_.size() + append_count));
    if (creating != 0U &&
        !ensure_index_capacity(indexed_entries_ + creating))
      return false;
  } catch (...) {
    return false;
  }

  for (const auto &edit : edits) {
    if (edit.kind == Ipv6NeighborBatchKind::remove_dynamic) {
      static_cast<void>(clear_dynamic(edit.interface_id, edit.address));
      continue;
    }
    // All allocation and conflict failure modes were removed above. A false
    // result here would indicate a violated internal capacity invariant, not
    // ordinary overload. Returning false avoids reporting a successful batch
    // while preserving diagnostics for the owning forwarding turn.
    if (!learn_stale(edit.interface_id, edit.address, edit.mac, false, now,
                     edit.stale_time, edit.proactive_refresh))
      return false;
  }
  return true;
}

bool Ipv6NeighborCache::install_static(std::uint64_t interface_id,
                                       const ip::Ipv6 &address,
                                       packet::Mac mac) noexcept {
  const bool mac_usable = (mac[0U] & 1U) == 0U &&
                          std::any_of(mac.begin(), mac.end(),
                                      [](auto byte) { return byte != 0U; });
  if (interface_id == 0U ||
      ip::is_unspecified(address) || ip::is_multicast(address) || !mac_usable)
    return false;
  auto *target = entry(interface_id, address);
  const bool creating = !target;
  if (creating && !ensure_index_capacity(indexed_entries_ + 1U))
    return false;
  if (creating)
    target = allocate(Clock::now());
  if (!target)
    return false;
  *target = {.valid = true,
             .is_router = false,
             .is_static = true,
             .interface_id = interface_id,
             .address = address,
             .mac = mac,
             .state = Ipv6NeighborState::reachable,
             .probes_sent = 0U,
             .use_generation = 0U,
             .deadline = Clock::time_point::max()};
  if (creating) {
    const auto entry_index =
        static_cast<std::size_t>(target - entries_.data());
    if (!index_insert(entry_index)) {
      *target = Entry{};
      return false;
    }
  }
  touch(*target);
  return true;
}

bool Ipv6NeighborCache::remove_static(std::uint64_t interface_id,
                                      const ip::Ipv6 &address) noexcept {
  auto *target = entry(interface_id, address);
  if (!target || !target->is_static)
    return false;
  erase_entry(*target);
  trim_unused_tail();
  return true;
}

std::size_t Ipv6NeighborCache::clear_dynamic(
    std::optional<std::uint64_t> interface_id,
    std::optional<ip::Ipv6> address) noexcept {
  std::size_t removed{};
  for (auto &target : entries_)
    if (target.valid && !target.is_static &&
        (!interface_id || target.interface_id == *interface_id) &&
        (!address || target.address == *address)) {
      erase_entry(target);
      ++removed;
    }
  trim_unused_tail();
  return removed;
}

bool Ipv6NeighborCache::confirm_reachability(
    std::uint64_t interface_id, const ip::Ipv6 &address,
    std::chrono::milliseconds reachable_time, Clock::time_point now) noexcept {
  auto *target = entry(interface_id, address);
  if (!target || target->state == Ipv6NeighborState::incomplete)
    return false;
  if (target->is_static)
    return true;
  mark_reachable(*target, reachable_time, now);
  return true;
}

std::size_t
Ipv6NeighborCache::poll(Clock::time_point now,
                        std::span<Ipv6NeighborAction> output) noexcept {
  std::size_t written{};
  for (auto &target : entries_) {
    if (!target.valid || target.deadline > now)
      continue;
    if (target.is_static)
      continue;
    if (target.state == Ipv6NeighborState::reachable) {
      mark_stale(target, target.stale_time, target.proactive_refresh, now);
      continue;
    }
    if (target.state == Ipv6NeighborState::stale) {
      // SR OS removes ordinary STALE entries at stale-time expiry. With the
      // scope-selective proactive policy it sends a unicast NUD probe instead.
      // Backpressure keeps the entry due until an action slot is available.
      if (!target.proactive_refresh) {
        erase_entry(target);
        continue;
      }
      if (written == output.size())
        break;
      target.state = Ipv6NeighborState::probe;
      target.probes_sent = 1U;
      target.deadline = now + device_catalog::nd_retrans_timer;
      output[written++] = {
          .kind = Ipv6NeighborActionKind::unicast_solicitation,
          .interface_id = target.interface_id,
          .address = target.address,
          .mac = target.mac};
      continue;
    }
    if (written == output.size())
      break;

    if (target.state == Ipv6NeighborState::delay) {
      target.state = Ipv6NeighborState::probe;
      target.probes_sent = 1;
      target.deadline = now + device_catalog::nd_retrans_timer;
      output[written++] = {.kind =
                               Ipv6NeighborActionKind::unicast_solicitation,
                           .interface_id = target.interface_id,
                           .address = target.address,
                           .mac = target.mac};
      continue;
    }

    const bool multicast = target.state == Ipv6NeighborState::incomplete;
    const auto maximum = multicast
                             ? device_catalog::nd_max_multicast_solicit
                             : device_catalog::nd_max_unicast_solicit;
    if ((multicast || target.state == Ipv6NeighborState::probe) &&
        target.probes_sent < maximum) {
      ++target.probes_sent;
      target.deadline = now + device_catalog::nd_retrans_timer;
      output[written++] = {
          .kind = multicast
                      ? Ipv6NeighborActionKind::multicast_solicitation
                      : Ipv6NeighborActionKind::unicast_solicitation,
          .interface_id = target.interface_id,
          .address = target.address,
          .mac = target.mac};
      continue;
    }

    output[written++] = {.kind = Ipv6NeighborActionKind::resolution_failed,
                         .interface_id = target.interface_id,
                         .address = target.address,
                         .mac = target.mac};
    erase_entry(target);
  }
  trim_unused_tail();
  return written;
}

std::optional<Ipv6NeighborCache::Clock::time_point>
Ipv6NeighborCache::next_deadline() const noexcept {
  auto result = Clock::time_point::max();
  for (const auto &target : entries_)
    if (target.valid && target.deadline < result)
      result = target.deadline;
  return result == Clock::time_point::max()
             ? std::nullopt
             : std::optional<Clock::time_point>{result};
}

std::optional<Ipv6NeighborSnapshot>
Ipv6NeighborCache::find(std::uint64_t interface_id,
                        const ip::Ipv6 &address) const noexcept {
  const auto *target = entry(interface_id, address);
  if (!target)
    return std::nullopt;
  return Ipv6NeighborSnapshot{.interface_id = target->interface_id,
                              .address = target->address,
                              .mac = target->mac,
                              .state = target->state,
                              .is_router = target->is_router,
                              .is_static = target->is_static};
}

std::size_t Ipv6NeighborCache::size() const noexcept {
  return indexed_entries_;
}

std::size_t
Ipv6NeighborCache::dynamic_size(std::uint64_t interface_id) const noexcept {
  // Limit accounting is interface-local and excludes administrator-owned
  // static mappings exactly as the SR OS neighbor-limit description requires.
  return static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(), [interface_id](const Entry &entry) {
        return entry.valid && !entry.is_static &&
               entry.interface_id == interface_id;
      }));
}

void Ipv6NeighborCache::remove_interface(std::uint64_t interface_id) noexcept {
  // Removing an IP interface invalidates only its RFC 4007 zone. Another SAP
  // on the same physical port must retain its independent neighbor mappings.
  for (auto &target : entries_)
    if (target.valid && target.interface_id == interface_id)
      erase_entry(target);
  trim_unused_tail();
}

void Ipv6NeighborCache::trim_unused_tail() noexcept {
  // Erasing only a vacant suffix cannot move a live Entry. Calls happen after
  // an owner operation has finished using entry pointers, so vector shrinkage
  // cannot invalidate an in-flight forwarding reference.
  while (!entries_.empty() && !entries_.back().valid)
    entries_.pop_back();
}

std::vector<Ipv6NeighborCheckpoint>
Ipv6NeighborCache::checkpoint(Clock::time_point now) const {
  std::vector<Ipv6NeighborCheckpoint> result;
  result.reserve(size());
  for (const auto &target : entries_) {
    if (!target.valid)
      continue;
    const bool has_deadline = target.deadline != Clock::time_point::max();
    const auto remaining = has_deadline && target.deadline > now
                               ? target.deadline - now
                               : Clock::duration::zero();
    result.push_back({
        .interface_id = target.interface_id,
        .address = target.address,
        .mac = target.mac,
        .state = target.state,
        .is_router = target.is_router,
        .is_static = target.is_static,
        .has_deadline = has_deadline,
        .probes_sent = target.probes_sent,
        .use_generation = target.use_generation,
        .remaining_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                .count(),
        .stale_time_seconds =
            static_cast<std::uint32_t>(target.stale_time.count()),
        .proactive_refresh = target.proactive_refresh});
  }
  return result;
}

bool Ipv6NeighborCache::validate_checkpoint(
    std::span<const Ipv6NeighborCheckpoint> state) noexcept {
  if (state.size() > device_catalog::ipv6_neighbor_entries_per_router)
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &target = state[index];
    const bool incomplete = target.state == Ipv6NeighborState::incomplete;
    const bool reachable = target.state == Ipv6NeighborState::reachable;
    const bool stale = target.state == Ipv6NeighborState::stale;
    const bool delay = target.state == Ipv6NeighborState::delay;
    const bool probe = target.state == Ipv6NeighborState::probe;
    const bool mac_is_usable =
        (target.mac[0] & 1U) == 0U &&
        std::any_of(target.mac.begin(), target.mac.end(),
                    [](auto byte) { return byte != 0U; });

    // Each NUD state has one legal timer shape. Enforcing it here prevents a
    // corrupted checkpoint from creating an immortal INCOMPLETE entry or a
    // STALE entry with an unbounded vendor aging timer after restore.
    if (target.interface_id == 0U ||
        ip::is_unspecified(target.address) ||
        ip::is_multicast(target.address) || target.remaining_nanoseconds < 0 ||
        target.stale_time_seconds <
            device_catalog::nd_minimum_stale_time_seconds ||
        target.stale_time_seconds >
            device_catalog::nd_maximum_stale_time_seconds ||
        (!incomplete && !reachable && !stale && !delay && !probe) ||
        (!target.is_static &&
         ((incomplete &&
           (!target.has_deadline || target.probes_sent == 0U ||
            target.probes_sent > device_catalog::nd_max_multicast_solicit)) ||
          (reachable && (!target.has_deadline || target.probes_sent != 0U)) ||
          (stale && (!target.has_deadline || target.probes_sent != 0U)) ||
          (delay && (!target.has_deadline || target.probes_sent != 0U)) ||
          (probe &&
           (!target.has_deadline || target.probes_sent == 0U ||
            target.probes_sent > device_catalog::nd_max_unicast_solicit)))) ||
        (!incomplete && !mac_is_usable) ||
        (target.is_static &&
         (incomplete || target.has_deadline || target.probes_sent != 0U ||
          !mac_is_usable)))
      return false;

    // Duplicate scoped addresses would make lookup depend on vector order.
    // The O(n^2) validation is confined to the cold checkpoint path and avoids
    // allocating a second maximum-profile hash table during restore.
    for (std::size_t previous = 0; previous < index; ++previous)
      if (state[previous].interface_id == target.interface_id &&
          state[previous].address == target.address)
        return false;
  }
  return true;
}

bool Ipv6NeighborCache::restore(
    std::span<const Ipv6NeighborCheckpoint> state,
    Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;

  // Build a complete replacement before touching live state. Allocation can
  // fail when a large project is restored near the Wasm ceiling; the existing
  // cache must remain usable in that case.
  std::vector<Entry> replacement;
  try {
    replacement.resize(state.size());
  } catch (...) {
    return false;
  }
  std::uint64_t replacement_generation{};
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &source = state[index];
    replacement[index] = {
        .valid = true,
        .is_router = source.is_router,
        .is_static = source.is_static,
        .interface_id = source.interface_id,
        .address = source.address,
        .mac = source.mac,
        .state = source.state,
        .probes_sent = source.probes_sent,
        .use_generation = source.use_generation,
        .deadline = source.has_deadline
                        ? now + std::chrono::nanoseconds(
                                    source.remaining_nanoseconds)
                        : Clock::time_point::max(),
        .stale_time = std::chrono::seconds{source.stale_time_seconds},
        .proactive_refresh = source.proactive_refresh};
    replacement_generation =
        std::max(replacement_generation, source.use_generation);
  }
  Ipv6NeighborCache staged;
  staged.entries_.swap(replacement);
  if (!staged.ensure_index_capacity(staged.entries_.size()))
    return false;
  staged.use_generation_ = replacement_generation;

  // Only fully indexed state is published. The derived slot layout may vary
  // across builds, but authoritative entries and their LRU generation do not.
  entries_.swap(staged.entries_);
  index_.swap(staged.index_);
  indexed_entries_ = staged.indexed_entries_;
  use_generation_ = staged.use_generation_;
  return true;
}

} // namespace router::lab
