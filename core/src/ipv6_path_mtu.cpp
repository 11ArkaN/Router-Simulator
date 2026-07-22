// RFC 8201 cache mechanics. A destination plus stable interface identity is
// the local path representation, preserving distinct estimates on multihomed
// nodes without pretending to know the editor topology or ECMP internals.

#include "router/ipv6_path_mtu.hpp"

#include <algorithm>

namespace router::ip {

Ipv6PathMtuEntry *Ipv6PathMtuCache::find(
    const Ipv6 &destination, std::uint64_t interface_id) noexcept {
  for (auto &entry : entries_)
    if (entry.occupied && entry.destination == destination &&
        entry.interface_id == interface_id)
      return &entry;
  return nullptr;
}

const Ipv6PathMtuEntry *Ipv6PathMtuCache::find(
    const Ipv6 &destination, std::uint64_t interface_id) const noexcept {
  for (const auto &entry : entries_)
    if (entry.occupied && entry.destination == destination &&
        entry.interface_id == interface_id)
      return &entry;
  return nullptr;
}

std::uint32_t Ipv6PathMtuCache::estimate(
    const Ipv6 &destination, std::uint64_t interface_id,
    std::uint32_t first_hop_mtu) const noexcept {
  const auto *entry = find(destination, interface_id);
  return entry ? std::min(entry->mtu, first_hop_mtu) : first_hop_mtu;
}

std::uint32_t Ipv6PathMtuCache::begin_probe(
    const Ipv6 &destination, std::uint64_t interface_id,
    std::uint32_t first_hop_mtu, std::uint32_t packet_octets,
    Clock::time_point now) noexcept {
  auto *entry = find(destination, interface_id);
  if (!entry || entry->probe_after > now)
    return entry ? std::min(entry->mtu, first_hop_mtu) : first_hop_mtu;

  const auto current = std::min(entry->mtu, first_hop_mtu);
  // A successful packet proves only its own size. The first-hop link remains
  // the upper bound even when an application asks to send a larger datagram
  // that the source will fragment before it reaches the wire.
  const auto candidate = std::min(packet_octets, first_hop_mtu);
  if (candidate <= current)
    return current;

  entry->probe_mtu = candidate;
  // RFC 8201 recommends ten minutes and forbids retry intervals below five
  // minutes. Reusing the generated ten-minute profile means a burst produces
  // one experiment and a lost reply cannot create continuous probe traffic.
  entry->probe_after = now + device_catalog::ipv6_pmtu_probe_interval;
  return candidate;
}

bool Ipv6PathMtuCache::confirm_probe(const Ipv6 &destination,
                                     std::uint64_t interface_id,
                                     Clock::time_point now) noexcept {
  auto *entry = find(destination, interface_id);
  if (!entry || entry->probe_mtu <= entry->mtu)
    return false;
  entry->mtu = entry->probe_mtu;
  entry->probe_mtu = 0U;
  entry->probe_after = now + device_catalog::ipv6_pmtu_probe_interval;
  return true;
}

PathMtuUpdate Ipv6PathMtuCache::update(
    const Ipv6 &destination, std::uint64_t interface_id,
    std::uint32_t reported_mtu, std::uint32_t first_hop_mtu,
    Clock::time_point now) noexcept {
  // RFC 8201 requires a PTB below 1280 to be discarded. Zero interface
  // identity and an unusable first-hop MTU are control-contract violations,
  // not cache keys with special meanings.
  if (!interface_id || is_unspecified(destination) ||
      reported_mtu < packet::ipv6_minimum_link_mtu ||
      first_hop_mtu < packet::ipv6_minimum_link_mtu)
    return PathMtuUpdate::invalid_report;
  auto *entry = find(destination, interface_id);
  const auto current = entry ? std::min(entry->mtu, first_hop_mtu)
                             : first_hop_mtu;
  if (reported_mtu >= current) {
    // A quote-matched PTB disproves an outstanding larger experiment even
    // when its MTU field does not lower the already conservative estimate.
    // Keeping that candidate would let a delayed Echo Reply raise the cache.
    if (entry) {
      entry->probe_mtu = 0U;
      entry->probe_after = now + device_catalog::ipv6_pmtu_probe_interval;
    }
    return PathMtuUpdate::unchanged;
  }
  if (!entry) {
    const auto free = std::find_if(entries_.begin(), entries_.end(),
                                   [](const auto &candidate) {
                                     return !candidate.occupied;
                                   });
    if (free == entries_.end())
      return PathMtuUpdate::resource_exhausted;
    entry = &*free;
  }
  *entry = {.destination = destination,
            .probe_after = now + device_catalog::ipv6_pmtu_probe_interval,
            .interface_id = interface_id,
            .mtu = reported_mtu,
            .probe_mtu = 0U,
            .occupied = true};
  return PathMtuUpdate::decreased;
}

void Ipv6PathMtuCache::remove_interface(std::uint64_t interface_id) noexcept {
  for (auto &entry : entries_)
    if (entry.occupied && entry.interface_id == interface_id)
      entry = {};
}

void Ipv6PathMtuCache::clear() noexcept { entries_.fill({}); }

std::size_t Ipv6PathMtuCache::size() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(),
      [](const auto &entry) { return entry.occupied; }));
}

std::vector<Ipv6PathMtuCheckpoint>
Ipv6PathMtuCache::checkpoint(Clock::time_point now) const {
  std::vector<Ipv6PathMtuCheckpoint> state;
  state.reserve(size());
  for (const auto &entry : entries_) {
    if (!entry.occupied)
      continue;
    const auto remaining = entry.probe_after > now
                               ? entry.probe_after - now
                               : Clock::duration::zero();
    state.push_back({
        .destination = entry.destination,
        .remaining_probe_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                .count(),
        .interface_id = entry.interface_id,
        .mtu = entry.mtu,
        .probe_mtu = entry.probe_mtu});
  }
  return state;
}

bool Ipv6PathMtuCache::validate_checkpoint(
    const std::vector<Ipv6PathMtuCheckpoint> &state) noexcept {
  if (state.size() > device_catalog::ipv6_pmtu_entries_per_endpoint)
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &entry = state[index];
    if (is_unspecified(entry.destination) || !entry.interface_id ||
        entry.mtu < packet::ipv6_minimum_link_mtu ||
        (entry.probe_mtu != 0U &&
         (entry.probe_mtu <= entry.mtu ||
          entry.probe_mtu > packet::ipv6_header_octets +
                                packet::maximum_ipv6_payload_octets)) ||
        entry.remaining_probe_nanoseconds < 0)
      return false;
    // Duplicate keys are rejected instead of allowing checkpoint order to
    // decide which estimate survives restore.
    for (std::size_t previous = 0; previous < index; ++previous)
      if (state[previous].destination == entry.destination &&
          state[previous].interface_id == entry.interface_id)
        return false;
  }
  return true;
}

bool Ipv6PathMtuCache::restore(
    const std::vector<Ipv6PathMtuCheckpoint> &state,
    Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  entries_.fill({});
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &source = state[index];
    entries_[index] = {
        .destination = source.destination,
        .probe_after =
            now + std::chrono::nanoseconds(source.remaining_probe_nanoseconds),
        .interface_id = source.interface_id,
        .mtu = source.mtu,
        .probe_mtu = source.probe_mtu,
        .occupied = true};
  }
  return true;
}

} // namespace router::ip
