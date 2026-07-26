// RFC 1191 Path MTU state transitions. This cold per-destination repository
// uses fixed storage so forged ICMP traffic cannot allocate without bound or
// introduce a hidden topology-dependent resource policy.

#include "router/ipv4_path_mtu.hpp"

#include <algorithm>

namespace router::ip {
namespace {

bool unspecified(packet::Ipv4 address) noexcept {
  return address == packet::Ipv4{};
}

// RFC 1191 table 7-1 recommends these search plateaus. They are protocol
// constants, not laboratory assumptions. Values are descending so both the
// old-router fallback and upward probe choose one value with a linear scan.
constexpr std::array<std::uint32_t, 11U> mtu_plateaus{
    65'535U, 32'000U, 17'914U, 8'166U, 4'352U, 2'002U,
    1'492U, 1'006U, 508U, 296U, packet::ipv4_minimum_reassembly_octets};

std::uint32_t lower_plateau(std::uint32_t upper_bound) noexcept {
  const auto found = std::find_if(mtu_plateaus.begin(), mtu_plateaus.end(),
                                  [upper_bound](std::uint32_t candidate) {
                                    return candidate < upper_bound;
                                  });
  return found == mtu_plateaus.end() ? 0U : *found;
}

std::uint32_t higher_plateau(std::uint32_t current,
                             std::uint32_t first_hop_mtu) noexcept {
  // Iterate from the smallest plateau upward and return the first strictly
  // larger candidate. The first-hop interface remains an absolute ceiling.
  for (auto iterator = mtu_plateaus.rbegin(); iterator != mtu_plateaus.rend();
       ++iterator)
    if (*iterator > current)
      return std::min(*iterator, first_hop_mtu);
  return first_hop_mtu;
}

} // namespace

Ipv4PathMtuEntry *Ipv4PathMtuCache::find(
    packet::Ipv4 destination, std::uint64_t interface_id) noexcept {
  for (auto &entry : entries_)
    if (entry.occupied && entry.destination == destination &&
        entry.interface_id == interface_id)
      return &entry;
  return nullptr;
}

const Ipv4PathMtuEntry *Ipv4PathMtuCache::find(
    packet::Ipv4 destination, std::uint64_t interface_id) const noexcept {
  for (const auto &entry : entries_)
    if (entry.occupied && entry.destination == destination &&
        entry.interface_id == interface_id)
      return &entry;
  return nullptr;
}

std::uint32_t Ipv4PathMtuCache::estimate(
    packet::Ipv4 destination, std::uint64_t interface_id,
    std::uint32_t first_hop_mtu) const noexcept {
  const auto *entry = find(destination, interface_id);
  return entry ? std::min(entry->mtu, first_hop_mtu) : first_hop_mtu;
}

std::uint32_t Ipv4PathMtuCache::begin_probe(
    packet::Ipv4 destination, std::uint64_t interface_id,
    std::uint32_t first_hop_mtu, std::uint32_t packet_octets,
    Clock::time_point now) noexcept {
  auto *entry = find(destination, interface_id);
  if (!entry || entry->probe_after > now)
    return entry ? std::min(entry->mtu, first_hop_mtu) : first_hop_mtu;

  const auto current = std::min(entry->mtu, first_hop_mtu);
  const auto raised = higher_plateau(current, first_hop_mtu);
  // A short request cannot demonstrate that the path carries the proposed
  // larger datagram. It therefore uses the confirmed PMTU and leaves the due
  // state intact for a later packet that can actually exercise the plateau.
  if (raised <= current || packet_octets < raised)
    return current;
  entry->probe_mtu = raised;
  // RFC 1191 recommends two minutes after an attempted increase. Scheduling
  // it here means a burst of local sends performs one experiment, not one per
  // packet. Other sends continue using mtu until confirm_probe publishes the
  // successful experiment.
  entry->probe_after =
      now + device_catalog::ipv4_pmtu_probe_retry_interval;
  return raised;
}

bool Ipv4PathMtuCache::confirm_probe(packet::Ipv4 destination,
                                     std::uint64_t interface_id,
                                     Clock::time_point now) noexcept {
  auto *entry = find(destination, interface_id);
  if (!entry || entry->probe_mtu <= entry->mtu)
    return false;
  entry->mtu = entry->probe_mtu;
  entry->probe_mtu = 0U;
  // A confirmed increase restarts the conservative ten-minute observation
  // interval. This avoids immediately testing a second plateau on the next
  // successful request in the same application burst.
  entry->probe_after = now + device_catalog::ipv4_pmtu_probe_interval;
  return true;
}

Ipv4PathMtuUpdate Ipv4PathMtuCache::update(
    packet::Ipv4 destination, std::uint64_t interface_id,
    std::uint32_t reported_mtu, std::uint32_t quoted_total_length,
    std::uint32_t first_hop_mtu, Clock::time_point now) noexcept {
  if (unspecified(destination) || !interface_id ||
      first_hop_mtu < packet::ipv4_minimum_reassembly_octets ||
      quoted_total_length < packet::ipv4_minimum_reassembly_octets)
    return Ipv4PathMtuUpdate::invalid_report;

  auto candidate = reported_mtu;
  if (candidate == 0U)
    candidate = lower_plateau(quoted_total_length);
  if (candidate < packet::ipv4_minimum_reassembly_octets)
    return Ipv4PathMtuUpdate::invalid_report;

  auto *entry = find(destination, interface_id);
  const auto current = entry ? std::min(entry->mtu, first_hop_mtu)
                             : first_hop_mtu;
  if (candidate >= current) {
    // A matched Too Big response rejects any outstanding upward experiment,
    // even when its advertised MTU cannot legally raise the confirmed value.
    // Keeping probe_mtu here would allow an unrelated later Echo Reply to
    // publish a candidate that this router already disproved.
    if (entry) {
      entry->probe_mtu = 0U;
      entry->probe_after = now + device_catalog::ipv4_pmtu_probe_interval;
    }
    return Ipv4PathMtuUpdate::unchanged;
  }
  if (!entry) {
    const auto free = std::find_if(entries_.begin(), entries_.end(),
                                   [](const auto &value) {
                                     return !value.occupied;
                                   });
    if (free == entries_.end())
      return Ipv4PathMtuUpdate::resource_exhausted;
    entry = &*free;
  }
  *entry = {.destination = destination,
            .probe_after =
                now + device_catalog::ipv4_pmtu_probe_interval,
            .interface_id = interface_id,
            .mtu = candidate,
            .probe_mtu = 0U,
            .occupied = true};
  return Ipv4PathMtuUpdate::decreased;
}

void Ipv4PathMtuCache::remove_interface(
    std::uint64_t interface_id) noexcept {
  for (auto &entry : entries_)
    if (entry.occupied && entry.interface_id == interface_id)
      entry = {};
}

void Ipv4PathMtuCache::clear() noexcept { entries_.fill({}); }

std::size_t Ipv4PathMtuCache::size() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(),
      [](const auto &entry) { return entry.occupied; }));
}

std::vector<Ipv4PathMtuCheckpoint>
Ipv4PathMtuCache::checkpoint(Clock::time_point now) const {
  std::vector<Ipv4PathMtuCheckpoint> state;
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

bool Ipv4PathMtuCache::validate_checkpoint(
    const std::vector<Ipv4PathMtuCheckpoint> &state) noexcept {
  if (state.size() > device_catalog::ipv4_pmtu_entries_per_endpoint)
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &entry = state[index];
    if (unspecified(entry.destination) || !entry.interface_id ||
        entry.mtu < packet::ipv4_minimum_reassembly_octets ||
        entry.mtu > packet::maximum_ipv4_datagram_octets ||
        (entry.probe_mtu != 0U &&
         (entry.probe_mtu <= entry.mtu ||
          entry.probe_mtu > packet::maximum_ipv4_datagram_octets)) ||
        entry.remaining_probe_nanoseconds < 0)
      return false;
    for (std::size_t previous = 0; previous < index; ++previous)
      if (state[previous].destination == entry.destination &&
          state[previous].interface_id == entry.interface_id)
        return false;
  }
  return true;
}

bool Ipv4PathMtuCache::restore(
    const std::vector<Ipv4PathMtuCheckpoint> &state,
    Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  entries_.fill({});
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &entry = state[index];
    entries_[index] = {
        .destination = entry.destination,
        .probe_after =
            now + std::chrono::nanoseconds(entry.remaining_probe_nanoseconds),
        .interface_id = entry.interface_id,
        .mtu = entry.mtu,
        .probe_mtu = entry.probe_mtu,
        .occupied = true};
  }
  return true;
}

} // namespace router::ip
