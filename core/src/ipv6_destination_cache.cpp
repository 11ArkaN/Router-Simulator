// RFC 4861 Destination Cache implementation. The cache is a host-side routing
// optimization only. Routers must ignore received Redirects and therefore do
// not instantiate or call this owner from their forwarding path.

#include "router/ipv6_destination_cache.hpp"

#include "router/ip_address.hpp"

#include <algorithm>

namespace router::lab {

Ipv6DestinationCache::Ipv6DestinationCache()
    : entries_(device_catalog::ipv6_destination_entries_per_endpoint) {}

void Ipv6DestinationCache::touch(Entry &entry) noexcept {
  ++use_generation_;
  if (!use_generation_)
    use_generation_ = 1U;
  entry.use_generation = use_generation_;
}

Ipv6DestinationCache::Entry *Ipv6DestinationCache::find(
    std::uint16_t port_ordinal,
    const packet::Ipv6 &destination) noexcept {
  const auto found = std::find_if(entries_.begin(), entries_.end(),
                                  [&](const auto &entry) {
    return entry.valid && entry.port_ordinal == port_ordinal &&
           entry.destination == destination;
  });
  return found == entries_.end() ? nullptr : &*found;
}

Ipv6DestinationCache::Entry *Ipv6DestinationCache::allocate() noexcept {
  if (const auto free = std::find_if(entries_.begin(), entries_.end(),
                                     [](const auto &entry) {
                                       return !entry.valid;
                                     });
      free != entries_.end())
    return &*free;
  // Destination Cache is advisory. Replacing the least recently used entry
  // falls back to normal route and ND resolution for that destination and can
  // never drop an already queued packet.
  return &*std::min_element(entries_.begin(), entries_.end(),
                            [](const auto &left, const auto &right) {
                              return left.use_generation <
                                     right.use_generation;
                            });
}

bool Ipv6DestinationCache::accept_redirect(
    std::uint16_t port_ordinal, const packet::nd::RedirectView &redirect,
    const packet::Ipv6 &current_first_hop,
    const packet::Ipv6 &route_first_hop) noexcept {
  if (!ip::is_link_local(redirect.source) ||
      redirect.source != current_first_hop ||
      ip::is_unspecified(route_first_hop) ||
      ip::is_multicast(route_first_hop) ||
      ip::is_unspecified(redirect.destination) ||
      ip::is_multicast(redirect.destination) ||
      !(ip::is_link_local(redirect.target) ||
        redirect.target == redirect.destination))
    return false;
  auto *entry = find(port_ordinal, redirect.destination);
  if (!entry)
    entry = allocate();
  *entry = {.valid = true,
            .port_ordinal = port_ordinal,
            .destination = redirect.destination,
            .next_hop = redirect.target,
            .route_first_hop = route_first_hop,
            .use_generation = 0U};
  touch(*entry);
  return true;
}

packet::Ipv6 Ipv6DestinationCache::current_next_hop(
    std::uint16_t port_ordinal, const packet::Ipv6 &destination,
    const packet::Ipv6 &route_first_hop) noexcept {
  auto *entry = find(port_ordinal, destination);
  if (!entry || entry->route_first_hop != route_first_hop)
    return route_first_hop;
  touch(*entry);
  return entry->next_hop;
}

void Ipv6DestinationCache::remove_port(std::uint16_t port_ordinal) noexcept {
  for (auto &entry : entries_)
    if (entry.valid && entry.port_ordinal == port_ordinal)
      entry = {};
}

std::size_t Ipv6DestinationCache::size() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(),
      [](const auto &entry) { return entry.valid; }));
}

std::vector<Ipv6DestinationCheckpoint>
Ipv6DestinationCache::checkpoint() const {
  std::vector<Ipv6DestinationCheckpoint> state;
  state.reserve(size());
  for (const auto &entry : entries_)
    if (entry.valid)
      state.push_back({.destination = entry.destination,
                       .next_hop = entry.next_hop,
                       .route_first_hop = entry.route_first_hop,
                       .port_ordinal = entry.port_ordinal,
                       .use_generation = entry.use_generation});
  return state;
}

bool Ipv6DestinationCache::validate_checkpoint(
    std::span<const Ipv6DestinationCheckpoint> state) noexcept {
  if (state.size() >
      device_catalog::ipv6_destination_entries_per_endpoint)
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &entry = state[index];
    if (ip::is_unspecified(entry.destination) ||
        ip::is_multicast(entry.destination) ||
        (ip::is_unspecified(entry.route_first_hop) ||
         ip::is_multicast(entry.route_first_hop)) ||
        !(ip::is_link_local(entry.next_hop) ||
          entry.next_hop == entry.destination) ||
        !entry.use_generation)
      return false;
    for (std::size_t other = 0; other < index; ++other)
      if (state[other].port_ordinal == entry.port_ordinal &&
          state[other].destination == entry.destination)
        return false;
  }
  return true;
}

bool Ipv6DestinationCache::restore(
    std::span<const Ipv6DestinationCheckpoint> state) noexcept {
  if (!validate_checkpoint(state))
    return false;
  std::fill(entries_.begin(), entries_.end(), Entry{});
  use_generation_ = 0U;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &source = state[index];
    entries_[index] = {.valid = true,
                       .port_ordinal = source.port_ordinal,
                       .destination = source.destination,
                       .next_hop = source.next_hop,
                       .route_first_hop = source.route_first_hop,
                       .use_generation = source.use_generation};
    use_generation_ = std::max(use_generation_, source.use_generation);
  }
  return true;
}

} // namespace router::lab
