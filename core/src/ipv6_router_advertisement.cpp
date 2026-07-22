// Router Advertisement deadline implementation. It uses only steady-clock
// deadlines local to the forwarding owner and never schedules work globally.

#include "router/ipv6_router_advertisement.hpp"

#include <algorithm>
#include <limits>

namespace router::lab {
namespace {

[[nodiscard]] std::uint64_t seed(std::uint16_t port,
                                 Ipv6RouterAdvertisementTable::Clock::time_point
                                     now) noexcept {
  // RA jitter is not a security primitive. The mixed steady-clock count and
  // stable port identity avoid synchronized interfaces without introducing a
  // shared PRNG or nondeterministic cross-shard mutable state.
  auto value = static_cast<std::uint64_t>(now.time_since_epoch().count()) ^
               (static_cast<std::uint64_t>(port) << 32U) ^
               0x9e3779b97f4a7c15ULL;
  value ^= value >> 30U;
  value *= 0xbf58476d1ce4e5b9ULL;
  value ^= value >> 27U;
  value *= 0x94d049bb133111ebULL;
  value ^= value >> 31U;
  return value ? value : 1U;
}

} // namespace

Ipv6RouterAdvertisementTable::Entry *
Ipv6RouterAdvertisementTable::find(std::uint16_t port_ordinal) noexcept {
  for (auto &entry : entries_)
    if (entry.occupied && entry.port_ordinal == port_ordinal)
      return &entry;
  return nullptr;
}

std::chrono::nanoseconds Ipv6RouterAdvertisementTable::random_delay(
    Entry &entry, std::chrono::nanoseconds maximum) noexcept {
  // xorshift64* gives a uniform bounded scheduling sample without allocation.
  // Modulo bias at nanosecond scale is negligible for protocol timer jitter,
  // while adding rejection sampling would make the owner loop unbounded.
  auto value = entry.random_state;
  value ^= value >> 12U;
  value ^= value << 25U;
  value ^= value >> 27U;
  entry.random_state = value;
  const auto sample = value * 0x2545f4914f6cdd1dULL;
  const auto bound = static_cast<std::uint64_t>(maximum.count());
  return std::chrono::nanoseconds{bound ? sample % (bound + 1U) : 0U};
}

std::chrono::nanoseconds
Ipv6RouterAdvertisementTable::periodic_delay(Entry &entry) noexcept {
  if (entry.initial_advertisements_remaining > 1U) {
    --entry.initial_advertisements_remaining;
    return random_delay(entry,
                        device_catalog::ra_max_initial_advertisement_interval);
  }
  entry.initial_advertisements_remaining = 0U;
  const auto minimum = std::chrono::seconds{
      entry.config.min_advertisement_interval_seconds};
  const auto maximum = std::chrono::seconds{
      entry.config.max_advertisement_interval_seconds};
  return minimum + random_delay(entry, maximum - minimum);
}

bool Ipv6RouterAdvertisementTable::configure(
    std::uint16_t port_ordinal, bool enabled,
    const packet::nd::RouterAdvertisementConfig &config,
    Clock::time_point now, bool link_ready) noexcept {
  if (!valid_config(config))
    return false;

  auto *entry = find(port_ordinal);
  if (!entry) {
    const auto available =
        std::find_if(entries_.begin(), entries_.end(),
                     [](const auto &candidate) {
                       return !candidate.occupied;
                     });
    if (available == entries_.end())
      return false;
    entry = &*available;
  }
  // Reconfiguration starts a fresh initial-advertisement sequence. The old
  // deadline cannot leak configuration bytes from a prior candidate commit.
  *entry = Entry{.config = config,
                 .random_state = seed(port_ordinal, now),
                 .port_ordinal = port_ordinal,
                 .initial_advertisements_remaining =
                     device_catalog::ra_max_initial_advertisements,
                 .occupied = true,
                 .requested_enabled = enabled,
                 .active = enabled && link_ready};
  if (entry->active)
    entry->next = now + random_delay(
                            *entry,
                            device_catalog::ra_max_initial_advertisement_interval);
  return true;
}

void Ipv6RouterAdvertisementTable::set_link_ready(
    std::uint16_t port_ordinal, bool ready, Clock::time_point now) noexcept {
  auto *entry = find(port_ordinal);
  if (!entry)
    return;
  const bool activate = entry->requested_enabled && ready;
  if (activate == entry->active)
    return;
  entry->active = activate;
  if (activate) {
    // Becoming operational starts a fresh initial sequence. Time spent without
    // a preferred link-local address is not counted as an advertisement.
    entry->initial_advertisements_remaining =
        device_catalog::ra_max_initial_advertisements;
    entry->has_sent = false;
    entry->next = now + random_delay(
                            *entry,
                            device_catalog::ra_max_initial_advertisement_interval);
  }
}

bool Ipv6RouterAdvertisementTable::valid_config(
    const packet::nd::RouterAdvertisementConfig &config) noexcept {
  const auto minimum = std::chrono::seconds{
      config.min_advertisement_interval_seconds};
  const auto maximum = std::chrono::seconds{
      config.max_advertisement_interval_seconds};
  const auto lifetime =
      std::chrono::seconds{config.router_lifetime_seconds};
  // SR OS exposes independent numeric ranges, while RFC 4861 additionally
  // requires MinRtrAdvInterval not to exceed 0.75 MaxRtrAdvInterval.
  if (!(minimum >= device_catalog::ra_minimum_min_advertisement_interval &&
         minimum <= device_catalog::ra_maximum_min_advertisement_interval &&
         maximum >= device_catalog::ra_minimum_max_advertisement_interval &&
          maximum <= device_catalog::ra_maximum_max_advertisement_interval &&
          minimum * 4 <= maximum * 3 &&
          (lifetime.count() == 0 ||
           (lifetime >= device_catalog::ra_minimum_nonzero_router_lifetime &&
            lifetime <= device_catalog::ra_maximum_router_lifetime &&
            lifetime >= maximum)) &&
          config.reachable_time_milliseconds <=
              static_cast<std::uint32_t>(
                  device_catalog::ra_maximum_reachable_time.count()) &&
          config.retrans_timer_milliseconds <=
              static_cast<std::uint32_t>(
                  device_catalog::ra_maximum_retransmit_time.count()) &&
          config.prefix_count <= config.prefixes.size() &&
          config.rdnss.count <= config.rdnss.servers.size() &&
          (config.advertised_mtu == 0U ||
           (config.advertised_mtu >=
                device_catalog::ra_minimum_advertised_mtu &&
            config.advertised_mtu <=
                device_catalog::ra_maximum_advertised_mtu))))
    return false;
  for (std::size_t index = 0; index < config.prefix_count; ++index) {
    const auto &prefix = config.prefixes[index];
    if (prefix.prefix.length > ip::ipv6_address_bits ||
        ip::mask(prefix.prefix.network, prefix.prefix.length) !=
            prefix.prefix.network ||
        ip::is_link_local(prefix.prefix.network) ||
        prefix.preferred_lifetime_seconds > prefix.valid_lifetime_seconds)
      return false;
  }
  if (config.rdnss_lifetime_seconds != device_catalog::ra_infinite_lifetime &&
      (config.rdnss_lifetime_seconds <
           device_catalog::ra_minimum_rdnss_lifetime ||
       config.rdnss_lifetime_seconds >
           device_catalog::ra_maximum_rdnss_lifetime))
    return false;
  for (std::size_t index = 0; index < config.rdnss.count; ++index) {
    const auto &server = config.rdnss.servers[index];
    if (ip::is_unspecified(server.address) || ip::is_multicast(server.address))
      return false;
  }
  return true;
}

void Ipv6RouterAdvertisementTable::remove(
    std::uint16_t port_ordinal) noexcept {
  if (auto *entry = find(port_ordinal))
    *entry = {};
}

void Ipv6RouterAdvertisementTable::observe_solicitation(
    std::uint16_t port_ordinal, Clock::time_point now) noexcept {
  auto *entry = find(port_ordinal);
  if (!entry || !entry->active)
    return;
  auto response = now + random_delay(*entry,
                                     device_catalog::ra_max_response_delay);
  if (entry->has_sent)
    response = std::max(
        response,
        entry->last_sent + device_catalog::ra_min_delay_between_advertisements);
  entry->next = std::min(entry->next, response);
}

std::size_t Ipv6RouterAdvertisementTable::poll(
    Clock::time_point now,
    std::span<RouterAdvertisementAction> actions) noexcept {
  std::size_t count{};
  for (auto &entry : entries_) {
    if (!entry.occupied || !entry.active || entry.next > now)
      continue;
    if (count == actions.size())
      break;
    actions[count++] = {.port_ordinal = entry.port_ordinal,
                        .config = entry.config};
    entry.has_sent = true;
    entry.last_sent = now;
    entry.next = now + periodic_delay(entry);
  }
  return count;
}

std::optional<Ipv6RouterAdvertisementTable::Clock::time_point>
Ipv6RouterAdvertisementTable::next_deadline() const noexcept {
  std::optional<Clock::time_point> result;
  for (const auto &entry : entries_)
    if (entry.occupied && entry.active &&
        (!result || entry.next < *result))
      result = entry.next;
  return result;
}

std::vector<Ipv6RouterAdvertisementCheckpoint>
Ipv6RouterAdvertisementTable::checkpoint(Clock::time_point now) const {
  std::vector<Ipv6RouterAdvertisementCheckpoint> result;
  result.reserve(entries_.size());
  for (const auto &entry : entries_) {
    if (!entry.occupied)
      continue;
    const auto remaining = entry.active && entry.next > now
                               ? entry.next - now
                               : Clock::duration::zero();
    const auto elapsed = entry.has_sent && now > entry.last_sent
                             ? now - entry.last_sent
                             : Clock::duration::zero();
    result.push_back({
        .config = entry.config,
        .remaining_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                .count(),
        .last_sent_ago_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed)
                .count(),
        .random_state = entry.random_state,
        .port_ordinal = entry.port_ordinal,
        .initial_advertisements_remaining =
            entry.initial_advertisements_remaining,
        .requested_enabled = entry.requested_enabled,
        .active = entry.active,
        .has_sent = entry.has_sent});
  }
  return result;
}

bool Ipv6RouterAdvertisementTable::validate_checkpoint(
    std::span<const Ipv6RouterAdvertisementCheckpoint> state) noexcept {
  if (state.size() > capacity)
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &entry = state[index];
    if (entry.port_ordinal >= capacity || entry.remaining_nanoseconds < 0 ||
        entry.last_sent_ago_nanoseconds < 0 || entry.random_state == 0U ||
        (entry.active && !entry.requested_enabled) ||
        entry.initial_advertisements_remaining >
            device_catalog::ra_max_initial_advertisements ||
        !valid_config(entry.config))
      return false;
    for (std::size_t prior = 0; prior < index; ++prior)
      if (state[prior].port_ordinal == entry.port_ordinal)
        return false;
  }
  return true;
}

bool Ipv6RouterAdvertisementTable::restore(
    std::span<const Ipv6RouterAdvertisementCheckpoint> state,
    Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  Ipv6RouterAdvertisementTable replacement;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &source = state[index];
    auto &entry = replacement.entries_[index];
    entry = {.config = source.config,
             .next = now +
                     std::chrono::nanoseconds{source.remaining_nanoseconds},
             .last_sent =
                 now - std::chrono::nanoseconds{
                           source.last_sent_ago_nanoseconds},
             .random_state = source.random_state,
             .port_ordinal = source.port_ordinal,
             .initial_advertisements_remaining =
                 source.initial_advertisements_remaining,
             .occupied = true,
             .requested_enabled = source.requested_enabled,
             .active = source.active,
             .has_sent = source.has_sent};
  }
  *this = replacement;
  return true;
}

} // namespace router::lab
