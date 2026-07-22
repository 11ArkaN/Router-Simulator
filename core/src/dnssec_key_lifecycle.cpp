// Explicit lifecycle state derivation from RFC 7583 section 3.1. The module
// does not invent default durations because safe rollover intervals depend on
// configured TTLs, signature validity and parent DS propagation.
// Source: ietf.dnssec.key_timing.rfc7583

#include "router/dnssec_key_lifecycle.hpp"

#include <array>
#include <algorithm>

namespace router::dnssec {

bool valid_schedule(const KeySchedule &schedule) noexcept {
  const std::array times{schedule.publish_at, schedule.ready_at,
                         schedule.activate_at, schedule.retire_at,
                         schedule.dead_at, schedule.remove_at};
  return std::ranges::is_sorted(times) && schedule.publish_at != 0U &&
         schedule.remove_at > schedule.publish_at;
}

std::optional<ManagedKey>
ManagedKey::create(KeyRole role, KeySchedule schedule,
                   std::unique_ptr<SigningKey> key) noexcept {
  if (!key || key->public_key().empty() || !valid_schedule(schedule))
    return std::nullopt;
  return ManagedKey{role, schedule, std::move(key)};
}

KeyLifecycleState ManagedKey::state(std::uint64_t now) const noexcept {
  // Compare from the terminal state backwards so equal adjacent timestamps
  // take effect atomically at the shared boundary.
  if (now >= schedule_.remove_at)
    return KeyLifecycleState::removed;
  if (now >= schedule_.dead_at)
    return KeyLifecycleState::dead;
  if (now >= schedule_.retire_at)
    return KeyLifecycleState::retired;
  if (now >= schedule_.activate_at)
    return KeyLifecycleState::active;
  if (now >= schedule_.ready_at)
    return KeyLifecycleState::ready;
  if (now >= schedule_.publish_at)
    return KeyLifecycleState::published;
  return KeyLifecycleState::generated;
}

bool ManagedKey::published(std::uint64_t now) const noexcept {
  // Retired and dead keys remain visible until their cached signatures or DS
  // data can no longer require them. Removal alone ends DNSKEY publication.
  return now >= schedule_.publish_at && now < schedule_.remove_at;
}

bool ManagedKey::signs(std::uint64_t now) const noexcept {
  return now >= schedule_.activate_at && now < schedule_.retire_at;
}

} // namespace router::dnssec
