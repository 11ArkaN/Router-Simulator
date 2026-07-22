// RFC 4301 soft and hard SA lifetime enforcement. Zero thresholds disable that
// dimension. A packet reaching a hard byte or packet limit is counted and may
// complete; the SA owner must remove or rekey the SA before another packet.

#include "router/ipsec_lifetime.hpp"

#include <limits>

namespace router::ipsec {
namespace {

bool reached(std::uint64_t value, std::uint64_t threshold) noexcept {
  return threshold != 0U && value >= threshold;
}

bool reached(std::chrono::steady_clock::duration age,
             std::chrono::seconds threshold) noexcept {
  return threshold != std::chrono::seconds::zero() && age >= threshold;
}

} // namespace

LifetimeReservation assess_sa_use(
    const SecurityAssociation &association, std::uint64_t bytes,
    std::chrono::steady_clock::time_point now) noexcept {
  if (now < association.created_at)
    return {.bytes = bytes,
            .packets = 1U,
            .status = LifetimeUseStatus::clock_reversed};
  if (association.counters.bytes >
          std::numeric_limits<std::uint64_t>::max() - bytes ||
      association.counters.packets ==
          std::numeric_limits<std::uint64_t>::max())
    return {.bytes = bytes,
            .packets = 1U,
            .status = LifetimeUseStatus::counter_overflow};
  const auto new_bytes = association.counters.bytes + bytes;
  const auto new_packets = association.counters.packets + 1U;
  const auto age = now - association.created_at;
  const auto &limits = association.lifetime;
  if (reached(association.counters.bytes, limits.hard_bytes) ||
      reached(association.counters.packets, limits.hard_packets) ||
      reached(age, limits.hard_time))
    return {.bytes = bytes,
            .packets = 1U,
            .status = LifetimeUseStatus::hard_expired};
  if (reached(new_bytes, limits.hard_bytes) ||
      reached(new_packets, limits.hard_packets))
    return {.bytes = bytes,
            .packets = 1U,
            .status = LifetimeUseStatus::accepted_hard_limit};
  if (reached(new_bytes, limits.soft_bytes) ||
      reached(new_packets, limits.soft_packets) ||
      reached(age, limits.soft_time))
    return {.bytes = bytes,
            .packets = 1U,
            .status = LifetimeUseStatus::accepted_soft_limit};
  return {.bytes = bytes,
          .packets = 1U,
          .status = LifetimeUseStatus::accepted};
}

void commit_sa_use(SecurityAssociation &association,
                   const LifetimeReservation &reservation) noexcept {
  if (reservation.status != LifetimeUseStatus::accepted &&
      reservation.status != LifetimeUseStatus::accepted_soft_limit &&
      reservation.status != LifetimeUseStatus::accepted_hard_limit)
    return;
  association.counters.bytes += reservation.bytes;
  association.counters.packets += reservation.packets;
}

} // namespace router::ipsec
