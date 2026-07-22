// Two-phase IPsec SA lifetime accounting. A forwarding owner assesses packet
// use before protection or after successful authentication, then commits that
// same reservation exactly once. No counter is shared across shards.

#pragma once

#include "router/ipsec_sad.hpp"

#include <chrono>
#include <cstdint>

namespace router::ipsec {

enum class LifetimeUseStatus : std::uint8_t {
  accepted,
  accepted_soft_limit,
  accepted_hard_limit,
  hard_expired,
  counter_overflow,
  clock_reversed
};

struct LifetimeReservation {
  std::uint64_t bytes{};
  std::uint64_t packets{1U};
  LifetimeUseStatus status{LifetimeUseStatus::hard_expired};
};

[[nodiscard]] LifetimeReservation assess_sa_use(
    const SecurityAssociation &association, std::uint64_t bytes,
    std::chrono::steady_clock::time_point now) noexcept;

// commit_sa_use accepts only a reservation returned for the current counters.
// The caller serializes assess and commit on the owning forwarding shard.
void commit_sa_use(SecurityAssociation &association,
                   const LifetimeReservation &reservation) noexcept;

} // namespace router::ipsec
