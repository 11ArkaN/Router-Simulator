// Lifetime tests exercise disabled dimensions, soft notification, a final
// packet at the hard boundary, rejection after the boundary and counter wrap.

#include "router/ipsec_lifetime.hpp"

#include <chrono>
#include <limits>
#include <stdexcept>

void ipsec_lifetime_tests() {
  using namespace router::ipsec;
  using namespace std::chrono_literals;
  SecurityAssociation association{};
  association.created_at = std::chrono::steady_clock::time_point{10s};
  association.lifetime.soft_bytes = 100U;
  association.lifetime.hard_bytes = 120U;
  auto reservation = assess_sa_use(
      association, 100U, std::chrono::steady_clock::time_point{11s});
  if (reservation.status != LifetimeUseStatus::accepted_soft_limit)
    throw std::runtime_error("IPsec soft byte lifetime was not reported");
  commit_sa_use(association, reservation);
  reservation = assess_sa_use(
      association, 20U, std::chrono::steady_clock::time_point{12s});
  if (reservation.status != LifetimeUseStatus::accepted_hard_limit)
    throw std::runtime_error("IPsec hard byte boundary was not reported");
  commit_sa_use(association, reservation);
  if (assess_sa_use(association, 1U,
                    std::chrono::steady_clock::time_point{13s})
          .status != LifetimeUseStatus::hard_expired)
    throw std::runtime_error("expired IPsec SA accepted another packet");

  association.lifetime = {};
  association.counters.bytes = std::numeric_limits<std::uint64_t>::max();
  if (assess_sa_use(association, 1U,
                    std::chrono::steady_clock::time_point{14s})
          .status != LifetimeUseStatus::counter_overflow)
    throw std::runtime_error("IPsec lifetime counter overflow was accepted");
}
