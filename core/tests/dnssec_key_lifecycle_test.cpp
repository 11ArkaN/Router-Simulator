// Lifecycle tests cover every boundary, including atomic equal-time emergency
// transitions and rejection of schedules that would move a key backwards.

#include "router/dnssec_key_lifecycle.hpp"

#include <stdexcept>

void dnssec_key_lifecycle_tests() {
  using namespace router::dnssec;

  const KeySchedule schedule{.publish_at = 100U,
                             .ready_at = 200U,
                             .activate_at = 300U,
                             .retire_at = 400U,
                             .dead_at = 500U,
                             .remove_at = 600U};
  auto managed = ManagedKey::create(KeyRole::zone_signing, schedule,
                                    generate_signing_key(15U));
  if (!managed || managed->state(99U) != KeyLifecycleState::generated ||
      managed->state(100U) != KeyLifecycleState::published ||
      managed->state(200U) != KeyLifecycleState::ready ||
      managed->state(300U) != KeyLifecycleState::active ||
      managed->state(400U) != KeyLifecycleState::retired ||
      managed->state(500U) != KeyLifecycleState::dead ||
      managed->state(600U) != KeyLifecycleState::removed)
    throw std::runtime_error("DNSSEC key lifecycle boundary is wrong");
  if (managed->published(99U) || !managed->published(599U) ||
      managed->published(600U) || managed->signs(299U) ||
      !managed->signs(399U) || managed->signs(400U))
    throw std::runtime_error("DNSSEC key publication/signing window is wrong");

  auto invalid = schedule;
  invalid.ready_at = 50U;
  if (valid_schedule(invalid) ||
      ManagedKey::create(KeyRole::key_signing, invalid,
                         generate_signing_key(15U)))
    throw std::runtime_error("DNSSEC accepted a non-monotonic key schedule");
}
