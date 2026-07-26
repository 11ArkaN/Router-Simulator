// Boundary tests for generated runtime shard placement. These values describe
// emulator ownership, not vendor hardware scaling claims.

#include "router/shard_policy.hpp"

#include <stdexcept>

void shard_policy_tests() {
  using router::lab::select_shard_policy;
  const auto unknown = select_shard_policy(0);
  const auto low = select_shard_policy(4);
  const auto medium = select_shard_policy(5);
  const auto medium_edge = select_shard_policy(8);
  const auto high = select_shard_policy(9);

  // hardware_concurrency may legally report zero. Treating it as the smallest
  // host is safe because it never overcommits an unknown execution budget.
  if (!unknown.combined_forwarding_link() || unknown.pthreads() != 2U ||
      !low.combined_forwarding_link() || low.worker_domains() != 3U ||
      medium.control != 1U || medium.forwarding != 2U || medium.link != 1U ||
      medium.ospf != 1U || medium_edge.worker_domains() != 5U ||
      high.control != 2U || high.forwarding != 3U || high.link != 1U ||
      high.ospf != 1U || high.pthreads() != 6U)
    throw std::runtime_error("generated shard placement policy is inconsistent");
}
