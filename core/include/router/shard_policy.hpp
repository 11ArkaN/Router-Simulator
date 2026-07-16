// Host-CPU to runtime-owner placement. The policy contains no mutable state and
// is shared by startup, telemetry and tests so thread counts cannot drift.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <cstddef>

namespace router::lab {

struct ShardPolicy {
  std::size_t control{};
  std::size_t forwarding{};
  std::size_t link{};

  // A zero link count means the sole forwarding pthread also owns the medium.
  // This preserves two physical domains on hosts with at most four logical
  // CPUs: the calling Wasm control Worker and one combined network owner.
  [[nodiscard]] constexpr bool combined_forwarding_link() const noexcept {
    return link == 0;
  }

  [[nodiscard]] constexpr std::size_t worker_domains() const noexcept {
    return control + forwarding + link;
  }

  // The primary control owner is the calling browser Worker. Every other
  // domain requires one pre-created Emscripten pthread.
  [[nodiscard]] constexpr std::size_t pthreads() const noexcept {
    return worker_domains() - 1U;
  }
};

[[nodiscard]] constexpr ShardPolicy
select_shard_policy(std::size_t logical_cpus) noexcept {
  if (logical_cpus <= device_catalog::low_cpu_max)
    return {device_catalog::low_control_shards,
            device_catalog::low_forwarding_shards,
            device_catalog::low_link_shards};
  if (logical_cpus <= device_catalog::medium_cpu_max)
    return {device_catalog::medium_control_shards,
            device_catalog::medium_forwarding_shards,
            device_catalog::medium_link_shards};
  return {device_catalog::high_control_shards,
          device_catalog::high_forwarding_shards,
          device_catalog::high_link_shards};
}

static_assert(select_shard_policy(1).pthreads() == 1U);
static_assert(select_shard_policy(5).pthreads() == 3U);
static_assert(select_shard_policy(9).pthreads() == 5U);
static_assert(select_shard_policy(9).worker_domains() <=
              device_catalog::maximum_worker_domains);

} // namespace router::lab
