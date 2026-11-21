// Pending route generations and installation results survive new slot storage.
// The test destroys the original channel before completing a saved borrowed
// generation and preserves refusal results rather than treating them as installs.

#include "router/route_publication.hpp"

#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

void route_publication_checkpoint_tests() {
  using namespace router;
  using namespace router::routing;
  using Channel = RoutePublicationChannel<3U>;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("Route publication checkpoint invariant at " + std::to_string(where.line()));
  };
  auto source = std::make_unique<Channel>();
  for (std::uint64_t generation{11U}; generation < 14U; ++generation) {
    const auto edit = source->try_acquire();
    require(edit.has_value());
    edit->generation->device = {3U, 7U};
    edit->generation->generation = generation;
    edit->generation->ipv4_count = edit->generation->ipv6_count = 1U;
    edit->generation->ipv4[0U].metric = static_cast<std::uint32_t>(generation);
    edit->generation->ipv6[0U].metric = static_cast<std::uint32_t>(generation + 100U);
    require(source->publish(edit->handle));
  }
  auto first = source->try_receive();
  require(first && source->complete(first->handle, {3U, 7U}, 11U, RouteInstallStatus::forwarding_failed));
  first.reset();
  auto held = source->try_receive();
  require(held && held->generation->generation == 12U);
  const auto held_handle = held->handle;
  held.reset();
  const auto saved = source->checkpoint_quiescent(101U);
  require(saved.ready.size() == 1U && saved.borrowed.size() == 1U && saved.returned.size() == 1U);
  auto prepared = Channel::prepare_restore(saved, 101U);
  require(prepared != nullptr);
  source.reset();
  auto resumed = std::make_unique<Channel>();
  require(!resumed->commit_quiescent(*prepared, 102U) && resumed->commit_quiescent(*prepared, 101U) &&
      !resumed->commit_quiescent(*prepared, 101U));
  for (unsigned invalid{}; invalid < 4U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: bad.occupied[0U].value.status = RouteInstallStatus::pending; break;
      case 1U: bad.occupied[1U].value.status = RouteInstallStatus::installed; break;
      case 2U: bad.occupied[2U].value.status = RouteInstallStatus::capacity; break;
      default: bad.occupied[0U].value.status = static_cast<RouteInstallStatus>(255U); break;
    }
    require(!Channel::valid_checkpoint(bad, 101U) && !Channel::prepare_restore(bad, 101U));
  }
  require(!resumed->complete(held_handle, {3U, 8U}, 12U, RouteInstallStatus::installed) &&
      !resumed->complete(held_handle, {3U, 7U}, 11U, RouteInstallStatus::installed) &&
      resumed->complete(held_handle, {3U, 7U}, 12U, RouteInstallStatus::installed));
  const auto failure = resumed->try_completion();
  const auto installed = resumed->try_completion();
  require(failure && failure->generation == 11U && failure->status == RouteInstallStatus::forwarding_failed &&
      installed && installed->generation == 12U && installed->status == RouteInstallStatus::installed);
  const auto ready = resumed->try_receive();
  require(ready && ready->generation->generation == 13U && ready->generation->ipv4[0U].metric == 13U &&
      ready->generation->ipv6[0U].metric == 113U &&
      resumed->complete(ready->handle, {3U, 7U}, 13U, RouteInstallStatus::capacity));
  const auto refused = resumed->try_completion();
  require(refused && refused->status == RouteInstallStatus::capacity && !resumed->try_completion());
  const auto editing = resumed->try_acquire();
  require(editing.has_value());
  editing->generation->device = {3U, 7U};
  editing->generation->generation = 14U;
  const auto editing_handle = editing->handle;
  auto edit_prepared = Channel::prepare_restore(resumed->checkpoint_quiescent(102U), 102U);
  resumed.reset(); resumed = std::make_unique<Channel>();
  require(edit_prepared && resumed->commit_quiescent(*edit_prepared, 102U));
  auto *continued = resumed->editing_generation_quiescent(editing_handle);
  require(continued && continued->generation == 14U);
  continued->ipv4_count = 1U;
  continued->ipv4[0U].metric = 55U;
  require(resumed->publish(editing_handle) && !resumed->editing_generation_quiescent(editing_handle));
  const auto final = resumed->try_receive();
  require(final && final->generation->generation == 14U && final->generation->ipv4[0U].metric == 55U &&
      resumed->complete(final->handle, {3U, 7U}, 14U, RouteInstallStatus::installed) && resumed->try_completion().has_value());
}
