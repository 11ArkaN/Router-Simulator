// The IS-IS pthread finalizes retained expirations and retires due purge headers.
// Dense instance iteration and a shared work budget prevent deadline floods from
// monopolizing the shard. Resource waits never poll an unserviceable past time.
// Source: iso.10589.2002.runtime_update

#include "router/isis_control_worker.hpp"

#include <algorithm>

namespace router::isis {
RuntimeClock::time_point ControlWorker::service_update_lifetimes(OwnedInstance &instance,
    RuntimeClock::time_point now, std::size_t &budget) noexcept {
  while (instance.status == UpdateStatus::applied) {
    for (std::size_t level{}; level < 2U; ++level)
      if (!instance.expiration_blocked[level].empty() && instance.expiration_revision[level] != instance.revision[level])
        instance.expiration_blocked[level].clear();
    const auto next = instance.process->next_database_deadline({
        std::span<const packet::isis::LspId>(instance.expiration_blocked[0U]),
        std::span<const packet::isis::LspId>(instance.expiration_blocked[1U])});
    if (!next) break;
    if (next->deadline.at > now || !budget) return next->deadline.at;
    --budget;
    if (next->deadline.kind == LspDeadlineKind::retire_purge) {
      if (!instance.process->retire_purge(next->level, next->deadline.id, now, instance.observer())) {
        instance.status = UpdateStatus::invalid_event;
        break;
      }
    } else {
      // Experimental admission rejects authentication selection. The future
      // key-policy owner must supply its current transmit lease here explicitly.
      const auto result = instance.process->finalize_expiration(next->level, next->deadline.id,
          {false, std::nullopt}, now, scratch_.options, scratch_.pdu, instance.observer());
      if (result.status == UpdateStatus::applied) continue;
      if (result.origin.install == LspInstallResult::capacity_exhausted ||
          result.status == UpdateStatus::capacity || result.status == UpdateStatus::authentication) {
        auto &blocked = instance.expiration_blocked[next->level];
        if (blocked.size() == blocked.capacity()) {
          instance.status = UpdateStatus::capacity;
          break;
        }
        blocked.insert(std::lower_bound(blocked.begin(), blocked.end(), next->deadline.id), next->deadline.id);
        instance.expiration_revision[next->level] = instance.revision[next->level];
      } else {
        instance.status = result.status;
        break;
      }
    }
  }
  return RuntimeClock::time_point::max();
}
} // namespace router::isis
