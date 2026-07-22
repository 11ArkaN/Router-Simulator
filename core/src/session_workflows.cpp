// Source-backed candidate workflow implementation. It models shared global
// and per-session private baselines, running locks and path-level conflicts.

#include "router/session_workflows.hpp"

#include <algorithm>
#include <new>

namespace router::lab {

SessionWorkflowController::SessionWorkflowController(
    SessionRegistry &sessions)
    : sessions_(sessions),
      candidates_(
          std::make_unique<std::array<SessionCandidate, maximum_sessions>>()),
      routers_(std::make_unique<std::array<
                   RouterCandidates, device_catalog::maximum_routers>>()) {}

bool SessionWorkflowController::ChangeSet::add(std::uint64_t key) noexcept {
  if (!key)
    return false;
  // Re-editing one schema path changes candidate bytes but does not consume a
  // second conflict-tracking slot. The command layer owns the actual value.
  if (std::find(keys.begin(), keys.begin() + count, key) !=
      keys.begin() + count)
    return true;
  if (count == keys.size())
    return false;
  keys[count++] = key;
  return true;
}

void SessionWorkflowController::ChangeSet::clear() noexcept {
  // Clearing the active prefix is enough for correctness, but zeroing it keeps
  // checkpoints and diagnostics from retaining stale configuration identities.
  std::fill(keys.begin(), keys.begin() + count, std::uint64_t{0});
  count = 0;
}

SessionWorkflowController::RouterCandidates &
SessionWorkflowController::router(DeviceHandle device) noexcept {
  auto &state = (*routers_)[device.index];
  if (state.device_generation != device.generation) {
    // Device deletion invalidates every datastore generation in its compact
    // slot. A replacement router never inherits candidate changes or locks.
    state = {};
    state.device_generation = device.generation;
    state.running_generation = 1;
    state.global_baseline = 1;
  }
  return state;
}

const SessionWorkflowController::RouterCandidates *
SessionWorkflowController::router_if_current(DeviceHandle device) const noexcept {
  if (!device || device.index >= routers_->size())
    return nullptr;
  const auto &state = (*routers_)[device.index];
  return state.device_generation == device.generation ? &state : nullptr;
}

SessionWorkflowController::SessionCandidate &
SessionWorkflowController::candidate(SessionHandle handle,
                                     const SessionRecord &record) noexcept {
  auto &state = (*candidates_)[handle.index];
  if (state.generation != handle.generation || state.device != record.device) {
    // Session generations provide the same stale-message protection as device
    // generations. A reused terminal slot begins with an empty private view.
    state = {};
    state.generation = handle.generation;
    state.device = record.device;
  }
  return state;
}

const SessionWorkflowController::SessionCandidate *
SessionWorkflowController::candidate_if_current(
    SessionHandle handle, const SessionRecord &record) const noexcept {
  if (!handle || handle.index >= candidates_->size())
    return nullptr;
  const auto &state = (*candidates_)[handle.index];
  return state.generation == handle.generation && state.device == record.device
             ? &state
             : nullptr;
}

bool SessionWorkflowController::add_global(RouterCandidates &state,
                                           std::uint64_t key) noexcept {
  if (!key)
    return false;
  const auto end = state.global_keys.begin() + state.global_count;
  if (std::find(state.global_keys.begin(), end, key) != end)
    return true;
  if (state.global_count == state.global_keys.size())
    return false;
  state.global_keys[state.global_count++] = key;
  return true;
}

std::uint64_t SessionWorkflowController::revision(
    const RouterCandidates &state, std::uint64_t key) const noexcept {
  for (std::size_t index = 0; index < state.revision_count; ++index)
    if (state.revisions[index].key == key)
      return state.revisions[index].generation;
  return 0;
}

SessionWorkflowResult SessionWorkflowController::apply(
    RouterCandidates &state, const std::uint64_t *keys, std::size_t count,
    std::uint64_t baseline) noexcept {
  // Conflict validation completes before any running revision is mutated. A
  // failed automatic update therefore leaves both candidate and running state
  // byte-for-byte unchanged.
  for (std::size_t index = 0; index < count; ++index)
    if (revision(state, keys[index]) > baseline)
      return SessionWorkflowResult::merge_conflict;

  std::size_t new_keys{};
  for (std::size_t index = 0; index < count; ++index)
    if (!revision(state, keys[index]))
      ++new_keys;
  if (state.revision_count + new_keys > state.revisions.size())
    return SessionWorkflowResult::candidate_full;
  if (!count)
    return SessionWorkflowResult::applied;

  const auto generation = ++state.running_generation;
  for (std::size_t index = 0; index < count; ++index) {
    KeyRevision *target{};
    for (std::size_t stored = 0; stored < state.revision_count; ++stored)
      if (state.revisions[stored].key == keys[index]) {
        target = &state.revisions[stored];
        break;
      }
    if (!target)
      target = &state.revisions[state.revision_count++];
    *target = {keys[index], generation};
  }
  return SessionWorkflowResult::applied;
}

SessionWorkflowResult SessionWorkflowController::enter(
    SessionHandle handle, CandidateMode mode) noexcept {
  auto *session = sessions_.get(handle);
  if (!session)
    return SessionWorkflowResult::invalid_session;
  if (session->mode != CandidateMode::operational)
    return SessionWorkflowResult::already_configuring;
  if (mode == CandidateMode::operational)
    return SessionWorkflowResult::not_configuring;

  auto &state = router(session->device);
  auto &private_state = candidate(handle, *session);
  if (mode == CandidateMode::exclusive) {
    // Exclusive and global are mutually exclusive. The global candidate must
    // also be clean before one session may reserve it and the running datastore.
    if (sessions_.count(session->device, CandidateMode::exclusive) ||
        sessions_.count(session->device, CandidateMode::global) ||
        state.global_count)
      return SessionWorkflowResult::exclusive_unavailable;
  } else if (mode == CandidateMode::global &&
             sessions_.count(session->device, CandidateMode::exclusive)) {
    return SessionWorkflowResult::exclusive_unavailable;
  }

  private_state.changes.clear();
  session->mode = mode;
  session->base_generation = mode == CandidateMode::private_candidate
                                 ? state.running_generation
                                 : state.global_baseline;
  return SessionWorkflowResult::applied;
}

SessionWorkflowResult SessionWorkflowController::leave(
    SessionHandle handle, bool discard) noexcept {
  auto *session = sessions_.get(handle);
  if (!session)
    return SessionWorkflowResult::invalid_session;
  if (session->mode == CandidateMode::operational)
    return SessionWorkflowResult::not_configuring;
  auto &state = router(session->device);
  auto &private_state = candidate(handle, *session);

  if (session->mode == CandidateMode::private_candidate &&
      private_state.changes.count && !discard)
    return SessionWorkflowResult::discard_confirmation_required;
  if (session->mode == CandidateMode::exclusive && state.global_count &&
      !discard)
    return SessionWorkflowResult::discard_confirmation_required;

  if (session->mode == CandidateMode::private_candidate)
    private_state.changes.clear();
  if (session->mode == CandidateMode::exclusive) {
    // Exclusive exit discards its global changes. Global mode differs and
    // intentionally leaves the shared candidate alive for other sessions.
    std::fill(state.global_keys.begin(),
              state.global_keys.begin() + state.global_count,
              std::uint64_t{0});
    state.global_count = 0;
    state.global_baseline = state.running_generation;
  }
  session->mode = CandidateMode::operational;
  session->base_generation = 0;
  return SessionWorkflowResult::applied;
}

SessionWorkflowResult SessionWorkflowController::transition(
    SessionHandle handle, CandidateMode target, bool discard) noexcept {
  auto *session = sessions_.get(handle);
  if (!session)
    return SessionWorkflowResult::invalid_session;
  const auto source = session->mode;
  if (source == CandidateMode::operational ||
      source == CandidateMode::private_candidate ||
      target == CandidateMode::operational ||
      target == CandidateMode::private_candidate)
    return SessionWorkflowResult::not_configuring;
  if (source == target)
    return SessionWorkflowResult::applied;

  auto &state = router(session->device);
  if (source == CandidateMode::exclusive && state.global_count && !discard)
    return SessionWorkflowResult::discard_confirmation_required;
  if (target == CandidateMode::exclusive) {
    // The current session is not counted as a conflicting owner. Any other
    // global or exclusive session prevents acquiring exclusive datastore access.
    const auto handles = sessions_.sessions(session->device);
    for (std::size_t index = 0; index < handles.count; ++index) {
      if (handles.handles[index] == handle)
        continue;
      const auto *other = sessions_.get(handles.handles[index]);
      if (other && (other->mode == CandidateMode::global ||
                    other->mode == CandidateMode::exclusive))
        return SessionWorkflowResult::exclusive_unavailable;
    }
  }
  if (source == CandidateMode::exclusive && discard) {
    std::fill(state.global_keys.begin(),
              state.global_keys.begin() + state.global_count,
              std::uint64_t{0});
    state.global_count = 0;
    state.global_baseline = state.running_generation;
  }
  session->mode = target;
  session->base_generation = state.global_baseline;
  return SessionWorkflowResult::applied;
}

SessionWorkflowResult SessionWorkflowController::record_edit(
    SessionHandle handle, std::uint64_t key) noexcept {
  auto *session = sessions_.get(handle);
  if (!session)
    return SessionWorkflowResult::invalid_session;
  if (session->mode == CandidateMode::operational)
    return SessionWorkflowResult::not_configuring;
  if (session->mode == CandidateMode::read_only)
    return SessionWorkflowResult::read_only;

  auto &state = router(session->device);
  if (session->mode == CandidateMode::private_candidate)
    return candidate(handle, *session).changes.add(key)
               ? SessionWorkflowResult::applied
               : SessionWorkflowResult::candidate_full;
  if (!state.global_count)
    state.global_baseline = state.running_generation;
  return add_global(state, key) ? SessionWorkflowResult::applied
                                : SessionWorkflowResult::candidate_full;
}

SessionWorkflowResult
SessionWorkflowController::commit(SessionHandle handle) noexcept {
  auto *session = sessions_.get(handle);
  if (!session)
    return SessionWorkflowResult::invalid_session;
  if (session->mode == CandidateMode::operational)
    return SessionWorkflowResult::not_configuring;
  if (session->mode == CandidateMode::read_only)
    return SessionWorkflowResult::read_only;
  if (session->mode != CandidateMode::exclusive &&
      sessions_.count(session->device, CandidateMode::exclusive))
    return SessionWorkflowResult::running_locked;

  auto &state = router(session->device);
  if (session->mode == CandidateMode::private_candidate) {
    auto &private_state = candidate(handle, *session);
    const auto result = apply(state, private_state.changes.keys.data(),
                              private_state.changes.count,
                              session->base_generation);
    if (result == SessionWorkflowResult::applied) {
      private_state.changes.clear();
      session->base_generation = state.running_generation;
      if (!state.global_count)
        state.global_baseline = state.running_generation;
    }
    return result;
  }

  const auto result = apply(state, state.global_keys.data(),
                            state.global_count, state.global_baseline);
  if (result == SessionWorkflowResult::applied) {
    std::fill(state.global_keys.begin(),
              state.global_keys.begin() + state.global_count,
              std::uint64_t{0});
    state.global_count = 0;
    state.global_baseline = state.running_generation;
    session->base_generation = state.running_generation;
  }
  return result;
}

SessionWorkflowResult SessionWorkflowController::authorize_classic_write(
    DeviceHandle device) const noexcept {
  if (!device || device.index >= routers_->size())
    return SessionWorkflowResult::invalid_session;
  if (sessions_.count(device, CandidateMode::exclusive))
    return SessionWorkflowResult::running_locked;
  return SessionWorkflowResult::applied;
}

SessionWorkflowResult SessionWorkflowController::classic_write(
    DeviceHandle device, std::uint64_t key) noexcept {
  const auto authorization = authorize_classic_write(device);
  if (authorization != SessionWorkflowResult::applied)
    return authorization;
  auto &state = router(device);
  const auto result = apply(state, &key, 1, state.running_generation);
  // A clean global baseline tracks running automatically. A dirty global
  // candidate retains its older baseline and becomes visibly out of date.
  if (result == SessionWorkflowResult::applied && !state.global_count)
    state.global_baseline = state.running_generation;
  return result;
}

bool SessionWorkflowController::global_candidate_dirty(
    DeviceHandle device) const noexcept {
  const auto *state = router_if_current(device);
  return state && state->global_count != 0;
}

SessionWorkflowResult
SessionWorkflowController::discard(SessionHandle handle) noexcept {
  auto *session = sessions_.get(handle);
  if (!session)
    return SessionWorkflowResult::invalid_session;
  if (session->mode == CandidateMode::operational)
    return SessionWorkflowResult::not_configuring;
  if (session->mode == CandidateMode::read_only)
    return SessionWorkflowResult::read_only;
  auto &state = router(session->device);
  if (session->mode == CandidateMode::private_candidate)
    candidate(handle, *session).changes.clear();
  else {
    std::fill(state.global_keys.begin(),
              state.global_keys.begin() + state.global_count,
              std::uint64_t{0});
    state.global_count = 0;
    state.global_baseline = state.running_generation;
  }
  session->base_generation = state.running_generation;
  return SessionWorkflowResult::applied;
}

bool SessionWorkflowController::close(SessionHandle handle) noexcept {
  auto *session = sessions_.get(handle);
  if (!session)
    return false;
  // A transport disconnect confirms discard implicitly. Global candidate
  // changes remain shared, while private and exclusive ownership is released.
  if (session->mode != CandidateMode::operational)
    static_cast<void>(leave(handle, true));
  (*candidates_)[handle.index] = {};
  return sessions_.erase(handle);
}

std::size_t
SessionWorkflowController::close_device(DeviceHandle device) noexcept {
  const auto snapshot = sessions_.sessions(device);
  std::size_t closed{};
  for (std::size_t index = 0; index < snapshot.count; ++index)
    closed += close(snapshot.handles[index]);
  // Router deletion removes even a global candidate retained by a disconnected
  // session because the complete device generation is being destroyed.
  if (device.index < routers_->size() &&
      (*routers_)[device.index].device_generation == device.generation)
    (*routers_)[device.index] = {};
  return closed;
}

std::optional<SessionWorkflowStatus>
SessionWorkflowController::status(SessionHandle handle) const noexcept {
  const auto *session = sessions_.get(handle);
  if (!session)
    return std::nullopt;
  const auto *state = router_if_current(session->device);
  if (!state)
    return SessionWorkflowStatus{.mode = session->mode};

  bool dirty{};
  std::uint64_t baseline{};
  if (session->mode == CandidateMode::private_candidate) {
    const auto *private_state = candidate_if_current(handle, *session);
    dirty = private_state && private_state->changes.count;
    baseline = session->base_generation;
  } else if (session->mode != CandidateMode::operational) {
    // Exclusive, global and read-only sessions all observe the shared global
    // candidate, although read-only cannot mutate or commit it.
    dirty = state->global_count != 0;
    baseline = state->global_baseline;
  }
  return SessionWorkflowStatus{session->mode, state->running_generation,
                               baseline, dirty,
                               baseline && baseline < state->running_generation};
}

SessionWorkflowsCheckpoint SessionWorkflowController::checkpoint() const {
  SessionWorkflowsCheckpoint state;
  for (std::size_t index = 0; index < routers_->size(); ++index) {
    const auto &source = (*routers_)[index];
    if (!source.device_generation)
      continue;
    WorkflowRouterCheckpoint router_state;
    router_state.device = {static_cast<std::uint16_t>(index),
                           source.device_generation};
    router_state.running_generation = source.running_generation;
    router_state.global_baseline = source.global_baseline;
    router_state.global_keys.assign(source.global_keys.begin(),
                                    source.global_keys.begin() +
                                        source.global_count);
    router_state.revisions.reserve(source.revision_count);
    for (std::size_t revision = 0; revision < source.revision_count;
         ++revision)
      router_state.revisions.push_back(
          {source.revisions[revision].key,
           source.revisions[revision].generation});
    state.routers.push_back(std::move(router_state));
  }
  for (std::size_t index = 0; index < candidates_->size(); ++index) {
    const auto &source = (*candidates_)[index];
    if (!source.generation)
      continue;
    const SessionHandle handle{static_cast<std::uint16_t>(index),
                               source.generation};
    const auto *session = sessions_.get(handle);
    if (!session || session->device != source.device)
      continue;
    WorkflowSessionCheckpoint session_state;
    session_state.session = handle;
    session_state.device = source.device;
    session_state.keys.assign(source.changes.keys.begin(),
                              source.changes.keys.begin() +
                                  source.changes.count);
    state.sessions.push_back(std::move(session_state));
  }
  return state;
}

bool SessionWorkflowController::restore(
    const SessionWorkflowsCheckpoint &state) {
  if (state.routers.size() > device_catalog::maximum_routers ||
      state.sessions.size() > maximum_sessions)
    return false;
  std::array<bool, device_catalog::maximum_routers> routers_seen{};
  std::array<bool, maximum_sessions> sessions_seen{};
  for (const auto &router_state : state.routers) {
    if (!router_state.device ||
        router_state.device.index >= routers_seen.size() ||
        routers_seen[router_state.device.index] ||
        !router_state.running_generation || !router_state.global_baseline ||
        router_state.global_baseline > router_state.running_generation ||
        router_state.global_keys.size() >
            device_catalog::candidate_keys_per_router ||
        router_state.revisions.size() >
            device_catalog::candidate_keys_per_router)
      return false;
    for (std::size_t index = 0; index < router_state.global_keys.size(); ++index)
      if (!router_state.global_keys[index] ||
          std::find(router_state.global_keys.begin(),
                    router_state.global_keys.begin() + index,
                    router_state.global_keys[index]) !=
              router_state.global_keys.begin() + index)
        return false;
    for (std::size_t index = 0; index < router_state.revisions.size(); ++index) {
      const auto &revision = router_state.revisions[index];
      if (!revision.key || !revision.generation ||
          revision.generation > router_state.running_generation ||
          std::find_if(router_state.revisions.begin(),
                       router_state.revisions.begin() + index,
                       [&](const auto &prior) {
                         return prior.key == revision.key;
                       }) != router_state.revisions.begin() + index)
        return false;
    }
    routers_seen[router_state.device.index] = true;
  }
  for (const auto &session_state : state.sessions) {
    const auto *session = sessions_.get(session_state.session);
    if (!session || session_state.session.index >= sessions_seen.size() ||
        sessions_seen[session_state.session.index] ||
        session->device != session_state.device ||
        session_state.keys.size() >
            device_catalog::candidate_keys_per_session)
      return false;
    for (std::size_t index = 0; index < session_state.keys.size(); ++index)
      if (!session_state.keys[index] ||
          std::find(session_state.keys.begin(),
                    session_state.keys.begin() + index,
                    session_state.keys[index]) !=
              session_state.keys.begin() + index)
        return false;
    sessions_seen[session_state.session.index] = true;
  }
  try {
    auto routers = std::make_unique<std::array<
        RouterCandidates, device_catalog::maximum_routers>>();
    auto candidates =
        std::make_unique<std::array<SessionCandidate, maximum_sessions>>();
    for (const auto &source : state.routers) {
      auto &target = (*routers)[source.device.index];
      target.device_generation = source.device.generation;
      target.running_generation = source.running_generation;
      target.global_baseline = source.global_baseline;
      target.global_count = static_cast<std::uint16_t>(source.global_keys.size());
      std::copy(source.global_keys.begin(), source.global_keys.end(),
                target.global_keys.begin());
      target.revision_count =
          static_cast<std::uint16_t>(source.revisions.size());
      for (std::size_t index = 0; index < source.revisions.size(); ++index)
        target.revisions[index] = {source.revisions[index].key,
                                   source.revisions[index].generation};
    }
    for (const auto &source : state.sessions) {
      auto &target = (*candidates)[source.session.index];
      target.device = source.device;
      target.generation = source.session.generation;
      target.changes.count = static_cast<std::uint16_t>(source.keys.size());
      std::copy(source.keys.begin(), source.keys.end(),
                target.changes.keys.begin());
    }
    routers_.swap(routers);
    candidates_.swap(candidates);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void SessionWorkflowController::swap_state(
    SessionWorkflowController &other) noexcept {
  // Registry references remain attached to their owning controllers. Only the
  // fully validated candidate arenas move during the supervisor commit.
  candidates_.swap(other.candidates_);
  routers_.swap(other.routers_);
}

} // namespace router::lab
