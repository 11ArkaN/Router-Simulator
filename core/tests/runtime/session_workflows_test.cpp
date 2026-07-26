// Candidate workflow tests cover shared visibility, exclusive running locks,
// private automatic update, path conflict detection and all 64 session slots.

#include "router/session_workflows.hpp"

#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char *message) {
  // One precise failure is more useful than continuing with corrupted lock or
  // generation state and reporting a secondary candidate symptom.
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void session_workflow_tests() {
  using namespace router::lab;
  SessionRegistry sessions;
  const DeviceHandle device{0, 1};
  const auto first = sessions.create(device, "first");
  const auto second = sessions.create(device, "second");
  const auto third = sessions.create(device, "third");
  const auto fourth = sessions.create(device, "fourth");
  require(first && second && third && fourth &&
              !sessions.create(device, "fifth"),
          "per-router terminal capacity is not four");

  SessionWorkflowController workflows{sessions};
  require(workflows.enter(*first, CandidateMode::global) ==
              SessionWorkflowResult::applied &&
              workflows.enter(*second, CandidateMode::global) ==
                  SessionWorkflowResult::applied &&
              workflows.enter(*third, CandidateMode::read_only) ==
                  SessionWorkflowResult::applied,
          "compatible global and read-only sessions were rejected");
  require(workflows.record_edit(*first, 11) ==
              SessionWorkflowResult::applied &&
              workflows.status(*second)->candidate_dirty &&
              workflows.status(*third)->candidate_dirty,
          "global candidate changes were not shared with permitted viewers");
  require(workflows.record_edit(*third, 12) ==
              SessionWorkflowResult::read_only &&
              workflows.commit(*third) == SessionWorkflowResult::read_only,
          "read-only session mutated or committed the global candidate");
  require(workflows.commit(*second) == SessionWorkflowResult::applied &&
              workflows.status(*first)->running_generation == 2 &&
              !workflows.status(*first)->candidate_dirty,
          "one global commit did not atomically commit all shared changes");
  require(workflows.enter(*fourth, CandidateMode::exclusive) ==
              SessionWorkflowResult::exclusive_unavailable,
          "exclusive mode coexisted with global writers");

  require(workflows.leave(*first, false) == SessionWorkflowResult::applied &&
              workflows.leave(*second, false) ==
                  SessionWorkflowResult::applied &&
              workflows.enter(*fourth, CandidateMode::exclusive) ==
                  SessionWorkflowResult::applied &&
              workflows.enter(*first, CandidateMode::private_candidate) ==
                  SessionWorkflowResult::applied,
          "exclusive and private coexistence did not match datastore rules");
  require(workflows.record_edit(*first, 22) ==
              SessionWorkflowResult::applied &&
              workflows.commit(*first) ==
                  SessionWorkflowResult::running_locked &&
              workflows.authorize_classic_write(device) ==
                  SessionWorkflowResult::running_locked &&
              workflows.classic_write(device, 23) ==
                  SessionWorkflowResult::running_locked,
          "exclusive mode failed to lock running commits and classic writes");
  require(workflows.record_edit(*fourth, 33) ==
              SessionWorkflowResult::applied &&
              workflows.status(*third)->candidate_dirty &&
              workflows.commit(*fourth) == SessionWorkflowResult::applied &&
              workflows.status(*first)->baseline_outdated,
          "exclusive commit did not update running and stale private baseline");
  require(workflows.leave(*fourth, false) ==
              SessionWorkflowResult::applied &&
              workflows.commit(*first) == SessionWorkflowResult::applied,
          "non-conflicting private candidate did not update and commit");

  require(workflows.leave(*third, false) == SessionWorkflowResult::applied &&
              workflows.enter(*second, CandidateMode::private_candidate) ==
                  SessionWorkflowResult::applied &&
              workflows.record_edit(*first, 44) ==
                  SessionWorkflowResult::applied &&
              workflows.commit(*first) == SessionWorkflowResult::applied &&
              workflows.record_edit(*second, 44) ==
                  SessionWorkflowResult::applied &&
              workflows.commit(*second) ==
                  SessionWorkflowResult::merge_conflict,
          "same-path private edit did not preserve candidate on conflict");
  require(workflows.leave(*second, false) ==
              SessionWorkflowResult::discard_confirmation_required &&
              workflows.leave(*second, true) == SessionWorkflowResult::applied,
          "dirty private exit bypassed or ignored discard confirmation");

  require(workflows.enter(*third, CandidateMode::global) ==
              SessionWorkflowResult::applied &&
              workflows.record_edit(*third, 55) ==
                  SessionWorkflowResult::applied &&
              workflows.leave(*third, false) ==
                  SessionWorkflowResult::applied &&
              workflows.enter(*fourth, CandidateMode::exclusive) ==
                  SessionWorkflowResult::exclusive_unavailable &&
              workflows.authorize_classic_write(device) ==
                  SessionWorkflowResult::applied &&
              workflows.classic_write(device, 66) ==
                  SessionWorkflowResult::applied &&
              workflows.enter(*third, CandidateMode::read_only) ==
                  SessionWorkflowResult::applied &&
              workflows.status(*third)->candidate_dirty &&
              workflows.status(*third)->baseline_outdated,
          "retained global candidate or classic private-exclusive write is wrong");
  const auto session_image = sessions.checkpoint();
  const auto workflow_image = workflows.checkpoint();
  SessionRegistry restored_sessions;
  require(restored_sessions.restore(session_image),
          "session registry could not stage workflow checkpoint");
  SessionWorkflowController restored_workflows{restored_sessions};
  require(restored_workflows.restore(workflow_image) &&
              restored_workflows.status(*third)->candidate_dirty &&
              restored_workflows.status(*third)->baseline_outdated &&
              restored_workflows.classic_write(device, 77) ==
                  SessionWorkflowResult::applied,
          "workflow checkpoint lost candidates, revisions or write semantics");
  auto invalid_workflow = workflow_image;
  invalid_workflow.routers.front().running_generation = 0;
  require(!restored_workflows.restore(invalid_workflow) &&
              restored_workflows.status(*third)->candidate_dirty,
          "invalid workflow checkpoint partially replaced active candidates");
  require(workflows.close_device(device) == 4 && sessions.size() == 0,
          "router teardown did not close every workflow-owned session");

  // A clean private candidate still observes its creation generation. Another
  // session may commit many distinct schema paths before that candidate edits
  // one of them, so revision history cannot be discarded merely because the
  // observer has not yet recorded a local change. The generated router arena
  // is sized to retain this realistic long-lived workflow without the former
  // permanent 256-path lockout.
  SessionRegistry history_sessions;
  SessionWorkflowController history{history_sessions};
  const DeviceHandle history_device{1U, 1U};
  const auto stale = history_sessions.create(history_device, "stale");
  const auto writer = history_sessions.create(history_device, "writer");
  require(stale && writer &&
              history.enter(*stale, CandidateMode::private_candidate) ==
                  SessionWorkflowResult::applied &&
              history.enter(*writer, CandidateMode::private_candidate) ==
                  SessionWorkflowResult::applied,
          "revision-history fixture could not open private candidates");
  constexpr std::uint64_t first_history_key = 1000U;
  constexpr std::uint64_t history_commits = 512U;
  for (std::uint64_t index = 0; index < history_commits; ++index)
    require(history.record_edit(*writer, first_history_key + index) ==
                    SessionWorkflowResult::applied &&
                history.commit(*writer) == SessionWorkflowResult::applied,
            "long-lived candidate exhausted router revision metadata");
  require(history.record_edit(*stale,
                              first_history_key + history_commits - 1U) ==
                  SessionWorkflowResult::applied &&
              history.commit(*stale) == SessionWorkflowResult::merge_conflict,
          "long-lived private candidate lost a late same-path conflict");

  SessionRegistry full;
  for (std::uint16_t router = 0;
       router < router::device_catalog::maximum_routers; ++router)
    for (std::size_t index = 0;
         index < router::device_catalog::maximum_sessions_per_router; ++index)
      require(full.create({router, 1}, "s" + std::to_string(index)).has_value(),
              "global 64-session registry capacity was not available");
  require(full.size() == router::device_catalog::maximum_routers *
                             router::device_catalog::maximum_sessions_per_router,
          "64-session registry size is inconsistent");
}
