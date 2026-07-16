// Router-local MD-CLI candidate arbitration. The control shard owns this
// object, SessionRegistry and all revision metadata. It never processes frames
// or exposes mutable candidate storage to another router or browser component.

#pragma once

#include "router/lab_registry.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace router::lab {

enum class SessionWorkflowResult : std::uint8_t {
  applied,
  invalid_session,
  already_configuring,
  not_configuring,
  exclusive_unavailable,
  read_only,
  candidate_full,
  running_locked,
  merge_conflict,
  discard_confirmation_required
};

struct SessionWorkflowStatus {
  CandidateMode mode{CandidateMode::operational};
  std::uint64_t running_generation{};
  std::uint64_t baseline_generation{};
  bool candidate_dirty{};
  bool baseline_outdated{};
};

struct WorkflowKeyRevisionCheckpoint {
  std::uint64_t key{};
  std::uint64_t generation{};
};

struct WorkflowRouterCheckpoint {
  DeviceHandle device{};
  std::uint64_t running_generation{};
  std::uint64_t global_baseline{};
  std::vector<std::uint64_t> global_keys;
  std::vector<WorkflowKeyRevisionCheckpoint> revisions;
};

struct WorkflowSessionCheckpoint {
  SessionHandle session{};
  DeviceHandle device{};
  std::vector<std::uint64_t> keys;
};

struct SessionWorkflowsCheckpoint {
  std::vector<WorkflowRouterCheckpoint> routers;
  std::vector<WorkflowSessionCheckpoint> sessions;
};

class SessionWorkflowController final {
public:
  explicit SessionWorkflowController(SessionRegistry &sessions);

  // Entering a mode changes only session and candidate arbitration state. CLI
  // navigation and implicit or explicit prompt layout remain session-owned
  // presentation concerns layered above this datastore contract.
  [[nodiscard]] SessionWorkflowResult enter(SessionHandle session,
                                            CandidateMode mode) noexcept;
  // Private and exclusive dirty exit requires a confirmed second operation.
  // Global exit keeps the shared candidate exactly as SR OS documents.
  [[nodiscard]] SessionWorkflowResult leave(SessionHandle session,
                                            bool discard) noexcept;
  // Global, exclusive and read-only all address the router's global candidate
  // and may transition in place. Private candidates are intentionally excluded
  // because changing their owner would change datastore identity.
  [[nodiscard]] SessionWorkflowResult transition(SessionHandle session,
                                                 CandidateMode target,
                                                 bool discard) noexcept;

  // key is a stable schema path identity supplied by the command handler. A
  // repeated edit of the same path occupies one candidate entry.
  [[nodiscard]] SessionWorkflowResult record_edit(SessionHandle session,
                                                  std::uint64_t key) noexcept;
  [[nodiscard]] SessionWorkflowResult commit(SessionHandle session) noexcept;
  // Discard replaces only the selected candidate with its current running
  // baseline. The session remains in the same configuration mode.
  [[nodiscard]] SessionWorkflowResult discard(SessionHandle session) noexcept;
  // Classic CLI first checks the running lock before a command handler touches
  // product configuration. The control shard then records a revision only
  // after the handler proves that the running value actually changed. Splitting
  // authorization from publication prevents an idempotent command from making
  // private MD candidates falsely appear out of date.
  [[nodiscard]] SessionWorkflowResult
  authorize_classic_write(DeviceHandle device) const noexcept;
  [[nodiscard]] SessionWorkflowResult classic_write(DeviceHandle device,
                                                     std::uint64_t key) noexcept;
  // The value owner uses this query to decide whether an initialized global
  // candidate follows a classic write. A dirty shared candidate must retain its
  // own values and baseline, while a clean one mirrors the new running value.
  [[nodiscard]] bool global_candidate_dirty(DeviceHandle device) const noexcept;

  [[nodiscard]] bool close(SessionHandle session) noexcept;
  [[nodiscard]] std::size_t close_device(DeviceHandle device) noexcept;
  [[nodiscard]] std::optional<SessionWorkflowStatus>
  status(SessionHandle session) const noexcept;
  [[nodiscard]] SessionWorkflowsCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const SessionWorkflowsCheckpoint &state);
  void swap_state(SessionWorkflowController &other) noexcept;

private:
  struct ChangeSet {
    std::array<std::uint64_t,
               device_catalog::candidate_keys_per_session> keys{};
    std::uint16_t count{};

    [[nodiscard]] bool add(std::uint64_t key) noexcept;
    void clear() noexcept;
  };

  struct KeyRevision {
    std::uint64_t key{};
    std::uint64_t generation{};
  };

  struct SessionCandidate {
    DeviceHandle device{};
    std::uint16_t generation{};
    ChangeSet changes{};
  };

  struct RouterCandidates {
    std::uint16_t device_generation{};
    std::uint64_t running_generation{1};
    std::uint64_t global_baseline{1};
    std::array<std::uint64_t,
               device_catalog::candidate_keys_per_router> global_keys{};
    std::uint16_t global_count{};
    std::array<KeyRevision,
               device_catalog::candidate_keys_per_router> revisions{};
    std::uint16_t revision_count{};
  };

  [[nodiscard]] RouterCandidates &router(DeviceHandle device) noexcept;
  [[nodiscard]] const RouterCandidates *
  router_if_current(DeviceHandle device) const noexcept;
  [[nodiscard]] SessionCandidate &
  candidate(SessionHandle handle, const SessionRecord &record) noexcept;
  [[nodiscard]] const SessionCandidate *
  candidate_if_current(SessionHandle handle,
                       const SessionRecord &record) const noexcept;
  [[nodiscard]] bool add_global(RouterCandidates &router,
                                std::uint64_t key) noexcept;
  [[nodiscard]] std::uint64_t revision(const RouterCandidates &router,
                                       std::uint64_t key) const noexcept;
  [[nodiscard]] SessionWorkflowResult
  apply(RouterCandidates &router, const std::uint64_t *keys,
        std::size_t count, std::uint64_t baseline) noexcept;

  SessionRegistry &sessions_;
  static constexpr std::size_t maximum_sessions =
      device_catalog::maximum_routers *
      device_catalog::maximum_sessions_per_router;
  // Both arenas have stable process-lifetime addresses and live off the small
  // control pthread stack. Candidate operations never allocate after startup.
  std::unique_ptr<std::array<SessionCandidate, maximum_sessions>> candidates_;
  std::unique_ptr<
      std::array<RouterCandidates, device_catalog::maximum_routers>> routers_;
};

} // namespace router::lab
