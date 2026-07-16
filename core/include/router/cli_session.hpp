// Router-owned terminal session semantics shared by the CLI engine, registry
// and checkpoint codec. This module contains no router configuration or UI
// state, so session persistence does not depend on a particular chassis.

#pragma once

#include <array>
#include <cstdint>

namespace router {

enum class CliEngine : std::uint8_t { md, classic };
enum class CliCompletionTrigger : std::uint8_t { tab, question, space };

// The navigation engine retains the exact workflow selected by this terminal.
// Candidate bytes and multi-session arbitration remain router-owned, but the
// prompt and exit messages must not infer a mode from another session.
enum class MdCliWorkflow : std::uint8_t {
  operational,
  implicit_exclusive,
  explicit_exclusive,
  implicit_global,
  explicit_global,
  implicit_private,
  explicit_private,
  implicit_read_only,
  explicit_read_only
};

struct CliSession {
  // MD and classic are engines in one router terminal session. Switching does
  // not create another device or a global application mode.
  CliEngine engine{CliEngine::md};
  MdCliWorkflow md_workflow{MdCliWorkflow::operational};
  // Each engine retains its own present and previous working contexts. Fixed
  // storage bounds checkpoint size and ensures paths remain NUL-terminated.
  std::array<char, 160> md_path{};
  std::array<char, 160> classic_path{};
  std::array<char, 160> md_previous_path{};
  std::array<char, 160> classic_previous_path{};
  // Confirmation and candidate markers are semantic session state. Persisting
  // them prevents reload from changing the meaning of the next input byte.
  bool md_exit_confirmation{};
  // A confirmation may leave configuration mode or transition exclusive to
  // another global-candidate mode. Keeping the requested target in the same
  // session makes the following y/n byte deterministic and checkpointable.
  MdCliWorkflow md_confirmation_target{MdCliWorkflow::operational};
  bool candidate_dirty{};
  bool candidate_outdated{};
  bool classic_unsaved{};

  bool operator==(const CliSession &) const = default;
};

} // namespace router
