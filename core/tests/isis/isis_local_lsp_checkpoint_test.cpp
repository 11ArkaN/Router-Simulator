// Local semantic and update owners are destroyed before resuming a saved pair.
// Publication tests retain withdrawn identities, blocked work, sequence floors
// and jitter progression while malformed transfers leave a live owner intact.

#include "router/isis_local_lsp_set.hpp"

#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

void isis_local_lsp_checkpoint_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location line = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS local checkpoint invariant at " + std::to_string(line.line()));
  };
  const auto now = RuntimeClock::time_point{100s}, restored_at = RuntimeClock::time_point{9000s};
  const SystemId local{1U, 2U, 3U, 4U, 5U, 6U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  auto pseudonode = root;
  pseudonode[6U] = 4U;
  const UpdateInstanceSelector selector{InstanceFormat::standard, 0U};
  const UpdateLevelConfiguration level{{8U, 8192U}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  LocalLspProgram program;
  program.levels = {LocalLspLevelProgram{1200U, 256U, 1s, 40s}, std::nullopt};
  program.random = 19U;
  program.records = {{0U, root, 3U, {}}, {0U, pseudonode, 3U, {}}};
  auto update = std::make_unique<InstanceUpdateProcess>(local, std::uint8_t{3U},
      std::array<std::optional<UpdateLevelConfiguration>, 2U>{level, std::nullopt},
      std::span<const UpdateCircuitConfiguration>{}, selector);
  auto current = std::make_unique<LocalLspSet>(local, std::uint8_t{3U}, selector, program, now);
  auto scratch = std::make_unique<PduScratch>();
  const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
  std::size_t budget{8U};
  require(current->service(*update, {}, now, *scratch, observer, budget).published == 2U);
  require(current->withdraw(0U, pseudonode) == LocalContentResult::changed);
  budget = 8U;
  require(current->service(*update, {TransmitAuthentication{true, std::nullopt}, {}}, now + 1s,
      *scratch, observer, budget).blocked == 1U);
  require(current->waiting_overload(0U, true, now + 1s) == LocalContentResult::changed);
  const auto saved = current->checkpoint(now + 1500ms);
  const auto database = update->checkpoint(now + 1500ms);
  auto resumed = LocalLspSet::restore_checkpoint(saved, local, 3U, selector, program, restored_at);
  auto resumed_update = InstanceUpdateProcess::restore_checkpoint(database, database.configuration, {}, restored_at);
  require(resumed && resumed_update && !resumed->contains(0U, pseudonode) && resumed->sequence(0U, pseudonode) == 1U);
  current.reset(); update.reset();
  for (unsigned invalid{}; invalid < 13U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: bad.version = 2U; break;
      case 1U: ++bad.local[0U]; break;
      case 2U: ++bad.maximum_areas; break;
      case 3U: ++bad.selector.wire_instance; break;
      case 4U: ++bad.levels[0U]->maximum_age; break;
      case 5U: bad.waiting_overload[1U] = true; break;
      case 6U: bad.first = bad.entries.size(); break;
      case 7U: bad.terminal = GenerationStatus::ready; break;
      case 8U: bad.entries[0U].content.id[7U] = 3U; break;
      case 9U: bad.entries[0U].retirement_pending = true; break;
      case 10U: bad.entries[1U].retirement_pending = false; break;
      case 11U: bad.entries[0U].generation.random = 0U; break;
      default: bad.entries[0U].content.options = {10U, 1U, 0U}; break;
    }
    require(!LocalLspSet::restore_checkpoint(bad, local, 3U, selector, program, restored_at) &&
        resumed->sequence(0U, pseudonode) == 1U);
  }
  budget = 8U;
  require(resumed->service(*resumed_update, {}, restored_at, *scratch, observer, budget).published == 1U);
  const auto root_wire = resumed_update->level(0U)->database().database().find(root, restored_at);
  require(root_wire && (root_wire->header.flags & 4U));
  const auto still_live = resumed_update->level(0U)->database().database().find(pseudonode, restored_at);
  require(still_live && !still_live->purge_installed);
  resumed->retry(0U);
  budget = 8U;
  require(resumed->service(*resumed_update, {}, restored_at, *scratch, observer, budget).published == 1U);
  const auto purged = resumed_update->level(0U)->database().database().find(pseudonode, restored_at);
  require(purged && purged->purge_installed && purged->header.sequence == 1U);
  require(resumed->require_after(0U, pseudonode, 100U, restored_at));
  require(resumed->replace(0U, pseudonode, 3U, {}, restored_at) == LocalContentResult::changed);
  const auto reactivated = resumed->checkpoint(restored_at);
  auto another = LocalLspSet::restore_checkpoint(reactivated, local, 3U, selector, program, restored_at);
  resumed.reset();
  require(another && another->contains(0U, pseudonode));
  budget = 8U;
  require(another->service(*resumed_update, {}, restored_at, *scratch, observer, budget).published == 1U &&
      another->sequence(0U, pseudonode) == 101U);
}
