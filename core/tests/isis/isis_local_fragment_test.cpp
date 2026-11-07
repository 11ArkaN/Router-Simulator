// Complete semantic family edits validate before changing any reserved slot.
// Local generation and retained encoded LSDB bytes remain separate owners.
#include "router/isis_local_lsp_set.hpp"
#include "router/isis_fragment_composition.hpp"
#include "router/isis_neighbor_origination.hpp"
#include "router/isis_origin_fragment_workspace.hpp"
#include <array>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>
namespace {
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS local fragment invariant at " + std::to_string(where.line()));
}
}
void isis_local_fragment_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = RuntimeClock::time_point{100s};
  const SystemId local{1U, 2U, 3U, 4U, 5U, 6U};
  const LanId source{1U, 2U, 3U, 4U, 5U, 6U, 0U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  auto next = root; next[7U] = 1U;
  LocalLspProgram program;
  program.random = 17U;
  program.levels[0U] = LocalLspLevelProgram{1200U, 128U, 1s, 40s};
  program.records = {{0U, root, 1U, {}}, {0U, next, 1U, {}, false}};
  LocalLspSet owner(local, 3U, {InstanceFormat::standard, 0U}, program, now);
  const std::array<std::uint8_t, 3U> option{250U, 1U, 7U};
  const std::array<std::uint8_t, 3U> malformed{250U, 2U, 7U};
  std::array fragments{LocalLspFragment{0U, 1U, option}, LocalLspFragment{1U, 1U, malformed}};
  const auto before = owner.checkpoint(now);
  require(owner.replace_fragments(0U, source, fragments, now) == LocalContentResult::invalid &&
      !owner.contains(0U, next) && owner.checkpoint(now).entries[0U].content == before.entries[0U].content);
  fragments[1U].options = option;
  require(owner.replace_fragments(0U, source, fragments, now) == LocalContentResult::changed && owner.contains(0U, next));
  require(owner.replace_fragments(0U, source, fragments, now) == LocalContentResult::unchanged);
  fragments[1U].number = 2U;
  require(owner.replace_fragments(0U, source, fragments, now) == LocalContentResult::missing && owner.contains(0U, next));
  fragments[1U].number = 1U;
  const std::array<std::uint8_t, 104U> large{250U, 102U};
  fragments[1U].options = large;
  require(owner.replace_fragments(0U, source, fragments, now) == LocalContentResult::capacity && owner.contains(0U, next));
  require(owner.replace_fragments(0U, source, {}, now) == LocalContentResult::invalid && owner.contains(0U, root));
  require(owner.replace_fragments(0U, source, std::span{fragments}.first(1U), now) == LocalContentResult::changed &&
      !owner.contains(0U, next) && owner.contains(0U, root));
  const auto saved = owner.checkpoint(now);
  require(saved.entries[1U].retirement_pending && !saved.entries[1U].content.active);
  auto restored = LocalLspSet::restore_checkpoint(saved, local, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(restored && !restored->contains(0U, next) && restored->contains(0U, root));
  const UpdateLevelConfiguration level{{4U, 1024U}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  InstanceUpdateProcess update(local, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  program.records[1U].active = true;
  LocalLspSet generated(local, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(generated.reserve_publication(update));
  auto scratch = std::make_unique<PduScratch>();
  struct Projection {
    const InstanceUpdateProcess *update;
    RuntimeClock::time_point now;
    std::uint32_t sequence{1U};
    std::size_t events{};
    bool complete{true}, purge{};
  } projection{&update, now};
  const LevelObserver observer{&projection, +[](void *context, const LevelEvent &event) noexcept {
    if (event.kind != LevelEventKind::database_changed && event.kind != LevelEventKind::database_refreshed) return;
    auto &value = *static_cast<Projection *>(context);
    ++value.events;
    for (std::uint8_t fragment{}; fragment < 2U; ++fragment) {
      const auto record = value.update->level(0U)->database().database().find(
          {1U, 2U, 3U, 4U, 5U, 6U, 0U, fragment}, value.now);
      value.complete = value.complete && record &&
          record->header.sequence == (fragment && value.purge ? 1U : value.sequence) &&
          record->purge_installed == (fragment && value.purge);
    }
  }};
  std::size_t budget{1U};
  require(!generated.service(update, {}, now, *scratch, observer, budget).published &&
      !update.level(0U)->database().database().size() && !projection.events);
  const auto prepared_local = generated.checkpoint(now);
  const auto prepared_update = update.checkpoint(now);
  require(prepared_local.entries[0U].generation.pending.has_value());
  auto resumed_update = InstanceUpdateProcess::restore_checkpoint(prepared_update,
      prepared_update.configuration, {}, now);
  auto resumed_local = LocalLspSet::restore_checkpoint(prepared_local, local, 3U,
      {InstanceFormat::standard, 0U}, program, now);
  require(resumed_update && resumed_local && resumed_local->reserve_publication(*resumed_update));
  projection.update = resumed_update.get();
  budget = 1U;
  require(!resumed_local->service(*resumed_update, {}, now, *scratch, observer, budget).published && !projection.events);
  budget = 1U;
  require(resumed_local->service(*resumed_update, {}, now, *scratch, observer, budget).published == 2U &&
      projection.events == 2U && projection.complete);
  InstanceUpdateProcess fenced_update(local, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  LocalLspSet fenced(local, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(fenced.reserve_publication(fenced_update));
  const LevelObserver quiet{nullptr, +[](void *, const LevelEvent &) noexcept {}};
  budget = 1U;
  require(!fenced.service(fenced_update, {}, now, *scratch, quiet, budget).published);
  require(fenced.withdraw(0U, next) == LocalContentResult::changed);
  budget = 0U;
  require(!fenced.service(fenced_update, {}, now, *scratch, quiet, budget).published &&
      !fenced_update.level(0U)->database().database().size());
  budget = 1U;
  require(fenced.service(fenced_update, {}, now, *scratch, quiet, budget).published == 1U);
  // Moving content out of a fragment and retiring it cannot expose only the
  // new root: live replacement and same-sequence purge commit together.
  const std::array root_only{LocalLspFragment{0U, 1U, option}};
  require(resumed_local->replace_fragments(0U, source, root_only, now + 1s) == LocalContentResult::changed);
  projection.now = now + 1s;
  projection.sequence = 2U;
  projection.purge = true;
  projection.events = 0U;
  budget = 1U;
  require(!resumed_local->service(*resumed_update, {}, now + 1s, *scratch, observer, budget).published &&
      !projection.events && !resumed_update->level(0U)->database().database().find(next, now + 1s)->purge_installed);
  budget = 1U;
  require(resumed_local->service(*resumed_update, {}, now + 1s, *scratch, observer, budget).published == 2U &&
      projection.events == 2U && projection.complete);

}

void isis_local_fragment_overload_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = RuntimeClock::time_point{100s};
  const SystemId system{1U, 2U, 3U, 4U, 5U, 6U};
  const LanId source{1U, 2U, 3U, 4U, 5U, 6U, 0U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  auto fragment = root; fragment[7U] = 1U;
  const UpdateLevelConfiguration level{{2U, 128U + lsp_header_octets}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  InstanceUpdateProcess update(system, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  LocalLspProgram program;
  program.random = 17U;
  program.levels[0U] = LocalLspLevelProgram{1200U, 128U, 1s, 40s};
  program.records = {{0U, root, 1U, {}}, {0U, fragment, 1U, {}}};
  LocalLspSet local(system, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(local.reserve_publication(update));
  struct Events { LocalLspSet *local; RuntimeClock::time_point now; } events{&local, now};
  const LevelObserver observer{&events, +[](void *context, const LevelEvent &event) noexcept {
    auto &value = *static_cast<Events *>(context);
    if (event.kind == LevelEventKind::overload_entered)
      static_cast<void>(value.local->waiting_overload(0U, true, value.now));
  }};
  auto scratch = std::make_unique<PduScratch>();
  std::size_t budget{4U};
  require(local.service(update, {}, now, *scratch, observer, budget).published == 2U);
  const std::array<std::uint8_t, 3U> option{250U, 1U, 7U};
  const std::array<std::uint8_t, 100U> large{250U, 98U};
  const std::array replacement{LocalLspFragment{0U, 1U, option}, LocalLspFragment{1U, 1U, large}};
  events.now = now + 1s;
  require(local.replace_fragments(0U, source, replacement, events.now) == LocalContentResult::changed);
  budget = 4U;
  const auto failed = local.service(update, {}, events.now, *scratch, observer, budget);
  const auto stored_root = update.level(0U)->database().database().find(root, events.now);
  const auto stored_fragment = update.level(0U)->database().database().find(fragment, events.now);
  require(failed.published == 1U && failed.blocked == 2U && update.level(0U)->waiting() &&
      stored_root && stored_root->header.sequence == 2U && (stored_root->header.flags & 4U) &&
      stored_root->pdu.tlvs.empty() && stored_fragment && stored_fragment->header.sequence == 1U &&
      stored_fragment->pdu.tlvs.empty());
  budget = 4U;
  const auto blocked = local.service(update, {}, events.now, *scratch, observer, budget);
  require(!blocked.published && blocked.blocked == 2U && blocked.deadline && *blocked.deadline > events.now && budget == 4U);
  // ISO 7.3.5 refresh still applies while the replacement waits for storage.
  // Renewing the old layout must neither expose new content nor unblock it.
  events.now = now + 45s;
  budget = 4U;
  const auto refreshed = local.service(update, {}, events.now, *scratch, observer, budget);
  const auto refreshed_root = update.level(0U)->database().database().find(root, events.now);
  const auto refreshed_fragment = update.level(0U)->database().database().find(fragment, events.now);
  require(refreshed.published == 2U && refreshed.blocked == 2U && refreshed_root && refreshed_fragment &&
      refreshed_root->header.sequence == 3U && (refreshed_root->header.flags & 4U) &&
      refreshed_fragment->header.sequence == 2U && refreshed_root->pdu.tlvs.empty() && refreshed_fragment->pdu.tlvs.empty());
  budget = 4U;
  const auto still_blocked = local.service(update, {}, events.now, *scratch, observer, budget);
  require(!still_blocked.published && still_blocked.blocked == 2U && still_blocked.deadline &&
      *still_blocked.deadline > events.now && budget == 4U);

}

void isis_local_fragment_key_rotation_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = RuntimeClock::time_point{100s};
  const SystemId system{1U, 2U, 3U, 4U, 5U, 6U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  const UpdateLevelConfiguration level{{65U, 8192U}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  LocalLspProgram program;
  program.random = 17U;
  program.levels[0U] = LocalLspLevelProgram{1200U, 128U, 1s, 40s};
  auto second = root; second[7U] = 1U;
  program.records = {{0U, root, 1U, {}}, {0U, second, 1U, {}}};
  InstanceUpdateProcess update(system, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  LocalLspSet local(system, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(local.reserve_publication(update));
  const std::array<std::uint8_t, 4U> old_secret{1U, 2U, 3U, 4U}, new_secret{5U, 6U, 7U, 8U};
  const AuthenticationKey old_key{AuthenticationMethod::hmac_sha256, 7U, old_secret};
  const AuthenticationKey new_key{AuthenticationMethod::hmac_sha256, 8U, new_secret};
  const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
  auto scratch = std::make_unique<PduScratch>();
  std::size_t budget{1U};
  require(!local.service(update, {TransmitAuthentication{true, old_key}, {}}, now, *scratch, observer, budget).published);
  budget = 1U;
  require(!local.service(update, {TransmitAuthentication{true, new_key}, {}}, now, *scratch, observer, budget).published &&
      !update.level(0U)->database().database().size());
  budget = 1U;
  require(local.service(update, {TransmitAuthentication{true, new_key}, {}}, now, *scratch, observer, budget).published == 2U);
  for (const auto &id : {root, second}) {
    const auto record = update.level(0U)->database().database().find(id, now);
    require(record && verify_authentication(record->pdu.bytes, new_key) == AuthenticationError::none &&
        verify_authentication(record->pdu.bytes, old_key) != AuthenticationError::none);
  }
  // A family larger than one control-turn budget still completes. No prefix
  // of that family is visible while its remaining members are being prepared.
  program.records.clear();
  for (std::uint8_t fragment{}; fragment < 65U; ++fragment) {
    auto id = root; id[7U] = fragment;
    program.records.push_back({0U, id, 1U, {}});
  }
  InstanceUpdateProcess large_update(system, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  LocalLspSet large(system, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(large.reserve_publication(large_update));
  for (std::size_t member{}; member < 65U; ++member) {
    budget = 1U;
    const auto result = large.service(large_update, {}, now, *scratch, observer, budget);
    require(!budget && result.published == (member == 64U ? 65U : 0U) &&
        large_update.level(0U)->database().database().size() == (member == 64U ? 65U : 0U));
  }
}

void isis_local_fragment_single_blocked_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = RuntimeClock::time_point{100s};
  const SystemId system{1U, 2U, 3U, 4U, 5U, 6U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  auto pseudonode = root; pseudonode[6U] = 4U;
  auto fragment = pseudonode; fragment[7U] = 1U;
  const UpdateLevelConfiguration level{{3U, 128U + 2U * lsp_header_octets}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  InstanceUpdateProcess update(system, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  LocalLspProgram program;
  program.random = 17U;
  program.levels[0U] = LocalLspLevelProgram{1200U, 128U, 1s, 40s};
  program.records = {{0U, root, 1U, {}}, {0U, pseudonode, 1U, {}}, {0U, fragment, 1U, {}}};
  LocalLspSet local(system, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(local.reserve_publication(update));
  struct Events { LocalLspSet *local; RuntimeClock::time_point now; } events{&local, now};
  const LevelObserver observer{&events, +[](void *context, const LevelEvent &event) noexcept {
    auto &value = *static_cast<Events *>(context);
    if (event.kind == LevelEventKind::overload_entered)
      static_cast<void>(value.local->waiting_overload(0U, true, value.now));
  }};
  auto scratch = std::make_unique<PduScratch>();
  std::size_t budget{4U};
  require(local.service(update, {}, now, *scratch, observer, budget).published == 3U);
  const std::array<std::uint8_t, 100U> large{250U, 98U};
  events.now = now + 1s;
  require(local.replace(0U, fragment, 1U, large, events.now) == LocalContentResult::changed);
  budget = 4U;
  const auto refused = local.service(update, {}, events.now, *scratch, observer, budget);
  require(refused.blocked && update.level(0U)->waiting() &&
      update.level(0U)->database().database().find(fragment, events.now)->header.sequence == 1U);
  events.now = now + 45s;
  budget = 8U;
  static_cast<void>(local.service(update, {}, events.now, *scratch, observer, budget));
  const auto retained = update.level(0U)->database().database().find(fragment, events.now);
  require(retained && retained->header.sequence == 2U && retained->pdu.tlvs.empty() &&
      local.last_error(0U, fragment) == UpdateStatus::applied);
  budget = 8U;
  const auto deferred = local.service(update, {}, events.now, *scratch, observer, budget);
  require(!deferred.published && deferred.blocked && deferred.deadline && *deferred.deadline > events.now);
}

void isis_local_fragment_composition_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = RuntimeClock::time_point{100s};
  const SystemId system{1U, 2U, 3U, 4U, 5U, 6U};
  const LanId source{1U, 2U, 3U, 4U, 5U, 6U, 0U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  const UpdateLevelConfiguration level{{5U, 1024U}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  InstanceUpdateProcess update(system, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  LocalLspProgram program;
  program.random = 17U;
  program.levels[0U] = LocalLspLevelProgram{1200U, 128U, 1s, 40s};
  for (std::uint8_t number{}; number < 3U; ++number) {
    auto id = root; id[7U] = number;
    program.records.push_back({0U, id, 1U, {}, !number});
  }
  auto pseudonode = root; pseudonode[6U] = 4U;
  auto pn_fragment = pseudonode; pn_fragment[7U] = 1U;
  program.records.push_back({0U, pseudonode, 1U, {}, false});
  program.records.push_back({0U, pn_fragment, 1U, {}, false});
  LocalLspSet local(system, 3U, {InstanceFormat::standard, 0U}, program, now);
  require(local.reserve_publication(update));
  FragmentPlanner planner(17U);
  const std::array<std::uint8_t, 6U> area{1U, 4U, 3U, 0x49U, 0U, 1U};
  std::array<std::array<std::uint8_t, 13U>, 16U> edges{};
  std::array<FragmentUnit, 17U> units{};
  units[0U] = {0U, area, {}, true};
  for (std::size_t index{}; index < edges.size(); ++index) {
    TlvWriter writer(edges[index]);
    require(append_p2p_origin_neighbor(writer, {2U, 2U, 3U, 4U, 5U, static_cast<std::uint8_t>(index + 1U)}, {10U, {}}));
    units[index + 1U] = {index + 1U, writer.bytes(), {}, false};
  }
  std::array<std::array<std::uint8_t, 101U>, 3U> bytes{};
  std::array options{FragmentOptions{bytes[0U]}, FragmentOptions{bytes[1U]}, FragmentOptions{bytes[2U]}};
  require(compose_local_fragments(local, planner, 0U, source, 1U, units, 101U, options, now) == LocalContentResult::changed);
  auto scratch = std::make_unique<PduScratch>();
  const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
  std::size_t budget{3U};
  require(local.service(update, {}, now, *scratch, observer, budget).published == 3U);
  std::uint32_t neighbors{};
  for (std::uint8_t number{}; number < 3U; ++number) {
    auto id = root; id[7U] = number;
    const auto record = update.level(0U)->database().database().find(id, now);
    require(record && record->pdu.bytes.size() <= 128U && valid_lsp_checksum(record->pdu));
    const auto counts = lsp_link_counts(record->pdu.tlvs);
    require(counts.has_value());
    neighbors += counts->wide;
    TlvCursor cursor(record->pdu.tlvs);
    std::size_t areas{};
    while (const auto option = cursor.next()) areas += option->code == 1U;
    require(areas == (number ? 0U : 1U));
  }
  require(neighbors == 16U);
  // Removing all neighbor units retires both higher fragments in the same
  // publication as the new fragment-zero contents.
  require(compose_local_fragments(local, planner, 0U, source, 1U, std::span{units}.first(1U),
      101U, options, now + 1s) == LocalContentResult::changed);
  budget = 3U;
  require(local.service(update, {}, now + 1s, *scratch, observer, budget).published == 3U);
  for (std::uint8_t number{1U}; number < 3U; ++number) {
    auto id = root; id[7U] = number;
    const auto record = update.level(0U)->database().database().find(id, now + 1s);
    require(record && record->purge_installed && record->header.sequence == 1U);
  }
  OriginFragmentWorkspace workspace(7U, 3U, 101U);
  const auto append = [&](std::uint32_t metric) {
    require(workspace.add_options({0U, 0U}, area, std::uint8_t{0U}, true));
    for (std::uint8_t index{}; index < 6U; ++index) {
      const LanId peer{2U, 2U, 3U, 4U, 5U, static_cast<std::uint8_t>(index + 1U), 0U};
      require(workspace.add_link({1U, index}, peer, {index == 1U ? metric : 10U, std::uint8_t{10U}},
          OriginFragmentWorkspace::previous_link(local, 0U, source, peer, 3U)));
    }
  };
  append(10U);
  require(workspace.compose(local, 0U, source, 1U, 3U, 101U, now + 2s) == LocalContentResult::changed);
  budget = 3U;
  require(local.service(update, {}, now + 2s, *scratch, observer, budget).published == 2U);
  for (std::uint8_t number{}; number < 2U; ++number) {
    auto id = root; id[7U] = number;
    const auto content = local.fragment(0U, id);
    require(content.has_value());
    const auto counts = lsp_link_counts(content->options);
    require(counts && counts->narrow == 3U && counts->wide == 3U);
  }
  append(20U);
  require(workspace.compose(local, 0U, source, 1U, 3U, 101U, now + 3s) == LocalContentResult::changed);
  budget = 3U;
  require(local.service(update, {}, now + 3s, *scratch, observer, budget).published == 1U);
  auto unchanged_id = root; unchanged_id[7U] = 1U;
  require(update.level(0U)->database().database().find(unchanged_id, now + 3s)->header.sequence == 2U);
  // Invalid metrics latch a refusal for this attempt and cannot partially edit
  // the catalog. The following attempt starts with empty borrowed preparation.
  require(!workspace.add_link({1U, 1U}, {2U, 2U, 3U, 4U, 5U, 1U, 0U}, {0U, {}}, {}));
  require(workspace.compose(local, 0U, source, 1U, 3U, 101U, now + 4s) == LocalContentResult::invalid);
  append(20U);
  require(workspace.compose(local, 0U, source, 1U, 3U, 101U, now + 4s) == LocalContentResult::unchanged);

  OriginFragmentWorkspace pseudonode_workspace(6U, 2U, 101U);
  auto pn_source = source; pn_source[6U] = 4U;
  require(pseudonode_workspace.add_pseudonode_link({3U, 0U}, system, true, {}));
  for (std::uint8_t peer{1U}; peer < 6U; ++peer)
    require(pseudonode_workspace.add_pseudonode_link({3U, peer}, {2U, 2U, 3U, 4U, 5U, peer}, true, {}));
  require(pseudonode_workspace.compose(local, 0U, pn_source, 1U, 2U, 101U, now + 5s) == LocalContentResult::changed);
  budget = 2U;
  require(local.service(update, {}, now + 5s, *scratch, observer, budget).published == 2U);
  for (const auto &id : {pseudonode, pn_fragment}) {
    const auto record = update.level(0U)->database().database().find(id, now + 5s);
    require(record && valid_lsp_checksum(record->pdu));
    const auto counts = lsp_link_counts(record->pdu.tlvs);
    require(counts && counts->narrow == 3U && counts->wide == 3U);
    TlvCursor cursor(record->pdu.tlvs);
    while (const auto option = cursor.next()) {
      require(option->code != 1U);
      if (option->code == 22U) {
        ExtendedNeighborCursor links(*option);
        while (const auto link = links.next()) require(!link->metric);
        require(links.valid());
      }
    }
  }
  require(pseudonode_workspace.compose(local, 0U, pn_source, 1U, 2U, 101U, now + 6s) == LocalContentResult::changed);
  budget = 2U;
  require(local.service(update, {}, now + 6s, *scratch, observer, budget).published == 2U &&
      !local.contains(0U, pseudonode) && !local.contains(0U, pn_fragment));

  const std::array<std::uint8_t, 1U> one_slot{0U};
  append(20U);
  require(workspace.validate(one_slot, 101U) == LocalContentResult::capacity && local.contains(0U, unchanged_id));
  const std::array<std::uint8_t, 2U> sparse_slots{0U, 2U};
  append(20U);
  require(workspace.validate(sparse_slots, 101U) == LocalContentResult::unchanged);
  append(20U);
  require(workspace.compose(local, 0U, source, 1U, sparse_slots, 101U, now + 7s) == LocalContentResult::changed &&
      !local.fragment(0U, unchanged_id));
  const LanId relocated_peer{2U, 2U, 3U, 4U, 5U, 5U, 0U};
  require(OriginFragmentWorkspace::previous_link(local, 0U, source, relocated_peer, 3U) == 2U);
  budget = 2U;
  require(local.service(update, {}, now + 7s, *scratch, observer, budget).published == 2U);
  auto sparse_id = root; sparse_id[7U] = 2U;
  require(update.level(0U)->database().database().find(unchanged_id, now + 7s)->purge_installed &&
      !update.level(0U)->database().database().find(sparse_id, now + 7s)->purge_installed);

}
