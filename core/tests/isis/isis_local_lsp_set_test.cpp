// Current semantic content and counters are independent of retained local
// PDUs. Tests publish encoded L1/L2 records through the actual update owner.

#include "router/isis_local_lsp_set.hpp"

#include <limits>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

void isis_local_lsp_set_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS current set failed at " + std::to_string(location.line()));
  };
  const auto now = RuntimeClock::time_point{100s};
  const SystemId local{1U, 2U, 3U, 4U, 5U, 6U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  const UpdateLevelConfiguration level{{8U, 8192U}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  InstanceUpdateProcess update(local, 3U, {level, level}, {}, {InstanceFormat::standard, 0U});
  LocalLspProgram program;
  program.levels = {LocalLspLevelProgram{1200U, 128U, 1s, 40s}, LocalLspLevelProgram{1200U, 128U, 1s, 40s}};
  program.random = 17U;
  const std::vector<std::uint8_t> area{1U, 4U, 3U, 0x49U, 0U, 1U};
  program.records = {{0U, root, 3U, area}, {1U, root, 3U, area}};
  LocalLspSet current(local, 3U, {InstanceFormat::standard, 0U}, std::move(program), now);
  unsigned notifications{};
  const LevelObserver observer{&notifications, +[](void *context, const LevelEvent &) noexcept {
    ++*static_cast<unsigned *>(context);
  }};
  auto scratch = std::make_unique<PduScratch>();
  const auto publish = [&](RuntimeClock::time_point time, std::array<TransmitAuthentication, 2U> keys = {},
      std::size_t work = 2U) { return current.service(update, keys, time, *scratch, observer, work); };
  const auto first = publish(now, {}, 1U);
  require(first.published == 1U && first.deadline == now && !first.blocked);
  require(publish(now).published == 1U && notifications == 2U);
  const auto stored = [&](std::size_t selected) { return update.level(selected)->database().database().find(root, now); };
  require(stored(0U)->header.sequence == 1U && stored(1U)->header.sequence == 1U &&
      current.sequence(0U, root) == 1U && current.sequence(1U, root) == 1U &&
      update.level(0U)->database().database().allocated_octets() == 128U);
  require(current.replace(0U, root, 3U, area, now + 1s) == LocalContentResult::unchanged &&
      !publish(now + 1s).published);
  require(current.replace(0U, root, 7U, area, now + 1s) == LocalContentResult::changed &&
      publish(now + 1s).published == 1U && stored(0U)->header.sequence == 2U && stored(0U)->header.flags == 7U);
  require(current.require_after(0U, root, 100U, now + 2s) && publish(now + 2s).published == 1U &&
      stored(0U)->header.sequence == 101U && stored(1U)->header.sequence == 1U);
  require(current.replace(0U, root, 3U, area, now + 3s) == LocalContentResult::changed);
  const auto refused = publish(now + 3s, {TransmitAuthentication{true, std::nullopt}, {}});
  require(!refused.published && refused.blocked == 1U && stored(0U)->header.sequence == 101U &&
      publish(now + 3s).blocked == 1U && current.last_error(0U, root) == UpdateStatus::authentication);
  current.retry(0U);
  require(publish(now + 3s).published == 1U && stored(0U)->header.sequence == 102U);
  require(current.waiting_overload(0U, true, now + 4s) == LocalContentResult::changed &&
      publish(now + 4s).published == 1U && stored(0U)->header.flags == 7U);
  require(current.waiting_overload(0U, false, now + 5s) == LocalContentResult::changed &&
      publish(now + 5s).published == 1U && stored(0U)->header.flags == 3U);
  require(current.replace(0U, root, 7U, area, now + 6s) == LocalContentResult::changed && publish(now + 6s).published == 1U);
  require(current.waiting_overload(0U, true, now + 7s) == LocalContentResult::changed && publish(now + 7s).published == 1U &&
      current.waiting_overload(0U, false, now + 8s) == LocalContentResult::changed && publish(now + 8s).published == 1U &&
      stored(0U)->header.flags == 7U);
  auto missing = root;
  missing.back() = 1U;
  require(!current.contains(0U, missing) && !current.require_after(0U, missing, 9U, now) &&
      !current.last_error(0U, missing) &&
      current.replace(0U, missing, 3U, area, now) == LocalContentResult::missing);
  const std::array<std::uint8_t, 2U> poi{13U, 0U};
  require(current.replace(0U, root, 3U, poi, now) == LocalContentResult::invalid);
  const std::array<std::uint8_t, 104U> too_large{8U, 102U};
  require(current.replace(0U, root, 3U, too_large, now) == LocalContentResult::capacity);
  const auto committed = current.sequence(0U, root);
  require(current.require_after(0U, root, std::numeric_limits<std::uint32_t>::max(), now + 9s));
  const auto exhausted = publish(now + 9s, {}, 0U);
  require(exhausted.terminal == GenerationStatus::sequence_exhausted && !exhausted.deadline &&
      !publish(now + 100s).published && stored(0U)->header.sequence == committed);
}

void isis_local_lsp_retirement_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS local retirement failed at " + std::to_string(location.line()));
  };
  const auto now = RuntimeClock::time_point{100s};
  const SystemId local{1U, 2U, 3U, 4U, 5U, 6U};
  const LspId root{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  auto fragment = root;
  fragment.back() = 1U;
  const UpdateLevelConfiguration level{{8U, 8192U}, 0U, 0U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  InstanceUpdateProcess update(local, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  LocalLspProgram program;
  program.levels[0U] = LocalLspLevelProgram{1200U, 128U, 1s, 40s};
  program.random = 17U;
  const std::vector<std::uint8_t> options{8U, 0U};
  program.records = {{0U, root, 1U, options}, {0U, fragment, 1U, options, false}};
  require(program.active_records() == 1U);
  LocalLspSet current(local, 3U, {InstanceFormat::standard, 0U}, program, now);
  const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
  auto scratch = std::make_unique<PduScratch>();
  const auto publish = [&](RuntimeClock::time_point time, std::array<TransmitAuthentication, 2U> keys = {},
      std::size_t work = 2U) { return current.service(update, keys, time, *scratch, observer, work); };
  const auto stored = [&](RuntimeClock::time_point time) { return update.level(0U)->database().database().find(fragment, time); };
  require(publish(now).published == 1U && !current.contains(0U, fragment) && !stored(now));
  require(current.withdraw(0U, root) == LocalContentResult::invalid &&
      current.withdraw(0U, fragment) == LocalContentResult::unchanged);
  require(current.replace(0U, fragment, 1U, options, now + 1s) == LocalContentResult::changed &&
      publish(now + 1s).published == 1U && stored(now + 1s)->header.sequence == 1U);
  require(current.withdraw(0U, fragment) == LocalContentResult::changed && !current.contains(0U, fragment));
  const auto blocked = publish(now + 2s, {TransmitAuthentication{true, std::nullopt}, {}});
  require(blocked.blocked == 1U && !blocked.published && stored(now + 2s)->header.remaining_seconds &&
      current.last_error(0U, fragment) == UpdateStatus::authentication);
  current.retry(0U);
  require(publish(now + 2s).published == 1U && stored(now + 2s)->purge_installed &&
      stored(now + 2s)->header.sequence == 1U && !stored(now + 2s)->header.remaining_seconds);
  const auto retirement = update.level(0U)->database().database().next_deadline(LspDeadlineKind::retire_purge);
  require(retirement && retirement->at == now + 1202s && !publish(now + 3s).published);
  require(current.require_after(0U, fragment, 77U, now + 3s) && !publish(now + 3s).published);
  require(update.retire_purge(0U, fragment, now + 1203s, observer) && !stored(now + 1203s));
  require(current.replace(0U, fragment, 1U, options, now + 1204s) == LocalContentResult::changed &&
      publish(now + 1204s).published == 2U && stored(now + 1204s)->header.sequence == 78U);
  require(current.withdraw(0U, fragment) == LocalContentResult::changed && publish(now + 1205s).published == 1U);
  require(current.require_after(0U, fragment, std::numeric_limits<std::uint32_t>::max(), now + 1206s));
  require(publish(now + 1206s, {}, 0U).terminal == GenerationStatus::waiting);
  require(current.replace(0U, fragment, 1U, options, now + 1207s) == LocalContentResult::changed &&
      publish(now + 1207s, {}, 0U).terminal == GenerationStatus::sequence_exhausted);

  // Withdrawal after actual lifetime expiration uses the old expiration
  // anchor and ZeroAgeLifetime, rather than restarting a MaxAge purge.
  InstanceUpdateProcess expired_update(local, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  program.records[1U].active = true;
  LocalLspSet expired(local, 3U, {InstanceFormat::standard, 0U}, program, now);
  std::size_t work{2U};
  require(expired.service(expired_update, {}, now, *scratch, observer, work).published == 2U);
  LspContents aged;
  aged.header = {PduType::lsp_l1, fragment, 2U, 2U, 1U};
  aged.options = options;
  aged.maximum_pdu_octets = 128U;
  const auto encoded = build_lsp_pdu(aged, scratch->options, scratch->pdu);
  require(encoded.status == LspBuildStatus::encoded && expired_update.originate(0U, encoded.bytes, now,
      OriginPurgeReason::none, observer).install == LspInstallResult::installed);
  require(expired.withdraw(0U, fragment) == LocalContentResult::changed);
  work = 2U;
  require(expired.service(expired_update, {}, now + 5s, *scratch, observer, work).published == 1U);
  const auto expired_deadline = expired_update.level(0U)->database().database().next_deadline(LspDeadlineKind::retire_purge);
  require(expired_deadline && expired_deadline->at == now + 62s);
}
