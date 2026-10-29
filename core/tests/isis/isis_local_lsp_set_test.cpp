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
  program.current = {{0U, root, 3U, area}, {1U, root, 3U, area}};
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
  auto missing = root;
  missing.back() = 1U;
  require(!current.contains(0U, missing) && !current.require_after(0U, missing, 9U, now) &&
      !current.last_error(0U, missing) &&
      current.replace(0U, missing, 3U, area, now) == LocalContentResult::missing);
  const std::array<std::uint8_t, 2U> poi{13U, 0U};
  require(current.replace(0U, root, 3U, poi, now) == LocalContentResult::invalid);
  const std::array<std::uint8_t, 104U> too_large{8U, 102U};
  require(current.replace(0U, root, 3U, too_large, now) == LocalContentResult::capacity);
  require(current.require_after(0U, root, std::numeric_limits<std::uint32_t>::max(), now + 4s));
  const auto exhausted = publish(now + 4s);
  require(exhausted.terminal == GenerationStatus::sequence_exhausted && !exhausted.deadline &&
      !publish(now + 100s).published && stored(0U)->header.sequence == 102U);
}
