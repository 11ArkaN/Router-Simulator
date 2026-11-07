// Checkpoint fixtures preserve wire, fractional aging and purge retention
// across different host epochs. Refusal tests retain the destination's buffers
// and deadlines; every database and clock input belongs to this test owner.

#include "router/isis_lsdb.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace {
void require(bool value) {
  if (!value) throw std::runtime_error("IS-IS LSDB checkpoint invariant failed");
}
}
void isis_lsdb_checkpoint_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto start = RuntimeClock::time_point{100s};
  const auto captured = start + 2500ms;
  const auto resumed = RuntimeClock::time_point{1000s};
  const LsdbLimits limits{5U, 1024U, 128U};
  LinkStateDatabase source(PduType::lsp_l1, limits);
  std::array<std::uint8_t, 256U> wire{};
  LspInput input{PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 30U, 1U, 3U};
  const auto install = [&](LinkStateDatabase &database, std::uint8_t fragment, std::uint16_t life,
      RuntimeClock::time_point at, LspAdmissionOrigin origin = LspAdmissionOrigin::received) {
    input.id[7U] = fragment;
    input.remaining_seconds = life;
    const auto encoded = encode_lsp(wire, input, {});
    require(encoded && database.install(*encoded, at, 1200U, 60s, {origin}) == LspInstallResult::installed);
    return input.id;
  };
  const auto live = install(source, 0U, 30U, start);
  const auto unfinalized = install(source, 1U, 1U, start);
  const auto notified = install(source, 2U, 2U, start);
  const auto purged = install(source, 3U, 0U, start + 1s, LspAdmissionOrigin::originated);
  require(source.mark_expiration_notified(notified, captured));
  const auto saved = source.checkpoint(captured);
  require(saved.version == 1U && saved.records.size() == 4U && saved.records[0U].age_nanoseconds == 2'500'000'000LL &&
      saved.records[3U].retirement_nanoseconds == 58'500'000'000LL);
  LinkStateDatabase destination(PduType::lsp_l1, limits);
  const auto sentinel = install(destination, 9U, 30U, resumed);
  require(destination.restore(saved, resumed, 1200U) && destination.size() == 4U && !destination.find(sentinel, resumed));
  const auto copy = destination.checkpoint(resumed);
  for (std::size_t index{}; index < saved.records.size(); ++index) {
    const auto &before = saved.records[index], &after = copy.records[index];
    require(before.bytes == after.bytes && before.allocation == after.allocation &&
        before.age_nanoseconds == after.age_nanoseconds && before.retirement_nanoseconds == after.retirement_nanoseconds &&
        before.expiration_notified == after.expiration_notified);
  }
  require(destination.find(live, resumed)->header.remaining_seconds == 28U &&
      destination.find(live, resumed + 27499ms)->header.remaining_seconds == 1U &&
      destination.find(live, resumed + 27500ms)->header.remaining_seconds == 0U);
  require(destination.next_deadline()->id == unfinalized && destination.next_deadline()->at == resumed - 1500ms &&
      !destination.find(unfinalized, resumed)->expiration_notified && destination.find(notified, resumed)->expiration_notified);
  require(!destination.retire_purge(purged, resumed + 58499ms) && destination.retire_purge(purged, resumed + 58500ms));

  const auto *buffer = destination.find(live, resumed)->pdu.bytes.data();
  const auto allocation = destination.allocated_octets();
  const auto deadline = destination.next_deadline()->at;
  const auto refused = [&](const LsdbCheckpoint &invalid, RuntimeClock::time_point epoch = RuntimeClock::time_point{1000s},
      std::uint16_t maximum_age = 1200U) {
    require(!destination.restore(invalid, epoch, maximum_age) && destination.size() == 3U &&
        destination.allocated_octets() == allocation && destination.find(live, resumed)->pdu.bytes.data() == buffer &&
        destination.next_deadline()->at == deadline);
  };
  auto invalid = saved;
  invalid.version = 2U; refused(invalid);
  invalid = saved; invalid.type = PduType::lsp_l2; refused(invalid);
  invalid = saved; ++invalid.limits.records; refused(invalid);
  invalid = saved; std::swap(invalid.records[0U], invalid.records[1U]); refused(invalid);
  invalid = saved; invalid.records[1U] = invalid.records[0U]; refused(invalid);
  invalid = saved; invalid.records[0U].allocation = 1025U; refused(invalid);
  invalid = saved; invalid.records[0U].allocation = 0U; refused(invalid);
  invalid = saved; invalid.records[0U].bytes.back() ^= 1U; refused(invalid);
  invalid = saved; invalid.records[0U].bytes.push_back(0U); refused(invalid);
  invalid = saved; invalid.records[0U].age_nanoseconds = -1; refused(invalid);
  invalid = saved; invalid.records[0U].expiration_notified = true; refused(invalid);
  invalid = saved; invalid.records[3U].retirement_nanoseconds.reset(); refused(invalid);
  invalid = saved; invalid.records[3U].expiration_notified = true; refused(invalid);
  invalid = saved; invalid.records[3U].retirement_nanoseconds = 65'536'000'000'000LL; refused(invalid);
  refused(saved, resumed, 29U);
  refused(saved, RuntimeClock::time_point::min());
  refused(saved, RuntimeClock::time_point::max());
  invalid = saved; invalid.records.resize(1U); refused(invalid, RuntimeClock::time_point::max());
  bool bad_capture{};
  try { static_cast<void>(source.checkpoint(start - 1ns)); }
  catch (const std::invalid_argument &) { bad_capture = true; }
  require(bad_capture && source.size() == 4U);

  // A signed-epoch boundary cannot overflow lifetime arithmetic or silently
  // wrap a relative timestamp. Long-expired bodies stay expired after restore.
  const auto minimum = RuntimeClock::time_point::min(), maximum = RuntimeClock::time_point::max();
  require(!checkpoint_time::offset(maximum, minimum) && !checkpoint_time::offset(minimum, maximum));
  require(!checkpoint_time::restore(1, maximum) && !checkpoint_time::restore(-1, minimum));
  require(checkpoint_time::offset(minimum, RuntimeClock::time_point{}) == std::numeric_limits<std::int64_t>::min() &&
      checkpoint_time::restore(std::numeric_limits<std::int64_t>::min(), RuntimeClock::time_point{}) == minimum);
  auto ancient = saved;
  ancient.records.resize(1U);
  ancient.records[0U].age_nanoseconds = std::numeric_limits<std::int64_t>::max();
  require(destination.restore(ancient, RuntimeClock::time_point{}, 1200U) &&
      !destination.find(live, RuntimeClock::time_point{1ns})->header.remaining_seconds);
}
