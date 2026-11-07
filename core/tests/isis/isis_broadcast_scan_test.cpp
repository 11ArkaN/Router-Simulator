// Injected owner-local monotonic times exercise periodic LAN selection without
// physical success claims before a matching completion. No remote state enters.

#include "router/isis_broadcast_scan.hpp"
#include "router/isis_lsp_builder.hpp"

#include <memory>

#include <stdexcept>

namespace {
void require(bool value) {
  if (!value) throw std::runtime_error("IS-IS broadcast scan invariant failed");
}
}
void isis_broadcast_scan_tests() {
  using router::isis::BroadcastScan;
  using namespace std::chrono_literals;
  const auto start = BroadcastScan::Clock::time_point{100s};
  for (const auto interval : {0us, -1us, 65'535'001us}) {
    bool refused{};
    try { BroadcastScan invalid(interval, 1U, start); }
    catch (const std::invalid_argument &) { refused = true; }
    require(refused);
  }
  bool unseeded{};
  try { BroadcastScan invalid(100ms, 0U, start); }
  catch (const std::invalid_argument &) { unseeded = true; }
  require(unseeded);
  BroadcastScan scan(100ms, 123U, start);
  const auto first = scan.deadline(false);
  require(first >= start + 75ms && first <= start + 100ms);
  const auto random = scan.random_state();
  require(!scan.begin(first - 1us, 7U, false) && scan.random_state() == random && !scan.complete(true, first));
  require(!scan.begin(first, 0U, false) && scan.deadline(false) > first && scan.random_state() != random);
  auto due = scan.deadline(false);
  auto selected = scan.begin(due, 7U, true);
  require(selected && *selected < 7U && scan.deadline(true) == BroadcastScan::Clock::time_point::max());
  require(!scan.begin(due + 1s, 7U, false));
  require(scan.complete(false, due + 1s) && !scan.complete(true, due + 1s));
  // A failed queue admission must not count as the permitted backlog emission.
  due = scan.deadline(true);
  require(scan.begin(due, 1U, true) == 0U && scan.complete(true, due));
  require(scan.deadline(true) >= due + 1s && !scan.begin(due + 900ms, 1U, true));
  require(scan.begin(due + 1s, 1U, true) == 0U && scan.complete(true, due + 1s));
  require(scan.deadline(false) < scan.deadline(true));
  const auto normal = scan.deadline(false);
  require(scan.begin(normal, 1U, false) == 0U && scan.complete(true, normal));
  // Independent owners with the same saved seed and time reproduce selection.
  BroadcastScan left(100ms, 57U, start), right(100ms, 57U, start);
  for (unsigned turn{}; turn < 100U; ++turn) {
    require(left.deadline(false) == right.deadline(false));
    const auto at = left.deadline(false);
    require(left.begin(at, 11U, false) == right.begin(at, 11U, false) && left.random_state() == right.random_state());
    require(left.complete(true, at) && right.complete(true, at));
  }
  BroadcastScan reactivated(100ms, 79U, start);
  const auto activated = start + 5s;
  const auto before_activation = reactivated.random_state();
  require(reactivated.activate(activated) && reactivated.random_state() != before_activation);
  require(reactivated.deadline(false) >= activated + 75ms &&
      reactivated.deadline(false) <= activated + 100ms && !reactivated.begin(activated, 1U, false));
  const auto emitted = reactivated.deadline(false);
  require(reactivated.begin(emitted, 1U, true) == 0U);
  const auto reserved_random = reactivated.random_state();
  require(!reactivated.activate(emitted + 1ms) && reactivated.random_state() == reserved_random &&
      reactivated.deadline(false) == BroadcastScan::Clock::time_point::max());
  require(reactivated.complete(true, emitted) && reactivated.activate(emitted + 10ms));
  require(reactivated.deadline(false) > emitted + 10ms && reactivated.deadline(true) == emitted + 1s);
  require(!reactivated.begin(emitted + 900ms, 1U, true));
  require(reactivated.begin(emitted + 1s, 1U, true) == 0U && reactivated.complete(true, emitted + 1s));
  BroadcastScan boundary(100ms, 1U, BroadcastScan::Clock::time_point::max() - 1us);
  require(boundary.deadline(false) == BroadcastScan::Clock::time_point::max() &&
      !boundary.begin(BroadcastScan::Clock::time_point::max(), 1U, false));
  using namespace router::isis;
  using namespace router::packet::isis;
  const std::array circuits{FloodCircuit{true, true, false, false}};
  LevelDatabase l1(PduType::lsp_l1, {4U, 4096U}, circuits);
  LevelDatabase l2(PduType::lsp_l2, {4U, 4096U}, circuits);
  LevelDatabase p2p(PduType::lsp_l1, {4U, 4096U}, std::array{FloodCircuit{false, true, false, false}});
  auto scratch = std::make_unique<PduScratch>();
  const auto install = [&](LevelDatabase &database, std::uint8_t suffix) {
    LspContents contents;
    contents.header = {database.type(), {1U, 2U, 3U, 4U, 5U, suffix, 0U, 0U}, 1200U, 1U, 3U};
    contents.maximum_pdu_octets = 1492U;
    const auto built = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(built.status == LspBuildStatus::encoded &&
        database.originate(built.bytes, start, 1200U, 60s) == LspInstallResult::installed);
    return contents.header.id;
  };
  const auto first_id = install(l1, 1U), second_id = install(l1, 2U), third_id = install(l2, 3U);
  require(l1.broadcast_srm_count(0U) == 2U && l1.broadcast_srm_at(0U, 0U) == first_id &&
      l1.broadcast_srm_at(0U, 1U) == second_id && !l1.broadcast_srm_at(0U, 2U) &&
      !l1.broadcast_srm_count(1U) && !p2p.broadcast_srm_count(0U));
  auto missing = first_id;
  missing[5U] = 9U;
  require(l1.receive_snp_entry({100U, missing, 1U, 1U}, 0U, start).request_missing &&
      l1.size() == 3U && l1.broadcast_srm_count(0U) == 2U);
  BroadcastScan catalog(100ms, 85U, start);
  const auto saved_random = catalog.random_state();
  const auto saved_deadline = catalog.deadline(false);
  require(catalog.begin(saved_deadline, std::array{BroadcastLevel{&p2p, 0U}, BroadcastLevel{}}, false).status ==
      BroadcastScanStatus::invalid_catalog && catalog.random_state() == saved_random && catalog.deadline(false) == saved_deadline);
  require(catalog.begin(saved_deadline, std::array{BroadcastLevel{}, BroadcastLevel{&l1, 0U}}, false).status ==
      BroadcastScanStatus::invalid_catalog && catalog.random_state() == saved_random);
  require(catalog.begin(saved_deadline, std::array{BroadcastLevel{&l1, 1U}, BroadcastLevel{}}, false).status ==
      BroadcastScanStatus::invalid_catalog && catalog.random_state() == saved_random);
  const std::array levels{BroadcastLevel{&l1, 0U}, BroadcastLevel{&l2, 0U}};
  std::array<unsigned, 3U> seen{};
  for (unsigned turn{}; turn < 120U; ++turn) {
    const auto at = catalog.deadline(false);
    const auto chosen = catalog.begin(at, levels, false);
    require(chosen.status == BroadcastScanStatus::selected && chosen.candidate.has_value());
    const auto &candidate = *chosen.candidate;
    require((candidate.level == 0U && (candidate.id == first_id || candidate.id == second_id)) ||
        (candidate.level == 1U && candidate.id == third_id));
    ++seen[candidate.id[5U] - 1U];
    require(catalog.complete(true, at));
  }
  require(seen[0U] > 15U && seen[1U] > 15U && seen[2U] > 15U);
  require(l1.suppress_oversized(first_id, 0U) && l1.broadcast_srm_count(0U) == 1U &&
      l1.broadcast_srm_at(0U, 0U) == second_id);
  require(l1.circuit(0U, true, false, false) && l1.broadcast_srm_count(0U) == 0U && !l1.broadcast_srm_at(0U, 0U));

}
