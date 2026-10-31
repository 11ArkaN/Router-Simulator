// Same-owner fault injection verifies detection of in-memory corruption rather
// than malformed network input. Cursor tests mutate sorted LSDB storage between
// bounded visits, and effective zero lifetimes retain the ISO checksum exemption.

#include "router/isis_database_validation.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/isis_basic_tlvs.hpp"

#include <memory>
#include <stdexcept>

void isis_database_validation_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS database validation invariant failed");
  };
  const auto now = RuntimeClock::time_point{100s};
  LinkStateDatabase database(PduType::lsp_l1, {8U, 8192U});
  auto scratch = std::make_unique<PduScratch>();
  const std::array<std::uint8_t, 3U> options{129U, 1U, ipv4_nlpid};
  const auto id = [](std::uint8_t fragment) { return LspId{1U, 2U, 3U, 4U, 5U, 6U, 0U, fragment}; };
  const auto install = [&](std::uint8_t fragment, std::uint16_t life, RuntimeClock::time_point time) {
    LspContents content;
    content.header = {PduType::lsp_l1, id(fragment), life, 1U, 3U};
    content.options = options;
    content.maximum_pdu_octets = 1492U;
    const auto built = build_lsp_pdu(content, scratch->options, scratch->pdu);
    require(built.status == LspBuildStatus::encoded);
    require(database.install(built.bytes, time, 1200U, 0s) == LspInstallResult::installed);
  };
  for (const auto fragment : {2U, 4U, 6U}) install(static_cast<std::uint8_t>(fragment), 1200U, now);
  DatabaseValidation scan(10s, 17U, now);
  const auto due = *scan.deadline();
  require(due >= now + 7500ms && due <= now + 10s);
  std::size_t budget{1U};
  require(scan.service(database, due - 1us, budget).status == DatabaseValidationStatus::waiting && budget == 1U);
  const auto first = scan.service(database, due, budget);
  require(first.status == DatabaseValidationStatus::more && first.checked == 1U && !budget);
  install(1U, 1200U, due);
  install(4U, 0U, due);
  require(database.retire_purge(id(4U), due));
  // A borrowed const view cannot normally mutate repository bytes. This test
  // acts as a memory fault on the sole owner, with no concurrently held view.
  auto *fault = const_cast<std::uint8_t *>(database.find(id(6U), due)->pdu.bytes.data()) + lsp_header_octets + 2U;
  *fault ^= 1U;
  budget = 1U;
  const auto corrupt = scan.service(database, due, budget);
  require(corrupt.status == DatabaseValidationStatus::corrupted && corrupt.corrupted == id(6U) &&
      corrupt.checked == 1U && !scan.deadline());
  *fault ^= 1U;
  budget = 8U;
  require(scan.service(database, due + 100s, budget).status == DatabaseValidationStatus::corrupted && budget == 8U);
  DatabaseValidation healthy(10s, 19U, due);
  budget = 0U;
  require(healthy.service(database, due + 10s, budget).status == DatabaseValidationStatus::more);
  budget = 8U;
  const auto complete = healthy.service(database, due + 10s, budget);
  require(complete.status == DatabaseValidationStatus::complete && complete.checked == 3U && budget == 5U &&
      *healthy.deadline() >= due + 17500ms && *healthy.deadline() <= due + 20s);
  *fault ^= 1U;
  DatabaseValidation expired(10s, 23U, now + 1300s);
  budget = 8U;
  require(expired.service(database, now + 1310s, budget).status == DatabaseValidationStatus::complete);
  LinkStateDatabase empty(PduType::lsp_l2, {1U, 128U});
  DatabaseValidation empty_scan(1s, 29U, now);
  budget = 0U;
  require(empty_scan.service(empty, now + 1s, budget).status == DatabaseValidationStatus::complete);
  for (const auto interval : {0us, -1us}) {
    bool rejected{};
    try { DatabaseValidation invalid(interval, 1U, now); }
    catch (const std::invalid_argument &) { rejected = true; }
    require(rejected);
  }
  bool rejected{};
  try { DatabaseValidation invalid(1s, 0U, now); }
  catch (const std::invalid_argument &) { rejected = true; }
  require(rejected);
}
