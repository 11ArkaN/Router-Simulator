// Local fragment transactions stage distinct encoded bodies before one LSDB
// commit. Capacity, recency and metadata refusals must retain every old record,
// including wire addresses, allocation reservations and purge deadlines.

#include "router/isis_lsdb.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <string>

namespace {
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS origin batch invariant at " + std::to_string(where.line()));
}
std::vector<std::uint8_t> wire(std::uint8_t fragment, std::uint32_t sequence,
    std::uint16_t lifetime = 1200U, std::size_t option_size = 8U) {
  std::vector<std::uint8_t> options(option_size + 2U, 0x35U);
  options[0U] = 250U;
  options[1U] = static_cast<std::uint8_t>(option_size);
  std::vector<std::uint8_t> bytes(lsp_header_octets + options.size());
  const auto encoded = encode_lsp(bytes, {PduType::lsp_l1,
      {1U, 2U, 3U, 4U, 5U, 6U, 0U, fragment}, lifetime, sequence, 3U}, options);
  require(encoded.has_value());
  return bytes;
}
}

void isis_lsdb_batch_tests() {
  const auto now = RuntimeClock::time_point{100s};
  LinkStateDatabase database(PduType::lsp_l1, {4U, 512U, 64U});
  require(!database.reserve_origin_batch(std::numeric_limits<std::size_t>::max()));
  auto first = wire(0U, 1U), second = wire(1U, 1U);
  std::array requests{LspInstallRequest{first, 1200U, 60s}, LspInstallRequest{second, 1200U, 60s}};
  require(database.install_origin_batch(requests, now) == LspInstallResult::capacity_exhausted && !database.size());
  require(database.reserve_origin_batch(requests.size()));
  require(database.install_origin_batch({}, now) == LspInstallResult::malformed);
  auto duplicate = requests;
  duplicate[1U].wire = first;
  require(database.install_origin_batch(duplicate, now) == LspInstallResult::malformed && !database.size());
  require(database.install_origin_batch(requests, now) == LspInstallResult::installed && database.size() == 2U);
  const auto before = database.checkpoint(now);
  const auto old_first = database.at(0U, now), old_second = database.at(1U, now);
  require(old_first && old_second && database.allocated_octets() == 128U);
  const auto preserved = [&] {
    const auto copy = database.checkpoint(now);
    require(copy.records.size() == before.records.size() && database.allocated_octets() == 128U);
    for (std::size_t index{}; index < copy.records.size(); ++index)
      require(copy.records[index].bytes == before.records[index].bytes &&
          copy.records[index].allocation == before.records[index].allocation &&
          copy.records[index].age_nanoseconds == before.records[index].age_nanoseconds &&
          copy.records[index].retirement_nanoseconds == before.records[index].retirement_nanoseconds);
    require(database.at(0U, now)->pdu.bytes.data() == old_first->pdu.bytes.data() &&
        database.at(1U, now)->pdu.bytes.data() == old_second->pdu.bytes.data());
  };
  require(database.install_origin_batch(requests, now) == LspInstallResult::identical);
  preserved();
  auto next_first = wire(0U, 2U), next_second = wire(1U, 2U);
  requests[0U].wire = next_first; requests[1U].wire = next_second;
  auto malformed = requests;
  malformed[1U].wire = std::span{next_second}.first(4U);
  require(database.install_origin_batch(malformed, now) == LspInstallResult::malformed);
  preserved();
  auto received = requests;
  received[1U].admission.origin = LspAdmissionOrigin::received;
  require(database.install_origin_batch(received, now) == LspInstallResult::malformed);
  preserved();
  auto corrupt = next_second;
  corrupt.back() ^= 1U;
  auto checksum = requests; checksum[1U].wire = corrupt;
  require(database.install_origin_batch(checksum, now) == LspInstallResult::invalid_checksum);
  preserved();
  auto confused = wire(1U, 1U, 1200U, 9U);
  auto rejected = requests; rejected[1U].wire = confused;
  require(database.install_origin_batch(rejected, now) == LspInstallResult::confusion);
  preserved();
  auto huge_first = wire(0U, 2U, 1200U, 240U), huge_second = wire(1U, 2U, 1200U, 240U);
  auto oversized = requests; oversized[0U].wire = huge_first; oversized[1U].wire = huge_second;
  require(database.install_origin_batch(oversized, now) == LspInstallResult::capacity_exhausted);
  preserved();
  require(database.install_origin_batch(requests, now + 1s) == LspInstallResult::installed &&
      database.at(0U, now + 1s)->header.sequence == 2U && database.at(1U, now + 1s)->header.sequence == 2U &&
      database.at(0U, now + 1s)->pdu.bytes.data() == old_first->pdu.bytes.data() &&
      database.at(1U, now + 1s)->pdu.bytes.data() == old_second->pdu.bytes.data());
  auto third = wire(0U, 3U);
  auto stale = requests; stale[0U].wire = third; stale[1U].wire = second;
  require(database.install_origin_batch(stale, now + 1s) == LspInstallResult::older &&
      database.at(0U, now + 1s)->header.sequence == 2U && database.at(1U, now + 1s)->header.sequence == 2U);
  // Final retained budget includes unchanged reusable reservations; request
  // order cannot make an oversized transaction appear admissible.
  LinkStateDatabase balanced(PduType::lsp_l1, {2U, 180U});
  require(balanced.reserve_origin_batch(2U));
  auto large = wire(0U, 1U, 1200U, 100U), small = wire(1U, 1U, 1200U, 1U);
  std::array initial{LspInstallRequest{large, 1200U, 60s}, LspInstallRequest{small, 1200U, 60s}};
  require(balanced.install_origin_batch(initial, now) == LspInstallResult::installed);
  // Reuse retains the larger reservation, so replacing it with fewer bytes
  // does not pretend to release storage to another LSP.
  auto shrunk = wire(0U, 2U, 1200U, 1U), grown = wire(1U, 2U, 1200U, 100U);
  std::array replacement{LspInstallRequest{grown, 1200U, 60s}, LspInstallRequest{shrunk, 1200U, 60s}};
  require(balanced.install_origin_batch(replacement, now) == LspInstallResult::capacity_exhausted);
  require(balanced.at(0U, now)->header.sequence == 1U && balanced.at(1U, now)->header.sequence == 1U);
  LinkStateDatabase fresh(PduType::lsp_l1, {3U, 512U});
  require(fresh.reserve_origin_batch(2U));
  std::size_t reservations{};
  for (auto &request : requests) {
    request.admission.context = &reservations;
    request.admission.reserve_metadata = +[](void *context, const LspView &) noexcept {
      return ++*static_cast<std::size_t *>(context) < 2U;
    };
  }
  require(fresh.install_origin_batch(requests, now) == LspInstallResult::capacity_exhausted &&
      reservations == 2U && !fresh.size() && !fresh.allocated_octets());
}
