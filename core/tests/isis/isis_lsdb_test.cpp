// LSDB tests own clocks and encoded advertisements. No simulated network clock
// or peer state is used. Capacity and recency failures preserve stored bytes.

#include "router/isis_lsdb.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_lsdb_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = RuntimeClock::time_point{} + 100s;
  LspView current{{}, 30U, 10U, 100U, 3U};
  auto candidate = current;
  candidate.remaining_seconds = 1U;
  require(compare_lsp_headers(candidate, current) == LspRecency::identical,
          "IS-IS lifetime difference incorrectly ranked identical LSPs");
  candidate.checksum = 101U;
  require(compare_lsp_headers(candidate, current) == LspRecency::confusion,
          "IS-IS checksum confusion was treated as a checksum tie-break");
  candidate.remaining_seconds = 0U;
  require(compare_lsp_headers(candidate, current) == LspRecency::newer &&
            compare_lsp_headers(current, candidate) == LspRecency::older,
          "IS-IS equal-sequence purge precedence failed");
  current.remaining_seconds = 0U;
  require(compare_lsp_headers(candidate, current) == LspRecency::identical,
          "IS-IS equal-sequence purges were not duplicates");
  candidate.sequence = 11U;
  require(compare_lsp_headers(candidate, current) == LspRecency::newer,
          "IS-IS unsigned sequence precedence failed");

  LspInput input{PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 1U}, 30U, 1U, 3U};
  std::array<std::uint8_t, 256U> first{};
  const std::array<std::uint8_t, 6U> option{135U, 4U, 1U, 2U, 3U, 4U};
  const auto first_wire = encode_lsp(first, input, option);
  require(first_wire.has_value(), "IS-IS LSDB fixture encoding failed");
  LinkStateDatabase database(PduType::lsp_l1, {1U, first_wire->size()});
  require(!database.next_deadline(), "Empty IS-IS database exposed a lifecycle deadline");
  require(database.install(*first_wire, now, 1200U, 60s) == LspInstallResult::installed &&
            database.size() == 1U, "IS-IS LSDB initial installation failed");
  const auto allocation = database.allocated_octets();
  require(database.next_deadline()->at == now + 30s &&
      database.next_deadline()->id == input.id && database.next_deadline()->kind == LspDeadlineKind::finalize_expiration,
      "IS-IS active LSP deadline did not require expiration finalization");
  auto retained = database.find(input.id, now + 1900ms);
  require(retained && retained->header.remaining_seconds == 29U &&
            retained->pdu.bytes.size() == first_wire->size(), "IS-IS LSDB lifetime projection failed");
  require(database.install(*first_wire, now + 2s, 1200U, 60s) == LspInstallResult::identical &&
            database.find(input.id, now + 3s)->header.remaining_seconds == 27U,
          "IS-IS duplicate receipt refreshed the lifetime");
  std::array<std::uint8_t, 256U> second{};
  auto other = input;
  other.id[7U] = 2U;
  auto wire = encode_lsp(second, other, {});
  require(wire && database.install(*wire, now, 1200U, 60s) == LspInstallResult::capacity_exhausted &&
            database.size() == 1U && !database.find(other.id, now),
          "IS-IS record capacity failure modified the LSDB");
  other = input;
  other.sequence = 2U;
  const std::array<std::uint8_t, 8U> larger{8U, 6U, 0U, 0U, 0U, 0U, 0U, 0U};
  wire = encode_lsp(second, other, larger);
  require(wire && database.install(*wire, now, 1200U, 60s) == LspInstallResult::capacity_exhausted &&
            database.find(input.id, now)->header.sequence == 1U && database.allocated_octets() == allocation,
          "IS-IS growing LSP failure lost its prior generation");
  wire = encode_lsp(second, other, {});
  require(wire && database.install(*wire, now + 4s, 1200U, 60s) == LspInstallResult::installed &&
            database.find(input.id, now + 4s)->header.sequence == 2U &&
            database.allocated_octets() == allocation,
          "IS-IS smaller replacement could not reuse a full allocation");
  require(database.install(*first_wire, now + 5s, 1200U, 60s) == LspInstallResult::older,
          "IS-IS older LSP replaced a newer generation");
  LinkStateDatabase reused(PduType::lsp_l1, {1U, first_wire->size()});
  require(reused.install(*first_wire, now, 1200U, 60s) == LspInstallResult::installed &&
            reused.install(*wire, now, 1200U, 60s) == LspInstallResult::installed,
          "IS-IS retained-capacity fixture failed");
  auto grown = input;
  grown.sequence = 3U;
  std::array<std::uint8_t, 256U> grown_bytes{};
  const auto grown_wire = encode_lsp(grown_bytes, grown, option);
  require(grown_wire && reused.install(*grown_wire, now, 1200U, 60s) == LspInstallResult::installed &&
            std::ranges::equal(reused.find(input.id, now)->pdu.bytes, *grown_wire),
          "IS-IS retained-capacity growth corrupted the accepted PDU suffix");
  other.flags ^= 4U;
  wire = encode_lsp(second, other, {});
  require(wire && database.install(*wire, now + 5s, 1200U, 60s) == LspInstallResult::confusion &&
            database.find(input.id, now + 5s)->header.flags == input.flags,
          "IS-IS confusion silently overwrote the LSDB");
  require(!database.retire_purge(input.id, now + 100s) &&
            database.find(input.id, now + 100s)->header.remaining_seconds == 0U,
          "IS-IS aged active LSP retired before purge construction");
  require(database.next_deadline()->at == now + 34s &&
      database.next_deadline()->kind == LspDeadlineKind::finalize_expiration,
      "IS-IS expired body lost its pending purge obligation");
  other.remaining_seconds = 0U;
  wire = encode_lsp(second, other, {});
  require(wire && database.install(*wire, now + 40s, 1200U, 60s) == LspInstallResult::installed &&
            database.find(input.id, now + 40s)->purge_installed,
          "IS-IS expired active body did not transition to an installed purge");
  require(database.next_deadline()->at == now + 94s &&
      database.next_deadline()->kind == LspDeadlineKind::retire_purge,
      "IS-IS retention deadline was measured from delayed purge construction");
  require(!database.retire_purge(input.id, now + 93s) &&
            database.retire_purge(input.id, now + 94s) && database.size() == 0U &&
            database.allocated_octets() == 0U,
          "IS-IS purge retention did not start at its actual expiration");
  require(database.install(*wire, now + 95s, 1200U, 60s) == LspInstallResult::unknown_purge &&
            database.size() == 0U, "IS-IS retained an unknown received purge");
  other.remaining_seconds = 1201U;
  wire = encode_lsp(second, other, {});
  require(wire && database.install(*wire, now, 1200U, 60s) == LspInstallResult::excessive_lifetime,
          "IS-IS accepted lifetime above MaxAge");
  other.remaining_seconds = 30U;
  wire = encode_lsp(second, other, {});
  second[26U] ^= 4U;
  require(wire && database.install(*wire, now, 1200U, 60s) == LspInstallResult::invalid_checksum,
          "IS-IS accepted an active LSP with invalid checksum");
  second[24U] = 0U;
  second[25U] = 0U;
  require(database.install(*wire, now, 1200U, 60s) == LspInstallResult::unknown_purge,
          "IS-IS zero checksum did not invoke expiration semantics");
  LinkStateDatabase ordered(PduType::lsp_l1, {3U, 256U});
  for (const auto fragment : {3U, 1U, 2U}) {
    other.id[7U] = static_cast<std::uint8_t>(fragment);
    wire = encode_lsp(second, other, {});
    require(wire && ordered.install(*wire, now, 1200U, 60s) == LspInstallResult::installed,
            "IS-IS ordered LSDB fixture failed");
  }
  require(ordered.at(0U, now)->header.id[7U] == 1U && ordered.at(2U, now)->header.id[7U] == 3U &&
            !ordered.at(3U, now), "IS-IS LSDB iteration is not LSP-ID ordered");
  require(ordered.next_deadline()->id[7U] == 1U && ordered.next_deadline()->at == now + 30s,
      "IS-IS equal lifecycle deadlines were not ordered by LSP ID");
  other.id[7U] = 3U;
  ++other.sequence;
  other.remaining_seconds = 1U;
  wire = encode_lsp(second, other, {});
  require(wire && ordered.install(*wire, now, 1200U, 60s) == LspInstallResult::installed &&
      ordered.next_deadline()->id == other.id && ordered.next_deadline()->at == now + 1s,
      "IS-IS earliest expiration was hidden by LSP ID ordering");
  LinkStateDatabase boundary(PduType::lsp_l1, {1U, 256U});
  const auto near_end = RuntimeClock::time_point::max() - 500ms;
  require(boundary.install(*wire, near_end, 1200U, 60s) == LspInstallResult::installed &&
      boundary.next_deadline()->at == RuntimeClock::time_point::max(),
      "IS-IS expiration deadline overflowed the monotonic clock");
  other.remaining_seconds = 0U;
  wire = encode_lsp(second, other, {});
  require(wire && boundary.install(*wire, near_end, 1200U, 60s) == LspInstallResult::installed &&
      boundary.next_deadline()->kind == LspDeadlineKind::retire_purge &&
      boundary.next_deadline()->at == RuntimeClock::time_point::max() &&
      !boundary.retire_purge(other.id, near_end) &&
      boundary.retire_purge(other.id, RuntimeClock::time_point::max()) && !boundary.next_deadline(),
      "IS-IS saturated purge retention wrapped or retained an empty deadline");
  unsigned admission_calls{};
  const LspAdmission refusing{LspAdmissionOrigin::received, &admission_calls,
      +[](void *opaque, const LspView &) noexcept { ++*static_cast<unsigned *>(opaque); return false; }};
  LinkStateDatabase guarded(PduType::lsp_l1, {2U, 256U});
  other = input;
  wire = encode_lsp(second, other, option);
  require(wire && guarded.install(*wire, now, 1200U, 60s, refusing) == LspInstallResult::capacity_exhausted &&
      admission_calls == 1U && guarded.size() == 0U && !guarded.allocated_octets(),
      "IS-IS metadata reservation failure published retained bytes");
  require(guarded.install(*wire, now, 1200U, 60s) == LspInstallResult::installed,
      "IS-IS admission callback fixture could not establish its retained identity");
  ++other.sequence;
  wire = encode_lsp(second, other, {});
  require(wire && guarded.install(*wire, now, 1200U, 60s, refusing) == LspInstallResult::installed &&
      admission_calls == 1U && guarded.find(other.id, now)->header.sequence == other.sequence,
      "IS-IS reusable replacement depended on new metadata capacity");
  LinkStateDatabase local_storage(PduType::lsp_l1, {2U, 155U});
  other = input;
  wire = encode_lsp(second, other, {});
  require(wire && local_storage.install(*wire, now, 1200U, 60s,
      {LspAdmissionOrigin::originated, nullptr, nullptr, 128U}) == LspInstallResult::installed &&
      local_storage.allocated_octets() == 128U,
      "IS-IS local root storage was not reserved before foreign admission");
  const auto root_id = other.id;
  const auto *root_buffer = local_storage.find(root_id, now)->pdu.bytes.data();
  other.id.back() = static_cast<std::uint8_t>(other.id.back() + 1U);
  wire = encode_lsp(second, other, {});
  require(wire && local_storage.install(*wire, now, 1200U, 60s) == LspInstallResult::installed &&
      local_storage.allocated_octets() == 155U,
      "IS-IS full-budget local reserve fixture did not admit foreign content");
  other.id = root_id;
  ++other.sequence;
  const std::array<std::uint8_t, 101U> padding{8U, 99U};
  wire = encode_lsp(second, other, padding);
  require(wire && wire->size() == 128U && local_storage.install(*wire, now, 1200U, 60s,
      {LspAdmissionOrigin::originated}) == LspInstallResult::installed &&
      local_storage.find(root_id, now)->pdu.bytes.data() == root_buffer && local_storage.allocated_octets() == 155U,
      "IS-IS local root growth lost its reservation at a full database budget");
  require(local_storage.install(*wire, now, 1200U, 60s,
      {LspAdmissionOrigin::received, nullptr, nullptr, 128U}) == LspInstallResult::malformed &&
      local_storage.install(*wire, now, 1200U, 60s,
      {LspAdmissionOrigin::originated, nullptr, nullptr, 65536U}) == LspInstallResult::malformed,
      "IS-IS local storage reservation accepted a foreign or out-of-wire request");
  other.remaining_seconds = 0U;
  wire = encode_lsp(second, other, {});
  const auto observed_live = now + std::chrono::seconds{input.remaining_seconds} + 20s;
  require(wire && local_storage.install(*wire, observed_live, 1200U, 1200s,
      {LspAdmissionOrigin::originated, nullptr, nullptr, 0U, LspPurgeAnchor::current_event}) == LspInstallResult::installed &&
      local_storage.next_deadline(LspDeadlineKind::retire_purge)->at == observed_live + 1200s &&
      !local_storage.retire_purge(root_id, observed_live + 1199s) &&
      local_storage.retire_purge(root_id, observed_live + 1200s),
      "IS-IS initiated purge reused an older expiration anchor for a newly observed live incarnation");
  require(local_storage.install(*wire, now, 1200U, 60s,
      {LspAdmissionOrigin::received, nullptr, nullptr, 0U, LspPurgeAnchor::current_event}) == LspInstallResult::malformed,
      "IS-IS received input selected a local purge event anchor");
}
