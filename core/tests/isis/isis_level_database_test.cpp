// The level owner admits retained flags before LSDB mutation and applies only
// matching egress receipts. All advertisements enter as encoded local bytes.

#include "router/isis_level_database.hpp"

#include <array>
#include <stdexcept>

void isis_level_database_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS level database ownership invariant failed");
  };
  const std::array circuits{FloodCircuit{false, true, false, false},
                            FloodCircuit{true, true, false, false}};
  LevelDatabase level(PduType::lsp_l1, {1U, 1024U}, circuits);
  std::array<std::uint8_t, 128U> bytes{};
  LspInput input{PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U};
  auto wire = encode_lsp(bytes, input, {});
  require(wire.has_value());
  const auto now = RuntimeClock::time_point{100s};
  auto result = level.receive(*wire, 0U, now, 1200U, 60s);
  require(result.install == LspInstallResult::installed && result.flooding.accepted &&
      level.database().size() == 1U && level.flags(input.id, 0U)->ssn && level.flags(input.id, 1U)->srm);
  const auto old = level.database().find(input.id, now)->header;
  require(level.complete(old, 1U, false, false, now) && level.flags(input.id, 1U)->srm);
  input.sequence = 2U;
  wire = encode_lsp(bytes, input, {});
  require(wire && level.receive(*wire, 0U, now, 1200U, 60s).install == LspInstallResult::installed);
  require(!level.complete(old, 1U, false, true, now) && level.flags(input.id, 1U)->srm);
  const auto current = level.database().find(input.id, now)->header;
  require(level.complete(current, 1U, false, true, now) && !level.flags(input.id, 1U)->srm);
  require(level.complete(current, 0U, true, false, now) && level.flags(input.id, 0U)->ssn);
  require(level.complete(current, 0U, true, true, now) && !level.flags(input.id, 0U)->ssn);
  input.id[0U] = 9U;
  wire = encode_lsp(bytes, input, {});
  result = level.receive(*wire, 0U, now, 1200U, 60s);
  require(result.install == LspInstallResult::capacity_exhausted && result.flooding.waiting_state &&
      !result.flooding.accepted && !level.flags(input.id, 0U) && level.database().size() == 1U);
  input.remaining_seconds = 0U;
  wire = encode_lsp(bytes, input, {});
  result = level.receive(*wire, 0U, now, 1200U, 60s);
  require(result.install == LspInstallResult::unknown_purge && result.flooding.transient_acknowledgement &&
      result.transient_acknowledgement && result.transient_acknowledgement->id == input.id &&
      !result.transient_acknowledgement->remaining_seconds &&
      level.database().size() == 1U && !level.flags(input.id, 0U));
  auto zero_checksum = input;
  zero_checksum.remaining_seconds = 1200U;
  const auto zero_wire = encode_lsp(bytes, zero_checksum, {});
  require(zero_wire.has_value());
  bytes[lsp_checksum_offset] = bytes[lsp_checksum_offset + 1U] = 0U;
  result = level.receive(*zero_wire, 0U, now, 1200U, 60s);
  require(result.install == LspInstallResult::unknown_purge && result.transient_acknowledgement &&
      !result.transient_acknowledgement->remaining_seconds && !result.transient_acknowledgement->checksum);
  require(!level.complete(current, 9U, false, true, now));
  level.omitted(current.id, 1U, current.id, current.id, now);
  require(level.flags(current.id, 1U)->srm);
  auto report = SnpEntry{current.remaining_seconds, current.id, current.sequence, current.checksum};
  require(!level.receive_snp_entry(report, 1U, now).confusion && level.flags(current.id, 1U)->srm);
  report.sequence += 1U;
  require(!level.receive_snp_entry(report, 0U, now).confusion && level.flags(current.id, 0U)->ssn);
  report.id = input.id;
  require(level.receive_snp_entry(report, 0U, now).waiting_state && !level.flags(input.id, 0U));
  require(!level.retire_purge(current.id, now + 2000s));
  input.id = current.id;
  input.sequence = current.sequence;
  wire = encode_lsp(bytes, input, {});
  require(wire && level.receive(*wire, 0U, now, 1200U, 60s).install == LspInstallResult::installed);
  require(!level.retire_purge(current.id, now + 59s) && level.retire_purge(current.id, now + 60s) &&
      level.database().size() == 0U && !level.flags(current.id, 0U));
  input.remaining_seconds = 1200U;
  input.sequence += 1U;
  wire = encode_lsp(bytes, input, {});
  require(wire && level.originate(*wire, now, 1200U, 60s) == LspInstallResult::installed &&
      level.flags(input.id, 0U)->srm && level.flags(input.id, 1U)->srm);
  require(!level.circuit(0U, true, true, false) && level.circuit(0U, false, false, false) &&
      !level.flags(input.id, 0U)->srm && !level.flags(input.id, 0U)->ssn);
  require(level.circuit(0U, false, true, true) && level.flags(input.id, 0U)->srm);
  report = {input.remaining_seconds, input.id, input.sequence, level.database().find(input.id, now)->header.checksum};
  require(!level.receive_snp_entry(report, 0U, now).confusion && !level.flags(input.id, 0U)->srm);
  LevelDatabase requests(PduType::lsp_l1, {2U, 1024U}, circuits);
  require(requests.receive_snp_entry(report, 0U, now).request_missing &&
      requests.size() == 1U && requests.database().size() == 0U &&
      requests.flags(report.id, 0U)->ssn && !requests.flags(report.id, 0U)->srm);
  const auto request = requests.snp_entry(report.id, now);
  require(request && !request->sequence && !request->checksum && !request->remaining_seconds &&
      requests.snp_entry_at(0U, now) == request && !requests.snp_entry_at(1U, now));
  require(requests.circuit(0U, false, true, true) && !requests.flags(report.id, 0U)->srm);
  const LspView request_receipt{report.id, 0U, 0U, 0U, 0U};
  require(!requests.complete(request_receipt, 0U, false, true, now) &&
      requests.complete(request_receipt, 0U, true, false, now) && requests.flags(report.id, 0U)->ssn);
  require(requests.complete(request_receipt, 0U, true, true, now) && !requests.flags(report.id, 0U)->ssn);
  require(requests.receive_snp_entry(report, 0U, now).request_missing && requests.flags(report.id, 0U)->ssn);
  require(wire && requests.receive(*wire, 0U, now, 1200U, 60s).install == LspInstallResult::installed &&
      requests.size() == 1U && requests.database().size() == 1U &&
      requests.snp_entry(report.id, now)->sequence == input.sequence &&
      !requests.complete(request_receipt, 0U, true, true, now));
  auto missing = report;
  missing.id[0U] = 0xffU;
  require(requests.receive_snp_entry(missing, 1U, now).request_missing &&
      requests.flags(missing.id, 1U)->ssn && !requests.flags(missing.id, 1U)->srm);
  missing.id[0U] = 0xfeU;
  require(requests.receive_snp_entry(missing, 1U, now).waiting_state && !requests.flags(missing.id, 1U));
  require(requests.circuit(1U, true, false, false) &&
      !requests.flags(requests.snp_entry_at(1U, now)->id, 1U)->ssn);
  LevelDatabase scan(PduType::lsp_l1, {3U, 1024U}, circuits);
  std::array<LspId, 3U> ids{};
  for (std::uint8_t index{}; index < ids.size(); ++index) {
    auto announced = report;
    announced.id[0U] = static_cast<std::uint8_t>(index + 1U);
    ids[index] = announced.id;
    require(scan.receive_snp_entry(announced, 0U, now).request_missing);
  }
  std::array<SnpEntry, 1U> single{};
  auto selected = scan.partial_snp(0U, std::nullopt, single, now);
  require(selected.count == 1U && selected.cursor == ids[0U] && single[0U].id == ids[0U]);
  selected = scan.partial_snp(0U, selected.cursor, single, now);
  require(selected.count == 1U && selected.cursor == ids[1U] && single[0U].id == ids[1U]);
  selected = scan.partial_snp(0U, selected.cursor, single, now);
  require(selected.count == 1U && selected.cursor == ids[2U] && single[0U].id == ids[2U]);
  std::array<SnpEntry, 2U> wrapped{};
  selected = scan.partial_snp(0U, ids[1U], wrapped, now);
  require(selected.count == 2U && selected.cursor == ids[0U] &&
      wrapped[0U].id == ids[0U] && wrapped[1U].id == ids[2U] && scan.flags(ids[0U], 0U)->ssn);
  require(scan.partial_snp(9U, std::nullopt, wrapped, now).count == 0U);
}
