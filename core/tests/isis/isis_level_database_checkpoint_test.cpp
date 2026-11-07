// Flooding snapshots preserve real LSPs and zero-sequence requests together.
// Same-owner tests exercise resumed receipts and whole-level atomic refusal,
// including failures found only after all flag vectors have been staged.

#include "router/isis_level_database.hpp"

#include <array>
#include <source_location>
#include <stdexcept>
#include <string>

namespace {
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS flood checkpoint invariant failed at " + std::to_string(at.line()));
}
bool equal_flags(const router::isis::FloodCircuit &a, const router::isis::FloodCircuit &b) {
  return a.broadcast == b.broadcast && a.eligible == b.eligible && a.srm == b.srm && a.ssn == b.ssn;
}
}
void isis_level_database_checkpoint_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto start = RuntimeClock::time_point{100s}, resumed = RuntimeClock::time_point{1000s};
  const std::array scopes{FloodCircuit{false, true}, FloodCircuit{true, true}, FloodCircuit{false, false}};
  LevelDatabase source(PduType::lsp_l1, {4U, 1024U, 128U}, scopes, 5U);
  require(source.admit_circuit(true) == 3U);
  std::array<std::uint8_t, 128U> bytes{};
  LspInput input{PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U};
  const auto first = input.id;
  auto encoded = encode_lsp(bytes, input, {});
  require(encoded && source.receive(*encoded, 0U, start, 1200U, 60s).install == LspInstallResult::installed);
  input.id[7U] = 1U;
  const auto second = input.id;
  encoded = encode_lsp(bytes, input, {});
  require(encoded && source.originate(*encoded, start, 1200U, 60s) == LspInstallResult::installed);
  const auto second_header = source.database().find(second, start)->header;
  require(source.complete(second_header, 1U, false, true, start));
  require(!source.receive_snp_entry({1200U, second, 2U, second_header.checksum}, 0U, start).waiting_state);
  auto missing = second;
  missing[7U] = 2U;
  require(source.receive_snp_entry({1200U, missing, 3U, 7U}, 1U, start).request_missing &&
      source.circuit(2U, false, true, true));
  const auto saved = source.checkpoint(start + 500ms);
  require(saved.records.size() == 3U && saved.database.records.size() == 2U &&
      saved.records[2U].placeholder && saved.circuits.size() == 4U);
  const std::array cold{FloodCircuit{false, false}, FloodCircuit{true, false},
      FloodCircuit{false, false}, FloodCircuit{true, false}};
  LevelDatabase destination(PduType::lsp_l1, {4U, 1024U, 128U}, cold, 5U);
  require(destination.restore(saved, resumed, 1200U) && destination.size() == 3U &&
      destination.database().size() == 2U && !destination.database().find(missing, resumed));
  for (const auto &record : saved.records) for (std::size_t index{}; index < cold.size(); ++index)
    require(equal_flags(*destination.flags(record.id, index), record.circuits[index]));
  require(destination.snp_entry(missing, resumed)->sequence == 0U && destination.broadcast_srm_count(1U) == 1U);
  const auto first_header = destination.database().find(first, resumed)->header;
  require(destination.complete(first_header, 0U, true, true, resumed) && !destination.flags(first, 0U)->ssn);
  require(destination.complete({missing, 0U, 0U, 0U, 0U}, 1U, true, true, resumed) &&
      !destination.flags(missing, 1U)->ssn && destination.size() == 3U);
  require(destination.complete(second_header, 2U, false, true, resumed) && destination.flags(second, 2U)->srm);
  std::array<SnpEntry, 4U> pending{};
  require(!destination.partial_snp(1U, std::nullopt, pending, resumed).count);

  const auto before = destination.checkpoint(resumed);
  const auto *buffer = destination.database().find(first, resumed)->pdu.bytes.data();
  const auto refused = [&](const LevelDatabaseCheckpoint &invalid) {
    require(!destination.restore(invalid, resumed, 1200U) && destination.database().find(first, resumed)->pdu.bytes.data() == buffer);
    const auto after = destination.checkpoint(resumed);
    require(after.records.size() == before.records.size() && after.circuits.size() == before.circuits.size() &&
        after.database.records.size() == before.database.records.size());
    for (std::size_t index{}; index < before.circuits.size(); ++index)
      require(equal_flags(after.circuits[index], before.circuits[index]));
    for (std::size_t index{}; index < before.records.size(); ++index) {
      require(after.records[index].id == before.records[index].id &&
          after.records[index].placeholder == before.records[index].placeholder);
      for (std::size_t circuit{}; circuit < before.circuits.size(); ++circuit)
        require(equal_flags(after.records[index].circuits[circuit], before.records[index].circuits[circuit]));
    }
    for (std::size_t index{}; index < before.database.records.size(); ++index)
      require(after.database.records[index].bytes == before.database.records[index].bytes &&
          after.database.records[index].age_nanoseconds == before.database.records[index].age_nanoseconds);
  };
  auto invalid = saved;
  invalid.version = 2U; refused(invalid);
  invalid = saved; ++invalid.maximum_circuits; refused(invalid);
  invalid = saved; invalid.circuits.pop_back(); refused(invalid);
  invalid = saved; invalid.circuits[0U].srm = true; refused(invalid);
  invalid = saved; invalid.circuits[0U].broadcast = true; refused(invalid);
  invalid = saved; invalid.records[0U].circuits.pop_back(); refused(invalid);
  invalid = saved; invalid.records[0U].circuits[0U].broadcast = true; refused(invalid);
  invalid = saved; invalid.records[0U].circuits[0U].eligible = false; refused(invalid);
  invalid = saved; invalid.records[0U].circuits[3U].srm = true; refused(invalid);
  invalid = saved; invalid.records[2U].circuits[1U].srm = true; refused(invalid);
  invalid = saved; invalid.records[2U].placeholder = false; refused(invalid);
  invalid = saved; invalid.records[0U].placeholder = true; refused(invalid);
  invalid = saved; invalid.records[1U].id = invalid.records[0U].id; refused(invalid);
  invalid = saved; invalid.records.erase(invalid.records.begin()); refused(invalid);
  invalid = saved; invalid.database.records.pop_back(); refused(invalid);
  invalid = saved; invalid.database.records[0U].bytes.back() ^= 1U; refused(invalid);
  invalid = saved; invalid.database.limits.allocated_pdu_octets = 1025U; refused(invalid);
  invalid = saved; invalid.database.records[0U].age_nanoseconds = -1; refused(invalid);
  require(destination.admit_circuit(false) == 4U && !destination.circuit_capacity_available() &&
      destination.flags(missing, 4U) && !destination.flags(missing, 4U)->ssn);
}
