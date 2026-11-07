// A level owner snapshots LSDB bytes and their per-circuit flood obligations.
// Metadata is staged and cross-checked before the nested repository commits;
// no callback or other shard can observe a partially restored owner generation.

#include "router/isis_level_database.hpp"

#include <new>
#include <stdexcept>

namespace router::isis {
LevelDatabaseCheckpoint LevelDatabase::checkpoint(RuntimeClock::time_point now) const {
  LevelDatabaseCheckpoint result{1U, database_.checkpoint(now), maximum_circuits_, circuits_, {}};
  result.records.reserve(records_.size());
  for (const auto &record : records_) result.records.push_back({record.id, record.circuits, record.placeholder});
  return result;
}

bool LevelDatabase::restore(const LevelDatabaseCheckpoint &saved, RuntimeClock::time_point now,
    std::uint16_t maximum_age) noexcept {
  if (saved.version != 1U || saved.maximum_circuits != maximum_circuits_ ||
      saved.circuits.size() != circuits_.size() || saved.records.size() > maximum_records_ ||
      saved.database.records.size() > saved.records.size()) return false;
  for (std::size_t index{}; index < saved.circuits.size(); ++index)
    if (saved.circuits[index].srm || saved.circuits[index].ssn ||
        saved.circuits[index].broadcast != circuits_[index].broadcast) return false;
  try {
    auto circuits = saved.circuits;
    std::vector<Record> records;
    records.reserve(maximum_records_);
    std::size_t retained{};
    for (const auto &entry : saved.records) {
      if ((!records.empty() && records.back().id >= entry.id) || entry.circuits.size() != circuits.size()) return false;
      for (std::size_t index{}; index < circuits.size(); ++index) {
        const auto &flags = entry.circuits[index], &scope = circuits[index];
        if (flags.broadcast != scope.broadcast || flags.eligible != scope.eligible ||
            (!flags.eligible && (flags.srm || flags.ssn)) || (entry.placeholder && flags.srm)) return false;
      }
      if (!entry.placeholder) {
        if (retained == saved.database.records.size()) return false;
        packet::isis::DecodeError error{};
        const auto pdu = packet::isis::parse(saved.database.records[retained++].bytes, error);
        const auto header = pdu ? packet::isis::lsp(*pdu) : std::nullopt;
        if (!header || header->id != entry.id) return false;
      }
      records.push_back({entry.id, entry.circuits, entry.placeholder});
    }
    // Strict unique metadata IDs and an exact ordered bijection for real LSPs
    // also prove that no placeholder can hide a retained encoded identity.
    if (retained != saved.database.records.size() || !database_.restore(saved.database, now, maximum_age)) return false;
    records_.swap(records);
    circuits_.swap(circuits);
    return true;
  } catch (const std::bad_alloc &) { return false; }
    catch (const std::length_error &) { return false; }
}
} // namespace router::isis
