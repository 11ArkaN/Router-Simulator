// The LSDB instance owner captures exact wire and relative lifetime state.
// Restoration stages a complete bounded repository before replacing any live
// record. Dependencies point to packet validation and owner-local time values.

#include "router/isis_lsdb.hpp"
#include "router/isis_checkpoint_time.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>

namespace router::isis {
LsdbCheckpoint LinkStateDatabase::checkpoint(RuntimeClock::time_point now) const {
  LsdbCheckpoint result{1U, type_, limits_, {}};
  result.records.reserve(records_.size());
  for (const auto &record : records_) {
    const auto age = checkpoint_time::offset(now, record.installed_at);
    const auto retirement = record.purge_installed ? checkpoint_time::offset(record.retire_at, now) :
        std::optional<std::int64_t>{};
    if (!age || *age < 0 || (record.purge_installed && !retirement))
      throw std::invalid_argument("IS-IS LSDB checkpoint clock range is invalid");
    result.records.push_back({record.bytes, record.bytes.capacity(), *age, retirement, record.expiration_notified});
  }
  return result;
}

bool LinkStateDatabase::restore(const LsdbCheckpoint &saved, RuntimeClock::time_point now,
    std::uint16_t maximum_age) noexcept {
  if (saved.version != 1U || saved.type != type_ || saved.limits != limits_ || saved.records.size() > limits_.records)
    return false;
  try {
    std::vector<Record> staged;
    staged.reserve(limits_.records);
    std::size_t allocated{};
    for (const auto &entry : saved.records) {
      packet::isis::DecodeError error{};
      const auto pdu = packet::isis::parse(entry.bytes, error);
      const auto header = pdu ? packet::isis::lsp(*pdu) : std::nullopt;
      if (!header || pdu->type != type_ || pdu->bytes.size() != entry.bytes.size() || !header->sequence ||
          header->remaining_seconds > maximum_age || entry.age_nanoseconds < 0 ||
          (!staged.empty() && staged.back().header.id >= header->id) ||
          entry.allocation < std::max(entry.bytes.size(), limits_.minimum_pdu_allocation) ||
          entry.allocation > limits_.allocated_pdu_octets - allocated) return false;
      const bool purge = header->remaining_seconds == 0U;
      const auto lifetime = std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::seconds{header->remaining_seconds}).count();
      if (purge != entry.retirement_nanoseconds.has_value() ||
          (!purge && (!header->checksum || !packet::isis::valid_lsp_checksum(*pdu))) ||
          (entry.expiration_notified && (purge || entry.age_nanoseconds < lifetime)) ||
          (!purge && !checkpoint_time::restore(lifetime - entry.age_nanoseconds, now)) ||
          (entry.retirement_nanoseconds && *entry.retirement_nanoseconds >
              std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds{65535}).count())) return false;
      const auto installed = checkpoint_time::restore(-entry.age_nanoseconds, now);
      const auto retired = entry.retirement_nanoseconds ? checkpoint_time::restore(*entry.retirement_nanoseconds, now) :
          std::optional{RuntimeClock::time_point{}};
      if (!installed || !retired) return false;
      Record record{*header, {}, *installed, *retired, purge, entry.expiration_notified};
      record.bytes.reserve(entry.allocation);
      if (record.bytes.capacity() > limits_.allocated_pdu_octets - allocated) return false;
      record.bytes.assign(entry.bytes.begin(), entry.bytes.end());
      allocated += record.bytes.capacity();
      staged.push_back(std::move(record));
    }
    records_.swap(staged);
    allocated_octets_ = allocated;
    return true;
  } catch (const std::bad_alloc &) { return false; }
    catch (const std::length_error &) { return false; }
}
} // namespace router::isis
