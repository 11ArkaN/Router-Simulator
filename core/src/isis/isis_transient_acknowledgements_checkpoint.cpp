// The level owner captures unknown-purge obligations and their ticket order.
// Complete validation and bounded scratch precede one atomic replacement;
// restored receipt identities remain local to the coordinated circuit owners.

#include "router/isis_transient_acknowledgements.hpp"

#include <algorithm>
#include <new>
#include <numeric>
#include <stdexcept>
#include <tuple>

namespace router::isis {
bool TransientAcknowledgements::contains(std::size_t circuit, const TransientAcknowledgement &entry) const noexcept {
  const auto begin = std::lower_bound(entries_.begin(), entries_.end(), std::tie(circuit, entry.entry.id),
      [](const auto &record, const auto &key) { return std::tie(record.circuit, record.acknowledgement.entry.id) < key; });
  for (auto current = begin; current != entries_.end() && current->circuit == circuit &&
      current->acknowledgement.entry.id == entry.entry.id; ++current)
    if (current->acknowledgement.ticket == entry.ticket && current->acknowledgement.entry == entry.entry) return true;
  return false;
}
TransientAcknowledgementsCheckpoint TransientAcknowledgements::checkpoint() const {
  TransientAcknowledgementsCheckpoint result{1U, capacity_, next_ticket_, {}};
  result.entries.reserve(entries_.size());
  for (const auto &record : entries_) result.entries.push_back({record.circuit, record.acknowledgement});
  return result;
}

bool TransientAcknowledgements::restore(const TransientAcknowledgementsCheckpoint &saved,
    std::size_t circuit_count) noexcept {
  if (saved.version != 1U || saved.capacity != capacity_ || !saved.next_ticket || saved.entries.size() > capacity_) return false;
  const auto order = [](const auto &record) {
    return std::tie(record.circuit, record.acknowledgement.entry.id, record.acknowledgement.ticket);
  };
  try {
    std::vector<Record> staged;
    staged.reserve(capacity_);
    for (std::size_t index{}; index < saved.entries.size(); ++index) {
      const auto &record = saved.entries[index];
      if (record.circuit >= circuit_count || record.acknowledgement.entry.remaining_seconds ||
          !record.acknowledgement.ticket || record.acknowledgement.ticket >= saved.next_ticket ||
          (index && order(saved.entries[index - 1U]) >= order(record))) return false;
      staged.push_back({record.circuit, record.acknowledgement});
    }
    // One bounded index scratch validates two independent uniqueness domains
    // without per-entry allocation or quadratic scans through large batches.
    std::vector<std::size_t> indices(saved.entries.size());
    std::iota(indices.begin(), indices.end(), std::size_t{});
    std::sort(indices.begin(), indices.end(), [&](auto a, auto b) {
      return staged[a].acknowledgement.ticket < staged[b].acknowledgement.ticket;
    });
    for (std::size_t index = 1U; index < indices.size(); ++index)
      if (staged[indices[index - 1U]].acknowledgement.ticket == staged[indices[index]].acknowledgement.ticket) return false;
    const auto identity = [&](auto index) {
      const auto &record = staged[index];
      const auto &entry = record.acknowledgement.entry;
      return std::tie(record.circuit, entry.id, entry.sequence, entry.checksum);
    };
    std::sort(indices.begin(), indices.end(), [&](auto a, auto b) { return identity(a) < identity(b); });
    for (std::size_t index = 1U; index < indices.size(); ++index)
      if (identity(indices[index - 1U]) == identity(indices[index])) return false;
    entries_.swap(staged);
    next_ticket_ = saved.next_ticket;
    return true;
  } catch (const std::bad_alloc &) { return false; }
    catch (const std::length_error &) { return false; }
}
} // namespace router::isis
