// Unknown-purge acknowledgement admission, ordered batching and receipt
// retirement. The level control owner alone mutates this bounded metadata.
// Source: ISO 10589 7.3.16.4(a), 7.3.17 and SNP entry ordering in 9.10-9.13.

#include "router/isis_transient_acknowledgements.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <tuple>

namespace router::isis {
TransientAcknowledgements::TransientAcknowledgements(std::size_t capacity, std::uint64_t first_ticket)
    : capacity_(capacity), next_ticket_(first_ticket) {
  if (!first_ticket) throw std::invalid_argument("IS-IS acknowledgement ticket zero is reserved");
  entries_.reserve(capacity);
}

AcknowledgementResult TransientAcknowledgements::admit(std::size_t circuit,
    const packet::isis::SnpEntry &entry) noexcept {
  if (entry.remaining_seconds) return {AcknowledgementAdmission::not_purge};
  const auto duplicate = std::find_if(entries_.begin(), entries_.end(), [&](const auto &record) {
    return record.circuit == circuit && record.acknowledgement.entry == entry;
  });
  if (duplicate != entries_.end()) return {AcknowledgementAdmission::duplicate, duplicate->acknowledgement.ticket};
  if (entries_.size() == capacity_) return {AcknowledgementAdmission::capacity};
  if (next_ticket_ == std::numeric_limits<std::uint64_t>::max())
    return {AcknowledgementAdmission::ticket_exhausted};
  const auto insertion = std::upper_bound(entries_.begin(), entries_.end(), std::tie(circuit, entry.id),
      [](const auto &key, const Record &record) {
        return key < std::tie(record.circuit, record.acknowledgement.entry.id);
      });
  const auto ticket = next_ticket_++;
  entries_.insert(insertion, {circuit, {entry, ticket}});
  return {AcknowledgementAdmission::queued, ticket};
}

AcknowledgementSelection TransientAcknowledgements::select(std::size_t circuit,
    std::optional<packet::isis::LspId> cursor, std::span<TransientAcknowledgement> output) const noexcept {
  AcknowledgementSelection result{0U, cursor};
  if (output.empty()) return result;
  const auto first = std::lower_bound(entries_.begin(), entries_.end(), circuit,
      [](const Record &record, auto value) { return record.circuit < value; });
  const auto last = std::upper_bound(first, entries_.end(), circuit,
      [](auto value, const Record &record) { return value < record.circuit; });
  const auto count = static_cast<std::size_t>(last - first);
  if (!count) return result;
  std::size_t start{};
  if (cursor) start = static_cast<std::size_t>(std::upper_bound(first, last, *cursor,
      [](const auto &id, const Record &record) { return id < record.acknowledgement.entry.id; }) - first);
  std::optional<packet::isis::LspId> previous;
  for (std::size_t offset{}; offset < count; ++offset) {
    const auto &acknowledgement = first[static_cast<std::ptrdiff_t>((start + offset) % count)].acknowledgement;
    if (previous && acknowledgement.entry.id == *previous) continue;
    previous = acknowledgement.entry.id;
    output[result.count++] = acknowledgement;
    result.cursor = acknowledgement.entry.id;
    if (result.count == output.size()) break;
  }
  std::sort(output.begin(), output.begin() + result.count,
      [](const auto &left, const auto &right) { return left.entry.id < right.entry.id; });
  return result;
}

bool TransientAcknowledgements::complete(std::size_t circuit, std::uint64_t ticket, bool enqueued) noexcept {
  const auto found = std::find_if(entries_.begin(), entries_.end(), [&](const auto &record) {
    return record.circuit == circuit && record.acknowledgement.ticket == ticket;
  });
  if (found == entries_.end()) return false;
  if (enqueued) entries_.erase(found);
  return true;
}

std::size_t TransientAcknowledgements::clear_circuit(std::size_t circuit) noexcept {
  return std::erase_if(entries_, [circuit](const auto &record) { return record.circuit == circuit; });
}
} // namespace router::isis
