// Owner-local LSDB storage, recency and lifetime projection. Sorted metadata
// has one reserved allocation; PDU vectors preserve exact accepted bytes.
// A growing replacement stages one PDU before swapping, so peak allocation
// includes one additional maximum PDU beyond the retained-byte budget.
// Source: iso.10589.2002.lsdb

#include "router/isis_lsdb.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <type_traits>

namespace router::isis {
namespace {
[[nodiscard]] RuntimeClock::time_point after(RuntimeClock::time_point now,
    std::chrono::seconds seconds) noexcept {
  const auto duration = std::chrono::duration_cast<RuntimeClock::duration>(seconds);
  return now > RuntimeClock::time_point::max() - duration
      ? RuntimeClock::time_point::max() : now + duration;
}
[[nodiscard]] std::uint16_t remaining(const packet::isis::LspView &header,
    RuntimeClock::time_point installed, RuntimeClock::time_point now) noexcept {
  if (now <= installed) return header.remaining_seconds;
  const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - installed).count();
  return elapsed >= header.remaining_seconds ? 0U :
      static_cast<std::uint16_t>(header.remaining_seconds - elapsed);
}
}

LspRecency compare_lsp_headers(const packet::isis::LspView &candidate,
                               const packet::isis::LspView &current) noexcept {
  if (candidate.sequence != current.sequence)
    return candidate.sequence > current.sequence ? LspRecency::newer : LspRecency::older;
  if ((candidate.remaining_seconds == 0U) != (current.remaining_seconds == 0U))
    return candidate.remaining_seconds == 0U ? LspRecency::newer : LspRecency::older;
  if (!candidate.remaining_seconds) return LspRecency::identical;
  return candidate.checksum == current.checksum ? LspRecency::identical : LspRecency::confusion;
}

LinkStateDatabase::LinkStateDatabase(packet::isis::PduType type, LsdbLimits limits)
    : type_(type), limits_(limits) {
  if (type != packet::isis::PduType::lsp_l1 && type != packet::isis::PduType::lsp_l2)
    throw std::invalid_argument("IS-IS LSDB requires an LSP level");
  if (limits.minimum_pdu_allocation > 65535U ||
      (limits.minimum_pdu_allocation && limits.minimum_pdu_allocation < packet::isis::lsp_header_octets))
    throw std::invalid_argument("Invalid IS-IS purge buffer reservation");
  if (limits.records > records_.max_size())
    throw std::invalid_argument("IS-IS LSDB metadata limit exceeds the container bound");
  records_.reserve(limits.records);
  static_assert(std::is_nothrow_move_constructible_v<Record> && std::is_nothrow_move_assignable_v<Record>);
}

StoredLspView LinkStateDatabase::view(const Record &record, RuntimeClock::time_point now) const noexcept {
  auto header = record.header;
  header.remaining_seconds = remaining(header, record.installed_at, now);
  const std::span<const std::uint8_t> bytes(record.bytes);
  return {{type_, static_cast<std::uint8_t>(bytes[7U] ? bytes[7U] : 3U), bytes,
           bytes.subspan(packet::isis::lsp_header_octets)}, header, record.purge_installed};
}

std::optional<StoredLspView> LinkStateDatabase::find(const packet::isis::LspId &id,
    RuntimeClock::time_point now) const noexcept {
  const auto entry = std::lower_bound(records_.begin(), records_.end(), id,
      [](const Record &record, const auto &key) { return record.header.id < key; });
  return entry == records_.end() || entry->header.id != id ? std::nullopt : std::optional(view(*entry, now));
}

std::optional<StoredLspView> LinkStateDatabase::at(std::size_t index,
    RuntimeClock::time_point now) const noexcept {
  return index < records_.size() ? std::optional(view(records_[index], now)) : std::nullopt;
}

std::optional<StoredLspView> LinkStateDatabase::next_after(std::optional<packet::isis::LspId> cursor,
    RuntimeClock::time_point now) const noexcept {
  const auto entry = cursor ? std::upper_bound(records_.begin(), records_.end(), *cursor,
      [](const auto &key, const Record &record) { return key < record.header.id; }) : records_.begin();
  return entry == records_.end() ? std::nullopt : std::optional(view(*entry, now));
}

std::optional<LspDeadline> LinkStateDatabase::next_deadline(std::optional<LspDeadlineKind> kind,
    std::span<const packet::isis::LspId> blocked_expirations) const noexcept {
  std::optional<LspDeadline> result;
  for (const auto &record : records_) {
    const LspDeadline candidate{record.header.id,
        record.purge_installed ? record.retire_at : after(record.installed_at, std::chrono::seconds{record.header.remaining_seconds}),
        record.purge_installed ? LspDeadlineKind::retire_purge : LspDeadlineKind::finalize_expiration};
    if (candidate.kind == LspDeadlineKind::finalize_expiration &&
        std::binary_search(blocked_expirations.begin(), blocked_expirations.end(), candidate.id)) continue;
    if ((!kind || candidate.kind == *kind) && (!result || candidate.at < result->at)) result = candidate;
  }
  return result;
}

LspInstallResult LinkStateDatabase::install(std::span<const std::uint8_t> wire,
    RuntimeClock::time_point now, std::uint16_t maximum_age, std::chrono::seconds purge_retention,
    LspAdmission admission) noexcept {
  using Result = LspInstallResult;
  packet::isis::DecodeError error{};
  const auto pdu = packet::isis::parse(wire, error);
  if (!pdu || pdu->type != type_ || admission.origin > LspAdmissionOrigin::originated || purge_retention.count() < 0 ||
      purge_retention.count() > std::numeric_limits<std::uint16_t>::max() || admission.minimum_allocation > 65535U ||
      (admission.minimum_allocation && admission.origin != LspAdmissionOrigin::originated) ||
      admission.purge_anchor > LspPurgeAnchor::current_event ||
      (admission.purge_anchor != LspPurgeAnchor::preserve_expiration &&
       admission.origin != LspAdmissionOrigin::originated)) return Result::malformed;
  auto header = packet::isis::lsp(*pdu);
  if (!header || !header->sequence) return Result::malformed;
  if (!header->checksum) header->remaining_seconds = 0U;
  if (header->remaining_seconds > maximum_age) return Result::excessive_lifetime;
  if (header->remaining_seconds && !packet::isis::valid_lsp_checksum(*pdu)) return Result::invalid_checksum;
  auto entry = std::lower_bound(records_.begin(), records_.end(), header->id,
      [](const Record &record, const auto &key) { return record.header.id < key; });
  const bool exists = entry != records_.end() && entry->header.id == header->id;
  auto purge_became_zero = now;
  if (exists) {
    const auto effective = view(*entry, now).header;
    const auto comparison = compare_lsp_headers(*header, effective);
    if (comparison == LspRecency::older) return Result::older;
    // Aging changes effective lifetime without rewriting authenticated bytes.
    // A same-sequence purge must still replace an aged active body so the
    // process can flood its finalized purge and eventually retire the record.
    const bool aged_body = !effective.remaining_seconds && !entry->purge_installed &&
                           header->sequence == effective.sequence && !header->remaining_seconds;
    if (comparison == LspRecency::identical && !aged_body) return Result::identical;
    if (comparison == LspRecency::confusion) return Result::confusion;
    if (aged_body && admission.purge_anchor == LspPurgeAnchor::preserve_expiration)
      purge_became_zero = after(entry->installed_at, std::chrono::seconds(entry->header.remaining_seconds));
  } else {
    if (!header->remaining_seconds && admission.origin == LspAdmissionOrigin::received) return Result::unknown_purge;
    if (records_.size() == limits_.records) return Result::capacity_exhausted;
  }
  const auto old_allocation = exists ? entry->bytes.capacity() : 0U;
  const auto retained_other = allocated_octets_ - old_allocation;
  const auto allocation = std::max({pdu->bytes.size(), limits_.minimum_pdu_allocation, admission.minimum_allocation});
  const bool reuse = exists && allocation <= entry->bytes.capacity();
  if (!reuse && allocation > limits_.allocated_pdu_octets - retained_other)
    return Result::capacity_exhausted;
  if (!exists && admission.reserve_metadata && !admission.reserve_metadata(admission.context, *header))
    return Result::capacity_exhausted;
  std::vector<std::uint8_t> staged;
  if (!reuse) {
    try {
      staged.reserve(allocation);
      staged.assign(pdu->bytes.begin(), pdu->bytes.end());
    }
    catch (const std::bad_alloc &) { return Result::capacity_exhausted; }
    if (staged.capacity() > limits_.allocated_pdu_octets - retained_other) return Result::capacity_exhausted;
  }
  if (!exists) entry = records_.insert(entry, Record{});
  if (reuse) {
    // Growing within retained capacity initializes the new elements before
    // copying, otherwise resize would overwrite the accepted suffix. Aliased
    // input cannot extend beyond the old size. Shrinking follows the copy so
    // a borrowed input slice remains alive throughout the move.
    if (pdu->bytes.size() > entry->bytes.size()) entry->bytes.resize(pdu->bytes.size());
    std::memmove(entry->bytes.data(), pdu->bytes.data(), pdu->bytes.size());
    entry->bytes.resize(pdu->bytes.size());
  } else entry->bytes.swap(staged);
  if (!header->remaining_seconds) {
    entry->bytes[10U] = 0U;
    entry->bytes[11U] = 0U;
  }
  entry->header = *header;
  entry->installed_at = now;
  entry->purge_installed = header->remaining_seconds == 0U;
  entry->retire_at = after(purge_became_zero, purge_retention);
  allocated_octets_ = retained_other + entry->bytes.capacity();
  return Result::installed;
}

bool LinkStateDatabase::retire_purge(const packet::isis::LspId &id,
    RuntimeClock::time_point now) noexcept {
  const auto entry = std::lower_bound(records_.begin(), records_.end(), id,
      [](const Record &record, const auto &key) { return record.header.id < key; });
  if (entry == records_.end() || entry->header.id != id || !entry->purge_installed || now < entry->retire_at)
    return false;
  allocated_octets_ -= entry->bytes.capacity();
  records_.erase(entry);
  return true;
}

} // namespace router::isis
