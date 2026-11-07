// Owner-local LSDB storage, recency and lifetime projection. Sorted metadata
// has one reserved allocation; PDU vectors preserve exact accepted bytes.
// A growing replacement stages one PDU before swapping, so peak allocation
// includes staged growing PDUs beyond the final retained-byte budget. Local
// multi-fragment admission reserves metadata cold and commits all bodies before
// its level owner publishes any of their flooding flags.
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
  // Unsigned subtraction represents even a distance spanning both signed
  // clock endpoints. Compare whole seconds before narrowing the difference.
  const auto ticks = static_cast<std::uint64_t>(now.time_since_epoch().count()) -
      static_cast<std::uint64_t>(installed.time_since_epoch().count());
  const auto elapsed = ticks / static_cast<std::uint64_t>(
      std::chrono::duration_cast<RuntimeClock::duration>(std::chrono::seconds{1}).count());
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
           bytes.subspan(packet::isis::lsp_header_octets)}, header, record.purge_installed, record.expiration_notified};
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

LspInstallResult LinkStateDatabase::plan_install(const LspInstallRequest &request,
    RuntimeClock::time_point now, PreparedInstall &prepared) const noexcept {
  using Result = LspInstallResult;
  const auto &admission = request.admission;
  packet::isis::DecodeError error{};
  const auto pdu = packet::isis::parse(request.wire, error);
  if (!pdu || pdu->type != type_ || admission.origin > LspAdmissionOrigin::originated || request.purge_retention.count() < 0 ||
      request.purge_retention.count() > std::numeric_limits<std::uint16_t>::max() || admission.minimum_allocation > 65535U ||
      (admission.minimum_allocation && admission.origin != LspAdmissionOrigin::originated) ||
      admission.purge_anchor > LspPurgeAnchor::current_event ||
      (admission.purge_anchor != LspPurgeAnchor::preserve_expiration &&
       admission.origin != LspAdmissionOrigin::originated)) return Result::malformed;
  auto header = packet::isis::lsp(*pdu);
  if (!header || !header->sequence) return Result::malformed;
  if (!header->checksum) header->remaining_seconds = 0U;
  if (header->remaining_seconds > request.maximum_age) return Result::excessive_lifetime;
  if (header->remaining_seconds && !packet::isis::valid_lsp_checksum(*pdu)) return Result::invalid_checksum;
  const auto entry = std::lower_bound(records_.begin(), records_.end(), header->id,
      [](const Record &record, const auto &key) { return record.header.id < key; });
  prepared.exists = entry != records_.end() && entry->header.id == header->id;
  auto purge_became_zero = now;
  if (prepared.exists) {
    const auto effective = view(*entry, now).header;
    const auto comparison = compare_lsp_headers(*header, effective);
    if (comparison == LspRecency::older) return Result::older;
    // An aged active body still needs its finalized same-sequence purge.
    const bool aged_body = !effective.remaining_seconds && !entry->purge_installed &&
                           header->sequence == effective.sequence && !header->remaining_seconds;
    if (comparison == LspRecency::identical && !aged_body) return Result::identical;
    if (comparison == LspRecency::confusion) return Result::confusion;
    if (aged_body && admission.purge_anchor == LspPurgeAnchor::preserve_expiration)
      purge_became_zero = after(entry->installed_at, std::chrono::seconds(entry->header.remaining_seconds));
  } else if (!header->remaining_seconds && admission.origin == LspAdmissionOrigin::received) {
    return Result::unknown_purge;
  }
  prepared.header = *header;
  prepared.wire = pdu->bytes;
  prepared.retire_at = after(purge_became_zero, request.purge_retention);
  prepared.old_allocation = prepared.exists ? entry->bytes.capacity() : 0U;
  prepared.allocation = std::max({pdu->bytes.size(), limits_.minimum_pdu_allocation, admission.minimum_allocation});
  prepared.reuse = prepared.exists && prepared.allocation <= prepared.old_allocation;
  return Result::installed;
}

bool LinkStateDatabase::stage_install(PreparedInstall &prepared) noexcept {
  if (prepared.reuse) return true;
  try {
    prepared.staged.reserve(prepared.allocation);
    prepared.staged.assign(prepared.wire.begin(), prepared.wire.end());
    prepared.allocation = prepared.staged.capacity();
    return true;
  } catch (const std::bad_alloc &) { return false; }
}

void LinkStateDatabase::commit_install(PreparedInstall &prepared, RuntimeClock::time_point now) noexcept {
  auto entry = std::lower_bound(records_.begin(), records_.end(), prepared.header.id,
      [](const Record &record, const auto &key) { return record.header.id < key; });
  if (!prepared.exists) entry = records_.insert(entry, Record{});
  if (prepared.reuse) {
    // Resize before growth-copy, after shrink-copy. Single admission permits
    // an aliased retained slice; batch admission requires disjoint owned wire.
    if (prepared.wire.size() > entry->bytes.size()) entry->bytes.resize(prepared.wire.size());
    std::memmove(entry->bytes.data(), prepared.wire.data(), prepared.wire.size());
    entry->bytes.resize(prepared.wire.size());
  } else entry->bytes.swap(prepared.staged);
  if (!prepared.header.remaining_seconds) {
    entry->bytes[10U] = 0U;
    entry->bytes[11U] = 0U;
  }
  entry->header = prepared.header;
  entry->installed_at = now;
  entry->purge_installed = prepared.header.remaining_seconds == 0U;
  entry->expiration_notified = false;
  entry->retire_at = prepared.retire_at;
  allocated_octets_ = allocated_octets_ - prepared.old_allocation + entry->bytes.capacity();
}

LspInstallResult LinkStateDatabase::install(std::span<const std::uint8_t> wire,
    RuntimeClock::time_point now, std::uint16_t maximum_age, std::chrono::seconds purge_retention,
    LspAdmission admission) noexcept {
  using Result = LspInstallResult;
  PreparedInstall prepared;
  const auto planned = plan_install({wire, maximum_age, purge_retention, admission}, now, prepared);
  if (planned != Result::installed) return planned;
  if ((!prepared.exists && records_.size() == limits_.records) ||
      (!prepared.reuse && prepared.allocation > limits_.allocated_pdu_octets - (allocated_octets_ - prepared.old_allocation)))
    return Result::capacity_exhausted;
  if (!prepared.exists && admission.reserve_metadata &&
      !admission.reserve_metadata(admission.context, prepared.header)) return Result::capacity_exhausted;
  if (!stage_install(prepared) || (!prepared.reuse &&
      prepared.allocation > limits_.allocated_pdu_octets - (allocated_octets_ - prepared.old_allocation)))
    return Result::capacity_exhausted;
  commit_install(prepared, now);
  return Result::installed;
}

bool LinkStateDatabase::reserve_origin_batch(std::size_t count) noexcept {
  if (count > limits_.records || count > origin_preparation_.max_size() || !origin_preparation_.empty()) return false;
  try { origin_preparation_.reserve(count); return true; }
  catch (const std::bad_alloc &) { return false; }
}

LspInstallResult LinkStateDatabase::install_origin_batch(
    std::span<const LspInstallRequest> requests, RuntimeClock::time_point now) noexcept {
  using Result = LspInstallResult;
  if (requests.empty() || !origin_preparation_.empty()) return Result::malformed;
  if (requests.size() > limits_.records || requests.size() > origin_preparation_.capacity()) return Result::capacity_exhausted;
  struct Clear {
    std::vector<PreparedInstall> &values;
    ~Clear() { values.clear(); }
  } clear{origin_preparation_};
  std::size_t added{}, released{}, replacement{};
  for (const auto &request : requests) {
    if (request.admission.origin != LspAdmissionOrigin::originated) return Result::malformed;
    auto &prepared = origin_preparation_.emplace_back();
    const auto planned = plan_install(request, now, prepared);
    if (planned != Result::installed) return planned;
    for (auto previous = origin_preparation_.begin(); previous != origin_preparation_.end() - 1; ++previous)
      if (previous->header.id == prepared.header.id) return Result::malformed;
    added += !prepared.exists;
    released += prepared.old_allocation;
    const auto allocation = prepared.reuse ? prepared.old_allocation : prepared.allocation;
    if (allocation > limits_.allocated_pdu_octets - replacement) return Result::capacity_exhausted;
    replacement += allocation;
  }
  if (added > limits_.records - records_.size() ||
      replacement > limits_.allocated_pdu_octets - (allocated_octets_ - released)) return Result::capacity_exhausted;
  for (std::size_t index{}; index < requests.size(); ++index) {
    auto &prepared = origin_preparation_[index];
    const auto &admission = requests[index].admission;
    if (!prepared.exists && admission.reserve_metadata &&
        !admission.reserve_metadata(admission.context, prepared.header)) return Result::capacity_exhausted;
    if (!stage_install(prepared)) return Result::capacity_exhausted;
    const auto actual = prepared.reuse ? prepared.old_allocation : prepared.allocation;
    const auto expected = prepared.reuse ? prepared.old_allocation :
        std::max({prepared.wire.size(), limits_.minimum_pdu_allocation, admission.minimum_allocation});
    if (actual - expected > limits_.allocated_pdu_octets - replacement) return Result::capacity_exhausted;
    replacement += actual - expected;
  }
  if (replacement > limits_.allocated_pdu_octets - (allocated_octets_ - released)) return Result::capacity_exhausted;
  for (auto &prepared : origin_preparation_) commit_install(prepared, now);
  return Result::installed;
}

bool LinkStateDatabase::mark_expiration_notified(const packet::isis::LspId &id,
    RuntimeClock::time_point now) noexcept {
  const auto entry = std::lower_bound(records_.begin(), records_.end(), id,
      [](const Record &record, const auto &key) { return record.header.id < key; });
  if (entry == records_.end() || entry->header.id != id || entry->purge_installed || entry->expiration_notified ||
      remaining(entry->header, entry->installed_at, now)) return false;
  entry->expiration_notified = true;
  return true;
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
