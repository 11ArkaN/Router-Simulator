// The instance control owner stages one changed source family across bounded
// calls, then publishes every body and SRM flag through the level transaction.
// Preparation is derived scratch; checkpointed generation tickets are authoritative.
#include "router/isis_local_lsp_set.hpp"
#include <algorithm>
#include <array>

namespace router::isis {
bool LocalLspSet::reserve_publication(InstanceUpdateProcess &update) const noexcept {
  std::array<std::size_t, 2U> maximum{};
  std::array<std::size_t, 512U> counts{};
  for (const auto &entry : entries_)
    maximum[entry.content.level] = std::max(maximum[entry.content.level],
        ++counts[entry.content.level * 256U + entry.content.id[6U]]);
  for (std::size_t level{}; level < maximum.size(); ++level)
    if (maximum[level]) {
      const auto *owner = update.level(level);
      if (!owner || !update.reserve_origin_batch(level,
          std::min(maximum[level], owner->database().database().record_limit()))) return false;
    }
  return true;
}

void LocalLspSet::service_overload(InstanceUpdateProcess &update, std::size_t level,
    TransmitAuthentication authentication, RuntimeClock::time_point now,
    PduScratch &scratch, LevelObserver observer, std::size_t &budget, LocalGenerationResult &result) noexcept {
  if (!waiting_overload_[level]) return;
  packet::isis::LspId id{};
  std::copy(local_.begin(), local_.end(), id.begin());
  if (auto *root = find(level, id)) service_retained(update, *root, authentication, now, scratch, observer, budget, result);
}

void LocalLspSet::service_retained(InstanceUpdateProcess &update, Entry &entry,
    TransmitAuthentication authentication, RuntimeClock::time_point now,
    PduScratch &scratch, LevelObserver observer, std::size_t &budget, LocalGenerationResult &result) noexcept {
  if (!observer.event || (authentication.required && !authentication.key)) return;
  const auto &id = entry.content.id;
  const auto level = entry.content.level;
  const auto *owner = update.level(level);
  if (!owner) return;
  const bool overload = waiting_overload_[level] && !id[6U] && !id[7U];
  const auto current = owner->database().database().find(id, now);
  const bool urgent = overload && (!current || !current->header.remaining_seconds || !(current->header.flags & 4U));
  if (!current && !urgent) return;
  const auto refresh = entry.generation.refresh_deadline();
  if ((!urgent || entry.generation.blocked()) && refresh > now) {
    if (!result.deadline || refresh < *result.deadline) result.deadline = refresh;
    return;
  }
  const bool deferred = entry.generation.blocked();
  entry.generation.retry();
  const auto due = entry.generation.deadline();
  if (!due || *due > now || !budget) {
    if (deferred) entry.generation.defer();
    if (due && (!result.deadline || *due < *result.deadline)) result.deadline = due;
    return;
  }
  --budget;
  const auto generation = entry.generation.prepare(now);
  if (generation.status != GenerationStatus::ready) {
    terminal_ = result.terminal = generation.status;
    result.deadline.reset();
    return;
  }
  // A refused relocation cannot publish the proposed new root by itself.
  // Re-encode its retained semantic body with OL and the current key instead.
  // Before initial root publication no old adjacency can be relocated, so the
  // proposed root is safe. Its full reserved allocation still must fit.
  entry.prepared.resize(entry.prepared.capacity());
  packet::isis::TlvWriter options(entry.prepared);
  packet::isis::TlvCursor cursor(current ? current->pdu.tlvs : std::span<const std::uint8_t>{entry.content.options});
  bool valid{true};
  while (const auto option = cursor.next())
    if (option->code != 7U && option->code != 10U && option->code != 13U && !options.append(option->code, option->value)) valid = false;
  const auto &program = *levels_[level];
  const auto flags = static_cast<std::uint8_t>((current ? current->header.flags : entry.content.flags) | (overload ? 4U : 0U));
  const auto built = valid && cursor.valid() ?
      compose(entry, generation.sequence, options.bytes(), flags, authentication.key, scratch) : LspBuild{};
  LevelOriginResult origin;
  if (built.status == LspBuildStatus::encoded)
    origin = update.originate(level, built.bytes, now, OriginPurgeReason::none, observer,
        !id[6U] && !id[7U] ? program.maximum_pdu_octets : 0U);
  const bool installed = origin.status == LevelStatus::applied && origin.install == LspInstallResult::installed;
  static_cast<void>(entry.generation.complete(generation.ticket, installed, now));
  entry.prepared.clear();
  if (installed) {
    entry.generation.changed(now);
    entry.last_error = UpdateStatus::applied;
    ++result.published;
  } else entry.last_error = built.status == LspBuildStatus::authentication ? UpdateStatus::authentication : UpdateStatus::capacity;
  if (deferred || !installed) entry.generation.defer();
  const auto next = entry.generation.refresh_deadline();
  if (next > now && (!result.deadline || next < *result.deadline)) result.deadline = next;
}

bool LocalLspSet::service_family(InstanceUpdateProcess &update, std::size_t index,
    std::array<TransmitAuthentication, 2U> authentication, RuntimeClock::time_point now,
    PduScratch &scratch, LevelObserver observer, std::size_t &budget, LocalGenerationResult &result) noexcept {
  auto &first = entries_[index];
  const auto level = first.content.level;
  const auto *owner = update.level(level);
  if (!owner) return false;
  std::array<Entry *, 256U> members{};
  std::size_t count{};
  bool reserved{};
  auto begin = index;
  const auto same_family = [&](const Entry &entry) noexcept {
    return entry.content.level == level &&
        std::equal(first.content.id.begin(), first.content.id.begin() + 7U, entry.content.id.begin());
  };
  while (begin && same_family(entries_[begin - 1U])) --begin;
  for (auto position = begin; position < entries_.size() && same_family(entries_[position]); ++position) {
    auto &entry = entries_[position];
    const auto current = owner->database().database().find(entry.content.id, now);
    if (current && current->header.sequence > entry.generation.sequence_floor())
      static_cast<void>(require_after(level, entry.content.id, current->header.sequence, now));
    if (entry.retirement_pending && (!current || current->purge_installed)) {
      entry.retirement_pending = entry.retirement_blocked = false;
      entry.prepared.clear();
      entry.last_error = UpdateStatus::applied;
    }
    if (const auto pending = entry.generation.reservation();
        pending && pending->sequence <= entry.generation.sequence_floor()) {
      entry.prepared.clear();
      entry.generation.abandon();
    }
    if (!(entry.content.active && entry.generation.content_pending()) && !entry.retirement_pending) continue;
    members[count++] = &entry;
    reserved = reserved || entry.generation.reservation().has_value();
  }
  if (!count || (count == 1U && !reserved && !members[0U]->generation.blocked() &&
      !members[0U]->retirement_blocked)) return false;
  auto block = [&](UpdateStatus error) noexcept {
    for (std::size_t member{}; member < count; ++member) {
      auto &entry = *members[member];
      if (const auto pending = entry.generation.reservation())
        static_cast<void>(entry.generation.complete(pending->ticket, false, now));
      entry.prepared.clear();
      entry.last_error = error;
      if (error == UpdateStatus::capacity && waiting_overload_[level] &&
          !entry.content.id[6U] && !entry.content.id[7U]) entry.generation.retry();
      if (entry.retirement_pending) entry.retirement_blocked = true;
      ++result.blocked;
    }
  };
  const auto retained = [&]() noexcept {
    service_overload(update, level, authentication[level], now, scratch, observer, budget, result);
    for (std::size_t member{}; member < count && terminal_ == GenerationStatus::waiting; ++member) {
      auto &entry = *members[member];
      if (waiting_overload_[level] && !entry.content.id[6U] && !entry.content.id[7U]) continue;
      service_retained(update, entry, authentication[level], now, scratch, observer, budget, result);
    }
  };
  std::optional<RuntimeClock::time_point> ready;
  for (std::size_t member{}; member < count; ++member) {
    auto &entry = *members[member];
    if (entry.generation.sequence_exhaustion_due(now) && entry.content.active) {
      terminal_ = result.terminal = entry.generation.prepare(now).status;
      result.deadline.reset();
      return true;
    }
    if ((entry.content.active && entry.generation.blocked()) || entry.retirement_blocked) {
      result.blocked += count;
      retained();
      return true;
    }
    if (entry.content.active && !entry.generation.reservation()) {
      const auto due = entry.generation.deadline();
      if (due && (!ready || *due > *ready)) ready = due;
    }
  }
  if (ready && *ready > now) {
    if (!result.deadline || *ready < *result.deadline) result.deadline = ready;
    return true;
  }
  // The parent uses a zero budget while a newer semantic composition is still
  // incomplete. Even a fully cached reservation must not bypass that fence.
  if (!budget) {
    if (!result.deadline || now < *result.deadline) result.deadline = now;
    return true;
  }
  const auto &key = authentication[level];
  if (key.required && !key.key) { block(UpdateStatus::authentication); return true; }
  if (!observer.event) { block(UpdateStatus::missing_observer); return true; }
  std::array<LevelOriginInput, 256U> inputs{};
  for (std::size_t member{}; member < count; ++member) {
    auto &entry = *members[member];
    if (!entry.prepared.empty()) {
      packet::isis::DecodeError error{};
      const auto pdu = packet::isis::parse(entry.prepared, error);
      bool valid = pdu.has_value();
      if (key.key) valid = valid && verify_authentication(entry.prepared, *key.key) == AuthenticationError::none;
      else if (pdu) {
        packet::isis::TlvCursor cursor(pdu->tlvs);
        while (const auto option = cursor.next()) if (option->code == 10U) valid = false;
      }
      if (valid && entry.retirement_pending) {
        const auto current = owner->database().database().find(entry.content.id, now);
        const auto header = packet::isis::lsp(*pdu);
        valid = current && header && header->sequence == current->header.sequence &&
            header->checksum == current->header.checksum && header->flags == current->header.flags &&
            entry.prepared_reason == (current->header.remaining_seconds ?
                OriginPurgeReason::initiated : OriginPurgeReason::lifetime_expired);
      }
      if (!valid) entry.prepared.clear();
    }
    if (entry.prepared.empty()) {
      if (!budget) {
        if (!result.deadline || now < *result.deadline) result.deadline = now;
        return true;
      }
      --budget;
      LspBuild built;
      if (entry.content.active) {
        auto generation = entry.generation.reservation();
        if (!generation) generation = entry.generation.prepare(now);
        if (generation->status != GenerationStatus::ready) {
          terminal_ = result.terminal = generation->status;
          result.deadline.reset();
          return true;
        }
        built = compose(entry, generation->sequence, entry.content.options, entry.content.flags, key.key, scratch);
        entry.prepared_reason = OriginPurgeReason::none;
      } else {
        const auto purge = update.prepare_local_retirement(level, entry.content.id, key, now, scratch.options, scratch.pdu);
        if (purge.status != UpdateStatus::applied) { block(purge.status); return true; }
        built = purge.composition;
        entry.prepared_reason = purge.reason;
      }
      if (built.status != LspBuildStatus::encoded) {
        block(built.status == LspBuildStatus::capacity ? UpdateStatus::capacity :
            built.status == LspBuildStatus::authentication ? UpdateStatus::authentication : UpdateStatus::invalid_configuration);
        return true;
      }
      if (built.bytes.size() > entry.prepared.capacity()) { block(UpdateStatus::capacity); return true; }
      entry.prepared.assign(built.bytes.begin(), built.bytes.end());
    }
    inputs[member] = {entry.prepared, entry.prepared_reason,
        !entry.content.id[6U] && !entry.content.id[7U] ? levels_[level]->maximum_pdu_octets : 0U};
  }
  // At most 256 members. All cached authentication and retained purge headers
  // are revalidated under this call's leases before the one atomic admission.
  const auto origin = update.originate_batch(level, std::span{inputs}.first(count), now, observer);
  if (origin.status != LevelStatus::applied || origin.install != LspInstallResult::installed) {
    block(origin.status == LevelStatus::capacity ? UpdateStatus::capacity : UpdateStatus::level_refused);
    retained();
    return true;
  }
  for (std::size_t member{}; member < count; ++member) {
    auto &entry = *members[member];
    if (const auto pending = entry.generation.reservation())
      static_cast<void>(entry.generation.complete(pending->ticket, true, now));
    entry.prepared.clear();
    entry.retirement_pending = entry.retirement_blocked = false;
    entry.last_error = UpdateStatus::applied;
    ++result.published;
  }
  return true;
}
}
