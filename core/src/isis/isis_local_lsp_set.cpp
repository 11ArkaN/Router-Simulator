// Current local content survives LSDB aging and resource waits. Per-record
// schedules commit only after encoded local publication, never after enqueue.
// Sources: iso.10589.2002.local_lsp_generation, iso.10589.2002.lsp_composition

#include "router/isis_local_lsp_set.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
namespace {
bool valid_content(std::size_t level, const packet::isis::LspId &id, std::uint8_t flags, std::span<const std::uint8_t> options) noexcept {
  const auto type = flags & 3U;
  if (level > 1U || (type != 1U && type != 3U) || (level && type != 3U)) return false;
  packet::isis::TlvCursor cursor(options);
  while (const auto option = cursor.next())
    if (option->code == 7U || option->code == 10U || option->code == 13U ||
        (option->code == 1U && (id[6U] || id[7U]))) return false;
  return cursor.valid();
}
}
std::size_t LocalLspProgram::active_records() const noexcept {
  return static_cast<std::size_t>(std::count_if(records.begin(), records.end(), [](const auto &record) { return record.active; }));
}
LocalLspSet::Entry::Entry(LocalLspContent value, const LocalLspLevelProgram &program,
    std::uint64_t random, RuntimeClock::time_point now)
    : content{value.level, value.id, value.flags, {}, value.active},
      generation(program.minimum_interval, program.refresh_interval, random, now) {
  prepared.reserve(program.maximum_pdu_octets);
  content.options.reserve(program.maximum_pdu_octets - packet::isis::lsp_header_octets);
  content.options.assign(value.options.begin(), value.options.end());
}
LocalLspSet::LocalLspSet(packet::isis::SystemId local, std::uint8_t maximum_areas,
    UpdateInstanceSelector selector, LocalLspProgram program, RuntimeClock::time_point now)
    : local_(local), maximum_areas_(maximum_areas), selector_(selector), levels_(program.levels) {
  if (!maximum_areas || maximum_areas == 255U || !program.random ||
      selector.format > packet::isis::InstanceFormat::standard || program.records.empty())
    throw std::invalid_argument("Invalid IS-IS local LSP program");
  for (const auto &level : levels_) if (level && (!level->maximum_age ||
      level->maximum_pdu_octets < packet::isis::lsp_header_octets ||
      level->refresh_interval >= std::chrono::seconds{level->maximum_age}))
    throw std::invalid_argument("Invalid IS-IS local LSP lifetime or buffer");
  std::sort(program.records.begin(), program.records.end(), [](const auto &left, const auto &right) {
    return left.level != right.level ? left.level < right.level : left.id < right.id;
  });
  std::array<bool, 2U> roots{};
  entries_.reserve(program.records.size());
  for (auto &content : program.records) {
    if (!valid_content(content.level, content.id, content.flags, content.options) || !levels_[content.level] ||
        !std::equal(local_.begin(), local_.end(), content.id.begin()) ||
        content.options.size() > levels_[content.level]->maximum_pdu_octets - packet::isis::lsp_header_octets ||
        find(content.level, content.id))
      throw std::invalid_argument("Invalid or duplicate current local IS-IS LSP");
    roots[content.level] = roots[content.level] || (content.active && !content.id[6U] && !content.id[7U]);
    auto seed = program.random ^ (static_cast<std::uint64_t>(entries_.size()) + 1U);
    if (!seed) seed = program.random;
    const auto level = content.level;
    entries_.emplace_back(std::move(content), *levels_[level], seed, now);
  }
  for (std::size_t level{}; level < levels_.size(); ++level)
    if (levels_[level] && !roots[level]) throw std::invalid_argument("Missing local IS-IS zeroth LSP");
}
LocalLspSet::Entry *LocalLspSet::find(std::size_t level, const packet::isis::LspId &id) noexcept {
  const auto found = std::find_if(entries_.begin(), entries_.end(), [&](const auto &entry) {
    return entry.content.level == level && entry.content.id == id;
  });
  return found == entries_.end() ? nullptr : &*found;
}
bool LocalLspSet::contains(std::size_t level, const packet::isis::LspId &id) const noexcept {
  return std::any_of(entries_.begin(), entries_.end(), [&](const auto &entry) {
    return entry.content.active && entry.content.level == level && entry.content.id == id;
  });
}
std::optional<LocalLspFragment> LocalLspSet::fragment(std::size_t level, const packet::isis::LspId &id) const noexcept {
  const auto entry = std::lower_bound(entries_.begin(), entries_.end(), id,
      [level](const auto &value, const auto &key) {
        return value.content.level != level ? value.content.level < level : value.content.id < key;
      });
  if (entry == entries_.end() || entry->content.level != level || entry->content.id != id || !entry->content.active)
    return std::nullopt;
  return LocalLspFragment{id[7U], entry->content.flags, entry->content.options};
}
std::optional<UpdateStatus> LocalLspSet::last_error(std::size_t level, const packet::isis::LspId &id) const noexcept {
  for (const auto &entry : entries_)
    if (entry.content.level == level && entry.content.id == id) return entry.last_error;
  return std::nullopt;
}
std::optional<std::uint32_t> LocalLspSet::sequence(std::size_t level, const packet::isis::LspId &id) const noexcept {
  for (const auto &entry : entries_)
    if (entry.content.level == level && entry.content.id == id) return entry.generation.committed_sequence();
  return std::nullopt;
}
std::optional<std::uint32_t> LocalLspSet::sequence_floor(std::size_t level, const packet::isis::LspId &id) const noexcept {
  for (const auto &entry : entries_)
    if (entry.content.level == level && entry.content.id == id) return entry.generation.sequence_floor();
  return std::nullopt;
}
LocalContentResult LocalLspSet::replace(std::size_t level, const packet::isis::LspId &id,
    std::uint8_t flags, std::span<const std::uint8_t> options, RuntimeClock::time_point now) noexcept {
  auto *entry = find(level, id);
  if (!entry) return LocalContentResult::missing;
  if (!valid_content(level, id, flags, options)) return LocalContentResult::invalid;
  if (options.size() > levels_[level]->maximum_pdu_octets - packet::isis::lsp_header_octets)
    return LocalContentResult::capacity;
  if (entry->content.active && entry->content.flags == flags && std::ranges::equal(entry->content.options, options))
    return LocalContentResult::unchanged;
  // Public inputs must not borrow this private vector. Its reserved capacity
  // bounds replacement; no allocation or invalidation of a published view occurs.
  entry->content.options.assign(options.begin(), options.end());
  entry->content.flags = flags;
  entry->content.active = true;
  entry->retirement_pending = entry->retirement_blocked = false;
  entry->prepared.clear();
  entry->generation.abandon();
  entry->generation.changed(now);
  entry->generation.retry();
  return LocalContentResult::changed;
}
LocalContentResult LocalLspSet::replace_fragments(std::size_t level,
    const packet::isis::LanId &source, std::span<const LocalLspFragment> fragments,
    RuntimeClock::time_point now) noexcept {
  if (level >= levels_.size() || !levels_[level] ||
      !std::equal(local_.begin(), local_.end(), source.begin()) ||
      (fragments.empty() && !source[6U]) || (!fragments.empty() && fragments.front().number))
    return LocalContentResult::invalid;
  packet::isis::LspId id{};
  std::copy(source.begin(), source.end(), id.begin());
  if (!find(level, id)) return LocalContentResult::missing;
  for (std::size_t index{}; index < fragments.size(); ++index) {
    const auto &fragment = fragments[index];
    id[7U] = fragment.number;
    const auto *entry = find(level, id);
    if (!entry) return LocalContentResult::missing;
    if ((index && fragments[index - 1U].number >= fragment.number) ||
        !valid_content(level, id, fragment.flags, fragment.options)) return LocalContentResult::invalid;
    if (fragment.options.size() > levels_[level]->maximum_pdu_octets - packet::isis::lsp_header_octets)
      return LocalContentResult::capacity;
  }
  bool changed{};
  // All calls below operate within capacities checked above and cannot refuse.
  // Missing inputs are withdrawn in the same owner turn, without observers.
  for (const auto &fragment : fragments) {
    id[7U] = fragment.number;
    changed = replace(level, id, fragment.flags, fragment.options, now) == LocalContentResult::changed || changed;
  }
  for (auto &entry : entries_) {
    if (entry.content.level != level || !std::equal(source.begin(), source.end(), entry.content.id.begin())) continue;
    const auto found = std::lower_bound(fragments.begin(), fragments.end(), entry.content.id[7U],
        [](const auto &fragment, std::uint8_t number) { return fragment.number < number; });
    if (found == fragments.end() || found->number != entry.content.id[7U])
      changed = withdraw(level, entry.content.id) == LocalContentResult::changed || changed;
  }
  return changed ? LocalContentResult::changed : LocalContentResult::unchanged;
}
LocalContentResult LocalLspSet::withdraw(std::size_t level, const packet::isis::LspId &id) noexcept {
  auto *entry = find(level, id);
  if (!entry) return LocalContentResult::missing;
  if (!id[6U] && !id[7U]) return LocalContentResult::invalid;
  if (!entry->content.active) return LocalContentResult::unchanged;
  entry->prepared.clear();
  entry->generation.abandon();
  entry->content.active = false;
  entry->retirement_pending = true;
  entry->retirement_blocked = false;
  return LocalContentResult::changed;
}
bool LocalLspSet::require_after(std::size_t level, const packet::isis::LspId &id,
    std::uint32_t sequence, RuntimeClock::time_point now) noexcept {
  auto *entry = find(level, id);
  if (!entry) return false;
  entry->prepared.clear();
  entry->generation.abandon();
  entry->generation.require_after(sequence, now);
  return true;
}
void LocalLspSet::retry(std::size_t level) noexcept {
  for (auto &entry : entries_) if (entry.content.level == level) {
    entry.generation.retry();
    entry.retirement_blocked = false;
  }
}
LocalContentResult LocalLspSet::waiting_overload(std::size_t level, bool enabled, RuntimeClock::time_point now) noexcept {
  if (level >= levels_.size() || !levels_[level]) return LocalContentResult::missing;
  if (waiting_overload_[level] == enabled) return LocalContentResult::unchanged;
  packet::isis::LspId root{};
  std::copy(local_.begin(), local_.end(), root.begin());
  auto *entry = find(level, root);
  if (!entry) return LocalContentResult::missing;
  waiting_overload_[level] = enabled;
  entry->prepared.clear();
  entry->generation.abandon();
  entry->generation.changed(now);
  entry->generation.retry();
  return LocalContentResult::changed;
}
LspBuild LocalLspSet::compose(const Entry &entry, std::uint32_t sequence,
    std::span<const std::uint8_t> options, std::uint8_t flags,
    std::optional<AuthenticationKey> key, PduScratch &scratch) const noexcept {
  const auto level = entry.content.level;
  LspContents contents;
  contents.header = {level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1,
      entry.content.id, levels_[level]->maximum_age, sequence, flags, maximum_areas_};
  if (waiting_overload_[level] && !entry.content.id[6U] && !entry.content.id[7U]) contents.header.flags |= 4U;
  contents.options = options;
  contents.authentication = key;
  contents.maximum_pdu_octets = levels_[level]->maximum_pdu_octets;
  const std::array<std::uint16_t, 1U> topology{0U};
  if (selector_.wire_instance || selector_.format == packet::isis::InstanceFormat::legacy_2009)
    contents.instance = PduInstanceOption{selector_.format, selector_.wire_instance,
        selector_.format == packet::isis::InstanceFormat::standard ? std::span<const std::uint16_t>(topology) :
            std::span<const std::uint16_t>{}};
  return build_lsp_pdu(contents, scratch.options, scratch.pdu);
}
LocalGenerationResult LocalLspSet::service(InstanceUpdateProcess &update,
    std::array<TransmitAuthentication, 2U> authentication, RuntimeClock::time_point now,
    PduScratch &scratch, LevelObserver observer, std::size_t &budget) noexcept {
  LocalGenerationResult result;
  result.terminal = terminal_;
  if (terminal_ != GenerationStatus::waiting) return result;
  std::array<bool, 512U> inspected{}, grouped{};
  for (std::size_t offset{}; offset < entries_.size(); ++offset) {
    auto &entry = entries_[(first_ + offset) % entries_.size()];
    const auto level = entry.content.level;
    const auto family = level * 256U + entry.content.id[6U];
    if (!inspected[family]) {
      inspected[family] = true;
      grouped[family] = service_family(update, (first_ + offset) % entries_.size(),
          authentication, now, scratch, observer, budget, result);
      if (terminal_ != GenerationStatus::waiting) return result;
    }
    if (grouped[family] && ((entry.content.active && entry.generation.content_pending()) || entry.retirement_pending)) continue;
    const auto *owner = update.level(level);
    if (owner) {
      const auto current = owner->database().database().find(entry.content.id, now);
      if (current && current->header.sequence > entry.generation.sequence_floor())
        static_cast<void>(require_after(level, entry.content.id, current->header.sequence, now));
    }
    if (!entry.content.active) {
      const auto current = owner ? owner->database().database().find(entry.content.id, now) : std::nullopt;
      if (entry.retirement_pending && (!current || current->purge_installed)) {
        entry.retirement_pending = entry.retirement_blocked = false;
        entry.last_error = UpdateStatus::applied;
      }
      if (entry.retirement_pending && !entry.retirement_blocked && budget) {
        --budget;
        const bool live = current->header.remaining_seconds != 0U;
        if (!live) static_cast<void>(update.notify_expiration(level, entry.content.id, now, observer));
        const auto purged = live ?
            update.initiate_local_purge(level, entry.content.id, authentication[level], now,
                scratch.options, scratch.pdu, observer) :
            update.finalize_expiration(level, entry.content.id, authentication[level], now,
                scratch.options, scratch.pdu, observer);
        entry.last_error = purged.status;
        if (purged.status == UpdateStatus::applied && purged.origin.install == LspInstallResult::installed) {
          entry.retirement_pending = false;
          ++result.published;
        } else entry.retirement_blocked = true;
      }
      if (entry.retirement_blocked) ++result.blocked;
      else if (entry.retirement_pending && (!result.deadline || now < *result.deadline)) result.deadline = now;
      continue;
    }
    const auto due = entry.generation.deadline();
    if (entry.generation.sequence_exhaustion_due(now)) {
      terminal_ = result.terminal = entry.generation.prepare(now).status;
      result.deadline.reset();
      return result;
    }
    if (budget && due && *due <= now) {
      --budget;
      const auto generation = entry.generation.prepare(now);
      if (generation.status != GenerationStatus::ready) {
        terminal_ = result.terminal = generation.status;
        result.deadline.reset();
        return result;
      }
      LspBuild built;
      LevelOriginResult origin;
      const auto &key = authentication[level];
      if (!key.required || key.key) {
        const auto &program = *levels_[level];
        built = compose(entry, generation.sequence, entry.content.options, entry.content.flags, key.key, scratch);
        if (built.status == LspBuildStatus::encoded)
          origin = update.originate(level, built.bytes, now, OriginPurgeReason::none, observer,
              !entry.content.id[6U] && !entry.content.id[7U] ? program.maximum_pdu_octets : 0U);
      }
      const bool installed = origin.status == LevelStatus::applied && origin.install == LspInstallResult::installed;
      static_cast<void>(entry.generation.complete(generation.ticket, installed, now));
      entry.last_error = UpdateStatus::applied;
      if (!installed) {
        if ((key.required && !key.key) || built.status == LspBuildStatus::authentication)
          entry.last_error = UpdateStatus::authentication;
        else if (built.status == LspBuildStatus::capacity || origin.status == LevelStatus::capacity)
          entry.last_error = UpdateStatus::capacity;
        else if (!observer.event) entry.last_error = UpdateStatus::missing_observer;
        else if (built.status != LspBuildStatus::encoded || origin.status == LevelStatus::invalid_configuration)
          entry.last_error = UpdateStatus::invalid_configuration;
        else entry.last_error = UpdateStatus::level_refused;
      }
      if (installed) ++result.published;
    }
    if (entry.generation.blocked()) ++result.blocked;
    const auto next = entry.generation.deadline();
    if (next && (!result.deadline || *next < *result.deadline)) result.deadline = *next;
  }
  first_ = (first_ + 1U) % entries_.size();
  return result;
}
} // namespace router::isis
