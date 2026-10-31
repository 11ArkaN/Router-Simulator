// Current local content survives LSDB aging and resource waits. Per-record
// schedules commit only after encoded local publication, never after enqueue.
// Sources: iso.10589.2002.local_lsp_generation, iso.10589.2002.lsp_composition

#include "router/isis_local_lsp_set.hpp"

#include <algorithm>
#include <stdexcept>

namespace router::isis {
namespace {
bool valid_content(std::size_t level, std::uint8_t flags, std::span<const std::uint8_t> options) noexcept {
  const auto type = flags & 3U;
  if (level > 1U || (type != 1U && type != 3U) || (level && type != 3U)) return false;
  packet::isis::TlvCursor cursor(options);
  while (const auto option = cursor.next())
    if (option->code == 7U || option->code == 10U || option->code == 13U) return false;
  return cursor.valid();
}
}
LocalLspSet::Entry::Entry(LocalLspContent value, const LocalLspLevelProgram &program,
    std::uint64_t random, RuntimeClock::time_point now)
    : content{value.level, value.id, value.flags, {}},
      generation(program.minimum_interval, program.refresh_interval, random, now) {
  content.options.reserve(program.maximum_pdu_octets - packet::isis::lsp_header_octets);
  content.options.assign(value.options.begin(), value.options.end());
}
LocalLspSet::LocalLspSet(packet::isis::SystemId local, std::uint8_t maximum_areas,
    UpdateInstanceSelector selector, LocalLspProgram program, RuntimeClock::time_point now)
    : local_(local), maximum_areas_(maximum_areas), selector_(selector), levels_(program.levels) {
  if (!maximum_areas || maximum_areas == 255U || !program.random ||
      selector.format > packet::isis::InstanceFormat::standard || program.current.empty())
    throw std::invalid_argument("Invalid IS-IS local LSP program");
  for (const auto &level : levels_) if (level && (!level->maximum_age ||
      level->maximum_pdu_octets < packet::isis::lsp_header_octets ||
      level->refresh_interval >= std::chrono::seconds{level->maximum_age}))
    throw std::invalid_argument("Invalid IS-IS local LSP lifetime or buffer");
  std::sort(program.current.begin(), program.current.end(), [](const auto &left, const auto &right) {
    return left.level != right.level ? left.level < right.level : left.id < right.id;
  });
  std::array<bool, 2U> roots{};
  entries_.reserve(program.current.size());
  for (auto &content : program.current) {
    if (!valid_content(content.level, content.flags, content.options) || !levels_[content.level] ||
        !std::equal(local_.begin(), local_.end(), content.id.begin()) ||
        content.options.size() > levels_[content.level]->maximum_pdu_octets - packet::isis::lsp_header_octets ||
        find(content.level, content.id))
      throw std::invalid_argument("Invalid or duplicate current local IS-IS LSP");
    roots[content.level] = roots[content.level] || (!content.id[6U] && !content.id[7U]);
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
    return entry.content.level == level && entry.content.id == id;
  });
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
LocalContentResult LocalLspSet::replace(std::size_t level, const packet::isis::LspId &id,
    std::uint8_t flags, std::span<const std::uint8_t> options, RuntimeClock::time_point now) noexcept {
  auto *entry = find(level, id);
  if (!entry) return LocalContentResult::missing;
  if (!valid_content(level, flags, options)) return LocalContentResult::invalid;
  if (options.size() > levels_[level]->maximum_pdu_octets - packet::isis::lsp_header_octets)
    return LocalContentResult::capacity;
  if (entry->content.flags == flags && std::ranges::equal(entry->content.options, options))
    return LocalContentResult::unchanged;
  // Public inputs must not borrow this private vector. Its reserved capacity
  // bounds replacement; no allocation or invalidation of a published view occurs.
  entry->content.options.assign(options.begin(), options.end());
  entry->content.flags = flags;
  entry->generation.changed(now);
  entry->generation.retry();
  return LocalContentResult::changed;
}
bool LocalLspSet::require_after(std::size_t level, const packet::isis::LspId &id,
    std::uint32_t sequence, RuntimeClock::time_point now) noexcept {
  auto *entry = find(level, id);
  if (!entry) return false;
  entry->generation.require_after(sequence, now);
  return true;
}
void LocalLspSet::retry(std::size_t level) noexcept {
  for (auto &entry : entries_) if (entry.content.level == level) entry.generation.retry();
}
LocalContentResult LocalLspSet::waiting_overload(std::size_t level, bool enabled, RuntimeClock::time_point now) noexcept {
  if (level >= levels_.size() || !levels_[level]) return LocalContentResult::missing;
  if (waiting_overload_[level] == enabled) return LocalContentResult::unchanged;
  packet::isis::LspId root{};
  std::copy(local_.begin(), local_.end(), root.begin());
  auto *entry = find(level, root);
  if (!entry) return LocalContentResult::missing;
  waiting_overload_[level] = enabled;
  entry->generation.changed(now);
  entry->generation.retry();
  return LocalContentResult::changed;
}
LocalGenerationResult LocalLspSet::service(InstanceUpdateProcess &update,
    std::array<TransmitAuthentication, 2U> authentication, RuntimeClock::time_point now,
    PduScratch &scratch, LevelObserver observer, std::size_t &budget) noexcept {
  LocalGenerationResult result;
  result.terminal = terminal_;
  if (terminal_ != GenerationStatus::waiting) return result;
  const std::array<std::uint16_t, 1U> topology{0U};
  for (std::size_t offset{}; offset < entries_.size(); ++offset) {
    auto &entry = entries_[(first_ + offset) % entries_.size()];
    const auto level = entry.content.level;
    const auto *owner = update.level(level);
    if (owner) {
      const auto current = owner->database().database().find(entry.content.id, now);
      if (current && current->header.sequence > entry.generation.committed_sequence())
        entry.generation.require_after(current->header.sequence, now);
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
        LspContents contents;
        contents.header = {level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1,
            entry.content.id, program.maximum_age, generation.sequence, entry.content.flags, maximum_areas_};
        if (waiting_overload_[level] && !entry.content.id[6U] && !entry.content.id[7U])
          contents.header.flags |= 4U; // ISO LSP Database Overload bit, independent of the configured flag.
        contents.options = entry.content.options;
        contents.authentication = key.key;
        contents.maximum_pdu_octets = program.maximum_pdu_octets;
        if (selector_.wire_instance || selector_.format == packet::isis::InstanceFormat::legacy_2009)
          contents.instance = PduInstanceOption{selector_.format, selector_.wire_instance,
              selector_.format == packet::isis::InstanceFormat::standard ? std::span<const std::uint16_t>(topology) :
                  std::span<const std::uint16_t>{}};
        built = build_lsp_pdu(contents, scratch.options, scratch.pdu);
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
