// Cold local-catalog admission and derived fragment workspace construction.
// The instance control owner reserves identities within its explicit emulator
// LSDB record budget. No SR OS platform limit or remote adjacency is inferred.
#include "router/isis_control_worker.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
namespace router::isis {
std::unique_ptr<OriginFragmentWorkspace> ControlWorker::make_fragment_workspace(const UpdateInstanceProgram &program) {
  const auto &origin = *program.origination;
  auto units = origin.content.records.size();
  for (const auto count : {origin.neighbors ? origin.neighbors->size() : 0U,
      origin.broadcast_neighbors ? origin.broadcast_neighbors->size() : 0U}) {
    if (count > std::numeric_limits<std::size_t>::max() - units)
      throw std::invalid_argument("IS-IS fragment unit budget overflow");
    units += count;
  }
  if (origin.broadcast_neighbors) for (const auto &entry : *origin.broadcast_neighbors) {
    if (entry.maximum_neighbors == std::numeric_limits<std::size_t>::max())
      throw std::invalid_argument("IS-IS pseudonode unit budget overflow");
    units = std::max(units, entry.maximum_neighbors + 1U);
  }
  std::array<std::size_t, 512U> counts{};
  std::size_t fragments{}, semantic{};
  for (const auto &record : origin.content.records) {
    if (record.level > 1U) throw std::invalid_argument("Invalid IS-IS fragment level");
    fragments = std::max(fragments, ++counts[record.level * 256U + record.id[6U]]);
  }
  for (const auto &level : origin.content.levels) if (level) {
    if (level->maximum_pdu_octets < packet::isis::lsp_header_octets)
      throw std::invalid_argument("Invalid IS-IS fragment buffer");
    semantic = std::max(semantic, static_cast<std::size_t>(level->maximum_pdu_octets - packet::isis::lsp_header_octets));
  }
  return std::make_unique<OriginFragmentWorkspace>(units, fragments, semantic);
}
ControlError ControlWorker::prepare_fragment_origination(UpdateInstanceProgram &program) noexcept {
  try {
    auto &origin = *program.origination;
    auto &records = origin.content.records;
    for (std::size_t level{}; level < 2U; ++level) if (program.levels[level]) {
      std::array<bool, 256U> present{};
      std::size_t roots{}, pseudonodes{};
      std::uint8_t flags{};
      for (const auto &record : records) if (record.level == level) {
        if (record.id[6U]) ++pseudonodes;
        else {
          if (present[record.id[7U]]) return ControlError::invalid_argument;
          present[record.id[7U]] = true;
          ++roots;
          if (!record.id[7U]) flags = static_cast<std::uint8_t>(record.flags & 3U);
        }
      }
      const auto budget = program.levels[level]->database.records;
      if (pseudonodes > budget) return ControlError::capacity;
      const auto reserved = std::min(std::size_t{256U}, budget - pseudonodes);
      if (!present[0U] || roots > reserved) return ControlError::capacity;
      // Unused IDs carry no LSDB body or flood flags. They reserve only local
      // semantic/preparation capacity and counters for later same-owner reuse.
      for (std::size_t number{}; roots < reserved && number < present.size(); ++number) if (!present[number]) {
        packet::isis::LspId id{};
        std::copy(program.local.begin(), program.local.end(), id.begin());
        id[7U] = static_cast<std::uint8_t>(number);
        records.push_back({static_cast<std::uint8_t>(level), id, flags, {}, false});
        ++roots;
      }
    }
    std::sort(records.begin(), records.end(), [](const auto &a, const auto &b) {
      return a.level != b.level ? a.level < b.level : a.id < b.id;
    });
    auto workspace = make_fragment_workspace(program);
    packet::isis::LanId source{};
    std::copy(program.local.begin(), program.local.end(), source.begin());
    for (std::size_t level{}; level < 2U; ++level) if (origin.content.levels[level]) {
      std::uint64_t metadata{};
      for (const auto &record : records) if (record.level == level && !record.id[6U] && record.active && !record.options.empty())
        if (!workspace->add_options({0U, metadata++}, record.options, record.id[7U], !record.id[7U])) return ControlError::capacity;
      // These sizing-only zero IDs are never admitted or emitted. Their real
      // configured metrics determine exact wide/narrow unit lengths. Actual
      // runtime units always come from this owner's accepted circuit snapshots.
      if (origin.neighbors) for (const auto &entry : *origin.neighbors) if (entry.levels[level])
        if (!workspace->add_link({1U, entry.interface_id}, {}, *entry.levels[level], {})) return ControlError::capacity;
      if (origin.broadcast_neighbors) for (const auto &entry : *origin.broadcast_neighbors) if (entry.levels[level])
        if (!workspace->add_link({2U, entry.interface_id}, {0U, 0U, 0U, 0U, 0U, 0U, 1U}, *entry.levels[level], {})) return ControlError::capacity;
      std::array<std::uint8_t, 256U> scratch{};
      const auto slots = local_fragment_slots(origin.content, level, source, scratch);
      const auto planned = workspace->validate(slots, origin.content.levels[level]->maximum_pdu_octets - packet::isis::lsp_header_octets);
      if (planned != LocalContentResult::unchanged)
        return planned == LocalContentResult::capacity ? ControlError::capacity : ControlError::invalid_argument;
    }
    return ControlError::none;
  } catch (const std::bad_alloc &) { return ControlError::capacity; }
    catch (const std::length_error &) { return ControlError::capacity; }
    catch (const std::invalid_argument &) { return ControlError::invalid_argument; }
}
}
