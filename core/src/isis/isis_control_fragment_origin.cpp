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
  if (origin.prefixes) {
    if (origin.prefixes->units.size() > std::numeric_limits<std::size_t>::max() - units)
      throw std::invalid_argument("IS-IS prefix unit budget overflow");
    units += origin.prefixes->units.size();
  }
  if (origin.ipv6_addresses) {
    if (origin.ipv6_addresses->units.size() > std::numeric_limits<std::size_t>::max() - units)
      throw std::invalid_argument("IS-IS IPv6 address unit budget overflow");
    units += origin.ipv6_addresses->units.size();
  }
  // Base records may contain many independently movable TLVs. Reserving only
  // one unit per LSP would undercount the cold workspace after splitting them.
  for (const auto &record : origin.content.records) {
    if (record.id[6U] || !record.active) continue;
    packet::isis::TlvCursor cursor(record.options);
    std::size_t count{};
    while (cursor.next()) ++count;
    if (!cursor.valid()) throw std::invalid_argument("Malformed IS-IS root metadata");
    if (count > 1U) {
      if (count - 1U > std::numeric_limits<std::size_t>::max() - units)
        throw std::invalid_argument("IS-IS root metadata unit budget overflow");
      units += count - 1U;
    }
  }
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
    const auto area_identity = make_area_set(program);
    static_cast<void>(area_identity);
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
    if (origin.prefixes) {
      if (!valid_local_prefix_catalog(*origin.prefixes)) return ControlError::invalid_argument;
      for (const auto &unit : origin.prefixes->units)
        if (!program.levels[unit.level] || !origin.content.levels[unit.level]) return ControlError::invalid_argument;
    }
    if (origin.ipv6_addresses && (!origin.prefixes ||
        !valid_local_ipv6_address_catalog(*origin.ipv6_addresses, *origin.prefixes))) return ControlError::invalid_argument;
    // Managed assignment metadata has exactly one owner. Static TLV232 would
    // bypass DAD gates, so refuse overlapping base content before publication.
    if (origin.ipv6_addresses) for (const auto &record : records) if (!record.id[6U]) {
      packet::isis::TlvCursor options(record.options);
      while (const auto option = options.next()) if (option->code == 232U) return ControlError::invalid_argument;
      if (!options.valid()) return ControlError::invalid_argument;
    }
    auto workspace = make_fragment_workspace(program);
    packet::isis::LanId source{};
    std::copy(program.local.begin(), program.local.end(), source.begin());
    for (std::size_t level{}; level < 2U; ++level) if (origin.content.levels[level]) {
      std::array<std::uint8_t, 257U> area_bytes{};
      std::array<NeighborArea, configuration_profile::area_addresses_maximum> worst_areas{};
      std::optional<std::span<const std::uint8_t>> area_override;
      if (level == 1U && origin.automatic_area_set) {
        for (std::size_t index{}; index < program.maximum_areas; ++index) {
          worst_areas[index].length = packet::isis::maximum_area_octets;
          worst_areas[index].bytes.back() = static_cast<std::uint8_t>(index);
        }
        const auto size = encode_area_set_options(std::span{worst_areas}.first(program.maximum_areas), area_bytes);
        if (!size) return ControlError::capacity;
        area_override = std::span<const std::uint8_t>{area_bytes}.first(*size);
      }
      if (!workspace->add_root_options(origin.content, level, area_override)) return ControlError::capacity;
      if (origin.prefixes) {
        const bool prefixes_valid = origin.ipv6_addresses
            ? append_local_af_prefixes(*workspace, *origin.prefixes, *origin.ipv6_addresses, level, true)
            : append_local_prefix_catalog(*workspace, *origin.prefixes, level, true);
        if (!prefixes_valid) return ControlError::capacity;
        if (origin.ipv6_addresses && !append_local_ipv6_addresses(*workspace, *origin.ipv6_addresses, *origin.prefixes, true))
          return ControlError::capacity;
      }
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
