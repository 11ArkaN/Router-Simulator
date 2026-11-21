// The instance control owner derives ISO area attachment from its current L2
// database and completed family-independent SPF. Borrowed inputs remain immutable;
// no device registry, editor topology, allocation or persistent state is used.
// Source: iso.10589.2002.attached_default
#pragma once
#include "router/isis_p2p_decision.hpp"
#include "router/isis_neighbor_attributes.hpp"
#include "router/isis_basic_tlvs.hpp"
#include <algorithm>
namespace router::isis {
// ISO 10589 7.2.11 unions reachable L1 root area lists, retaining the
// maximumAreaAddresses numerically lowest distinct values. The caller supplies
// exactly that many slots. No allocation; invalid framing contributes no area.
// The output prefix is sorted and owned by the caller; nullopt rejects a wrong
// database level or empty capacity. Inputs require a matching completed L1 SPF.
// The optional visitor observes every validated reachable area before bounded
// selection, including duplicates and rejected high addresses. It must not
// throw or retain views; mutations remain unpublished caller-owned scratch.
template <typename Visit>
[[nodiscard]] inline std::optional<std::size_t> collect_area_addresses(
    const LinkStateDatabase &database, const P2pRouteDecision &decision,
    RuntimeClock::time_point now, std::span<NeighborArea> output, Visit visit) noexcept {
  if (output.empty()) return {};
  std::size_t count{};
  const auto less = [](const NeighborArea &a, const NeighborArea &b) {
    return std::lexicographical_compare(a.view().begin(), a.view().end(), b.view().begin(), b.view().end());
  };
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto record = database.at(index, now);
    if (!record) continue;
    if (record->pdu.type != packet::isis::PduType::lsp_l1) return {};
    if (record->header.id[6U] || record->header.id[7U] || !record->header.remaining_seconds ||
        !record->header.sequence || !record->header.checksum) continue;
    packet::isis::LanId root{};
    std::copy_n(record->header.id.begin(), root.size(), root.begin());
    if (!decision.cost(root)) continue;
    packet::isis::TlvCursor framing(record->pdu.tlvs);
    while (framing.next()) {}
    if (!framing.valid()) continue;
    packet::isis::TlvCursor options(record->pdu.tlvs);
    while (const auto option = options.next()) if (option->code == 1U) {
      packet::isis::AreaAddressCursor check(*option);
      while (check.next()) {}
      if (!check.valid()) continue;
      packet::isis::AreaAddressCursor areas(*option);
      while (const auto value = areas.next()) {
        NeighborArea candidate{}; candidate.length = static_cast<std::uint8_t>(value->size());
        std::copy(value->begin(), value->end(), candidate.bytes.begin());
        visit(candidate);
        const auto position = std::lower_bound(output.begin(), output.begin() + count, candidate, less);
        const auto offset = static_cast<std::size_t>(position - output.begin());
        if ((offset < count && output[offset] == candidate) || offset == output.size()) continue;
        const auto next = std::min(count + 1U, output.size());
        std::move_backward(output.begin() + offset, output.begin() + next - 1U, output.begin() + next);
        output[offset] = candidate; count = next;
      }
    }
  }
  return count;
}
[[nodiscard]] inline std::optional<std::size_t> collect_area_addresses(
    const LinkStateDatabase &database, const P2pRouteDecision &decision,
    RuntimeClock::time_point now, std::span<NeighborArea> output) noexcept {
  return collect_area_addresses(database, decision, now, output, [](const NeighborArea &) noexcept {});
}
// Requires a revision-matched L2 SPF and canonical local area set. The result
// covers ISO 10589 7.2.9.2's reachable-other-area condition. CLNS address-prefix
// attachment is a separate condition and must not be inferred from IP prefixes.
// Malformed area options cannot supply evidence of another reachable area.
[[nodiscard]] inline bool reachable_other_area(const LinkStateDatabase &database,
    const P2pRouteDecision &decision, std::span<const NeighborArea> local,
    RuntimeClock::time_point now, const packet::isis::SystemId &local_system) noexcept {
  if (local.empty()) return false;
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto record = database.at(index, now);
    if (!record || record->pdu.type != packet::isis::PduType::lsp_l2 ||
        record->header.id[6U] || record->header.id[7U] || !record->header.remaining_seconds ||
        !record->header.sequence || !record->header.checksum) continue;
    // Own L2 metadata can lag an L1 area recomputation. It cannot supply
    // evidence that a remote area is reachable through the L2 topology.
    if (std::equal(local_system.begin(), local_system.end(), record->header.id.begin())) continue;
    packet::isis::LanId root{};
    std::copy_n(record->header.id.begin(), root.size(), root.begin());
    if (!decision.cost(root)) continue;
    bool other{};
    packet::isis::TlvCursor options(record->pdu.tlvs);
    while (const auto option = options.next()) if (option->code == 1U) {
      packet::isis::AreaAddressCursor areas(*option);
      bool candidate{};
      while (const auto area = areas.next())
        candidate = candidate || std::none_of(local.begin(), local.end(), [&](const auto &ours) {
          return std::ranges::equal(ours.view(), *area);
        });
      if (areas.valid()) other = other || candidate;
    }
    if (options.valid() && other) return true;
  }
  return false;
}
// Both decisions must match their databases at now. The caller owns revision
// validation. A missing result rejects invalid area capacity or L1 database;
// false is a valid suppressed or unattached result. No state is modified.
[[nodiscard]] inline std::optional<bool> derive_area_attachment(
    const LinkStateDatabase &level1, const P2pRouteDecision &decision1,
    const LinkStateDatabase &level2, const P2pRouteDecision &decision2,
    std::uint8_t maximum_areas, bool suppress, RuntimeClock::time_point now,
    const packet::isis::SystemId &local_system) noexcept {
  std::array<NeighborArea, 255U> areas{};
  const auto count = collect_area_addresses(level1, decision1, now,
      std::span{areas}.first(maximum_areas));
  if (!count) return {};
  return !suppress && reachable_other_area(level2, decision2,
      std::span{areas}.first(*count), now, local_system);
}

}
