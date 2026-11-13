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
[[nodiscard]] inline std::optional<std::size_t> collect_area_addresses(
    const LinkStateDatabase &database, const P2pRouteDecision &decision,
    RuntimeClock::time_point now, std::span<NeighborArea> output) noexcept {
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
// Requires a revision-matched L2 SPF and canonical local area set. The result
// covers ISO 10589 7.2.9.2's reachable-other-area condition. CLNS address-prefix
// attachment is a separate condition and must not be inferred from IP prefixes.
// Malformed area options cannot supply evidence of another reachable area.
[[nodiscard]] inline bool reachable_other_area(const LinkStateDatabase &database,
    const P2pRouteDecision &decision, std::span<const NeighborArea> local,
    RuntimeClock::time_point now) noexcept {
  if (local.empty()) return false;
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto record = database.at(index, now);
    if (!record || record->pdu.type != packet::isis::PduType::lsp_l2 ||
        record->header.id[6U] || record->header.id[7U] || !record->header.remaining_seconds ||
        !record->header.sequence || !record->header.checksum) continue;
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
}
