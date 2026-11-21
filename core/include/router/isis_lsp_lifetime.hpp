// ISO 10589 7.3.16.3 lifetime arithmetic belongs to each encoded LSP owner.
// This value has no clock or mutable shared state. Callers supply elapsed
// holding time and the estimated transit duration at their ownership boundary.

#pragma once

#include "router/isis_ethernet.hpp"
#include "router/protocol_frame_expiry.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>

namespace router::isis {
// Only an explicitly finalized purge may produce zero. A live LSP that
// cannot survive the budget returns nullopt: only its instance owner may build
// the authenticated purge. Negative durations reject without producing bytes.
// Holding time consumes complete seconds; transit rounds upward and consumes
// at least one second. Division precedes addition to avoid duration overflow.
[[nodiscard]] constexpr std::optional<std::uint16_t> lsp_transmission_lifetime(
    std::uint16_t remaining, std::chrono::nanoseconds holding,
    std::chrono::nanoseconds transit, bool finalized_purge = false) noexcept {
  if (holding.count() < 0 || transit.count() < 0) return std::nullopt;
  if (finalized_purge) return remaining ? std::nullopt : std::optional<std::uint16_t>{0U};
  if (!remaining) return std::nullopt;
  constexpr std::int64_t second = 1'000'000'000;
  const auto held = holding.count() / second;
  const auto estimated = transit.count() / second + (transit.count() % second != 0);
  const auto decrement = held + std::max<std::int64_t>(1, estimated);
  if (decrement >= remaining) return std::nullopt;
  return static_cast<std::uint16_t>(remaining - decrement);
}
// Quiescent coordinator validation. A descriptor may rewrite only the lifetime
// of a live encoded LSP, including its actual VLAN/LLC offset. Empty descriptors
// remain valid for ordinary traffic and finalized purges. Views never escape.
[[nodiscard]] inline bool valid_queued_lsp_expiry(std::span<const std::uint8_t> bytes,
    const protocol::FrameExpiryCheckpoint &expiry) noexcept {
  if (!protocol::FrameExpiry::restore(expiry, {})) return false;
  if (!expiry.offset) return true;
  packet::isis::EthernetDecodeError error{};
  const auto wire = packet::isis::parse_ethernet_pdu(bytes, error);
  const auto header = wire ? packet::isis::lsp(wire->pdu) : std::nullopt;
  return header && header->remaining_seconds && expiry.offset ==
      static_cast<std::size_t>(wire->pdu.bytes.data() - bytes.data()) + 10U;
}
} // namespace router::isis
