// LAN two-way state follows the received neighbor MAC list independently for
// each level. Only the dedicated protocol owner may mutate this record.
// Source: iso.10589.2002.adjacency_decisions

#include "router/isis_lan_adjacency.hpp"

#include <stdexcept>

namespace router::isis {

LanAdjacency::LanAdjacency(packet::isis::PduType type, packet::isis::SystemId peer,
    packet::Mac peer_mac, packet::Mac local_mac)
    : type_(type), peer_(peer), peer_mac_(peer_mac), local_mac_(local_mac) {
  if (type != packet::isis::PduType::lan_hello_l1 && type != packet::isis::PduType::lan_hello_l2)
    throw std::invalid_argument("IS-IS LAN adjacency requires an L1 or L2 LAN Hello");
}

std::optional<LanAdjacency::Clock::time_point> LanAdjacency::deadline() const noexcept {
  return state_.present ? std::optional(holding_deadline_) : std::nullopt;
}

LanUpdate LanAdjacency::remove(LanReason reason) noexcept {
  state_ = {};
  holding_deadline_ = {};
  return {LanOutcome::down, reason, false};
}

LanUpdate LanAdjacency::expire(Clock::time_point now) noexcept {
  return state_.present && now >= holding_deadline_ ? remove(LanReason::holding_expired) : LanUpdate{};
}

LanUpdate LanAdjacency::circuit_down() noexcept {
  return state_.present ? remove(LanReason::circuit_down) : LanUpdate{};
}

LanUpdate LanAdjacency::receive(const packet::isis::PduView &pdu,
    const packet::Mac &source, Clock::time_point now) noexcept {
  if (pdu.type != type_) return {LanOutcome::discarded, LanReason::malformed};
  const auto hello = packet::isis::hello(pdu);
  if (!hello) return {LanOutcome::discarded, LanReason::malformed};
  if (hello->source != peer_ || source != peer_mac_) return {LanOutcome::discarded, LanReason::different_peer};
  bool seen_local{};
  packet::isis::TlvCursor cursor(pdu.tlvs);
  while (const auto tlv = cursor.next()) {
    if (tlv->code != 6U) continue;
    packet::isis::FixedAddressCursor<6U> neighbors(*tlv, 6U);
    while (const auto neighbor = neighbors.next()) seen_local = seen_local || *neighbor == local_mac_;
    if (!neighbors.valid()) return {LanOutcome::discarded, LanReason::malformed};
  }
  if (!cursor.valid()) return {LanOutcome::discarded, LanReason::malformed};
  const bool was_up = state_.present && state_.state == LanState::up;
  state_ = {peer_, peer_mac_, hello->designated_id, hello->priority,
             seen_local ? LanState::up : LanState::initializing, true};
  holding_deadline_ = now + std::chrono::seconds(hello->holding_seconds);
  if (seen_local && !was_up) return {LanOutcome::up, LanReason::none, true};
  if (!seen_local && was_up) return {LanOutcome::down, LanReason::one_way, true};
  return {seen_local ? LanOutcome::accepted : LanOutcome::initializing, LanReason::none, true};
}

} // namespace router::isis
