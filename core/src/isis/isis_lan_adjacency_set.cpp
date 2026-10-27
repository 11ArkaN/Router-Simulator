// Admission preflights retained areas and candidate state before replacing a
// neighbor. Down callbacks complete before the replacement is inserted. Source:
// iso.10589.2002.adjacency_decisions, clauses 8.4.2 through 8.4.3.

#include "router/isis_lan_adjacency_set.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>
#include <type_traits>

namespace router::isis {

LanAdjacencySet::LanAdjacencySet(packet::isis::PduType type, packet::Mac local, LanSetLimits limits)
    : type_(type), local_(local), limits_(limits) {
  if (type != packet::isis::PduType::lan_hello_l1 && type != packet::isis::PduType::lan_hello_l2)
    throw std::invalid_argument("IS-IS LAN set requires an L1 or L2 LAN Hello");
  if (limits.neighbors > peers_.max_size() || limits.neighbors > candidate_scratch_.max_size() ||
      limits.areas_per_neighbor > area_scratch_.max_size())
    throw std::invalid_argument("IS-IS LAN set resource extent exceeds its container bound");
  peers_.reserve(limits.neighbors);
  candidate_scratch_.reserve(limits.neighbors);
  area_scratch_.reserve(limits.areas_per_neighbor);
  static_assert(std::is_nothrow_move_constructible_v<Peer> && std::is_nothrow_move_assignable_v<Peer>);
}

LanPeerView LanAdjacencySet::view(const Peer &peer) const noexcept {
  return {peer.adjacency.snapshot(), peer.areas};
}

std::size_t LanAdjacencySet::position(const packet::Mac &mac) const noexcept {
  return static_cast<std::size_t>(std::lower_bound(peers_.begin(), peers_.end(), mac,
      [](const Peer &peer, const packet::Mac &key) { return peer.adjacency.snapshot().mac < key; }) - peers_.begin());
}

std::optional<LanPeerView> LanAdjacencySet::find(const packet::Mac &mac) const noexcept {
  const auto index = position(mac);
  return index < peers_.size() && peers_[index].adjacency.snapshot().mac == mac ?
      std::optional(view(peers_[index])) : std::nullopt;
}

std::optional<LanPeerView> LanAdjacencySet::at(std::size_t index) const noexcept {
  return index < peers_.size() ? std::optional(view(peers_[index])) : std::nullopt;
}

std::optional<LanAdjacencySet::Clock::time_point> LanAdjacencySet::deadline() const noexcept {
  std::optional<Clock::time_point> earliest;
  for (const auto &peer : peers_) {
    const auto next = peer.adjacency.deadline();
    if (next && (!earliest || *next < *earliest)) earliest = next;
  }
  return earliest;
}

LanSetResult LanAdjacencySet::stage_areas(const packet::isis::PduView &pdu) noexcept {
  area_scratch_.clear();
  packet::isis::TlvCursor options(pdu.tlvs);
  while (const auto option = options.next()) {
    if (option->code != 1U) continue;
    packet::isis::AreaAddressCursor areas(*option);
    while (const auto area = areas.next()) {
      if (area_scratch_.size() == limits_.areas_per_neighbor) return LanSetResult::capacity_refused;
      NeighborArea retained;
      retained.length = static_cast<std::uint8_t>(area->size());
      std::copy(area->begin(), area->end(), retained.bytes.begin());
      area_scratch_.push_back(retained);
    }
    if (!areas.valid()) return LanSetResult::malformed;
  }
  return options.valid() ? LanSetResult::accepted : LanSetResult::malformed;
}

LanAdjacencySet::Peer LanAdjacencySet::remove(std::size_t index, LanEventCause cause,
    Clock::time_point now, void *context, LanPeerObserver observer) noexcept {
  auto retired = std::move(peers_[index]);
  peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(index));
  const auto before = view(retired);
  const auto update = cause == LanEventCause::expired ? retired.adjacency.expire(now) : retired.adjacency.circuit_down();
  observer(context, {before, {}, update, cause});
  return retired;
}

LanSetResult LanAdjacencySet::receive(const packet::isis::PduView &pdu, const packet::Mac &source,
    Clock::time_point now, void *context, LanPeerObserver observer) noexcept {
  if (!observer) return LanSetResult::missing_observer;
  if (pdu.type != type_) return LanSetResult::discarded;
  const auto header = packet::isis::hello(pdu);
  if (!header) return LanSetResult::malformed;
  const auto index = position(source);
  const bool existing = index < peers_.size() && peers_[index].adjacency.snapshot().mac == source;
  if (existing && peers_[index].adjacency.snapshot().system != header->source) return LanSetResult::discarded;
  const auto staged = stage_areas(pdu);
  if (staged != LanSetResult::accepted) return staged;
  if (existing) {
    auto &peer = peers_[index];
    const auto before = peer.adjacency.snapshot();
    const auto update = peer.adjacency.receive(pdu, source, now);
    if (!update.holding_refreshed) return LanSetResult::discarded;
    peer.areas.swap(area_scratch_);
    observer(context, {{before, area_scratch_}, view(peer), update, LanEventCause::received});
    return LanSetResult::accepted;
  }
  LanAdjacency adjacency(type_, header->source, source, local_);
  const auto update = adjacency.receive(pdu, source, now);
  if (!update.holding_refreshed) return LanSetResult::discarded;
  std::vector<NeighborArea> retained;
  if (peers_.size() == limits_.neighbors) {
    candidate_scratch_.clear();
    for (const auto &peer : peers_) {
      const auto snapshot = peer.adjacency.snapshot();
      candidate_scratch_.push_back({snapshot.mac, snapshot.priority});
    }
    const auto eviction = select_lan_eviction(candidate_scratch_, {source, header->priority});
    if (eviction.action != LanAdmission::evict_existing) return LanSetResult::capacity_refused;
    // All protocol Down work is synchronous on this owner. No allocation or
    // fallible input validation follows eviction, so a failure cannot remove
    // the victim while leaving an unadmitted replacement behind.
    auto retired = remove(eviction.victim, LanEventCause::capacity_evicted, now, context, observer);
    retained = std::move(retired.areas);
  } else {
    try { retained.reserve(limits_.areas_per_neighbor); }
    catch (const std::bad_alloc &) { return LanSetResult::memory_refused; }
  }
  retained.assign(area_scratch_.begin(), area_scratch_.end());
  const auto inserted = peers_.insert(peers_.begin() + static_cast<std::ptrdiff_t>(position(source)),
                                     Peer{std::move(adjacency), std::move(retained)});
  observer(context, {{}, view(*inserted), update, LanEventCause::received});
  return LanSetResult::accepted;
}

bool LanAdjacencySet::expire_one(Clock::time_point now, void *context, LanPeerObserver observer) noexcept {
  if (!observer) return false;
  for (std::size_t index = 0U; index < peers_.size(); ++index) {
    const auto deadline = peers_[index].adjacency.deadline();
    if (deadline && now >= *deadline) {
      (void)remove(index, LanEventCause::expired, now, context, observer);
      return true;
    }
  }
  return false;
}

bool LanAdjacencySet::circuit_down(void *context, LanPeerObserver observer) noexcept {
  if (!observer) return false;
  while (!peers_.empty()) (void)remove(peers_.size() - 1U, LanEventCause::circuit_down, {}, context, observer);
  return true;
}

} // namespace router::isis
