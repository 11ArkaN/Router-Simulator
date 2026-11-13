// ISO 10589 7.3.15.6 and 10.1: periodic random SRM choice and queued-input
// inhibition belong to the LAN control owner. Physical receipt commits spacing;
// this module cannot modify flood flags or inspect another router's state.

#include "router/isis_broadcast_scan.hpp"

#include <algorithm>
#include <stdexcept>
#include <limits>

namespace router::isis {
namespace {
BroadcastScan::Clock::time_point later(BroadcastScan::Clock::time_point now,
    std::chrono::microseconds interval) noexcept {
  const auto duration = std::chrono::duration_cast<BroadcastScan::Clock::duration>(interval);
  return now > BroadcastScan::Clock::time_point::max() - duration
      ? BroadcastScan::Clock::time_point::max() : now + duration;
}
}
BroadcastScan::BroadcastScan(std::chrono::microseconds interval, std::uint64_t seed,
    Clock::time_point now) : interval_(interval), random_(seed) {
  if (interval.count() <= 0 || interval > std::chrono::milliseconds{65535} || !seed)
    throw std::invalid_argument("Invalid IS-IS broadcast scan program");
  periodic_ = later(now, *jittered_interval(interval_, random_));
}
bool BroadcastScan::activate(Clock::time_point now) noexcept {
  if (pending_) return false;
  periodic_ = later(now, *jittered_interval(interval_, random_));
  return true;
}
std::optional<std::size_t> BroadcastScan::begin(Clock::time_point now,
    std::size_t candidates, bool ingress_pending) noexcept {
  if (now < periodic_ || now == Clock::time_point::max()) return std::nullopt;
  periodic_ = later(now, *jittered_interval(interval_, random_));
  if (pending_ || !candidates || (ingress_pending && last_sent_ &&
      now < later(*last_sent_, std::chrono::seconds{1}))) return std::nullopt;
  pending_ = true;
  return static_cast<std::size_t>(*random_below(candidates, random_));
}
BroadcastSelection BroadcastScan::begin(Clock::time_point now,
    std::array<BroadcastLevel, 2U> levels, bool ingress_pending) noexcept {
  std::array<std::size_t, 2U> counts{};
  for (std::size_t level{}; level < levels.size(); ++level) if (levels[level].database) {
    const auto &database = *levels[level].database;
    const auto expected = level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1;
    const auto count = database.broadcast_srm_count(levels[level].circuit);
    if (database.type() != expected || !count) return {BroadcastScanStatus::invalid_catalog};
    counts[level] = *count;
  }
  if (counts[1U] > std::numeric_limits<std::size_t>::max() - counts[0U])
    return {BroadcastScanStatus::invalid_catalog};
  const auto selected = begin(now, counts[0U] + counts[1U], ingress_pending);
  if (!selected) return {};
  const auto level = *selected < counts[0U] ? std::size_t{0U} : std::size_t{1U};
  const auto ordinal = *selected - (level ? counts[0U] : 0U);
  const auto id = levels[level].database->broadcast_srm_at(levels[level].circuit, ordinal);
  if (!id) { static_cast<void>(complete(false, now)); return {BroadcastScanStatus::invalid_catalog}; }
  return {BroadcastScanStatus::selected, BroadcastCandidate{level, *id}};
}
bool BroadcastScan::complete(bool enqueued, Clock::time_point now) noexcept {
  if (!pending_) return false;
  pending_ = false;
  if (enqueued) last_sent_ = now;
  return true;
}
BroadcastScan::Clock::time_point BroadcastScan::deadline(bool ingress_pending) const noexcept {
  if (pending_) return Clock::time_point::max();
  return ingress_pending && last_sent_ ? std::max(periodic_, later(*last_sent_, std::chrono::seconds{1})) : periodic_;
}
} // namespace router::isis
