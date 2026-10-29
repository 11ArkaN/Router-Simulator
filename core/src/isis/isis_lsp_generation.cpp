// ISO 10589 7.3.5/7.3.6 separates periodic refresh from content-driven work.
// One LSP's sequence advances only after local publication. Failed composition
// or admission never consumes a sequence or polls an unserviceable deadline.

#include "router/isis_lsp_generation.hpp"
#include "router/isis_jitter.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace router::isis {
namespace {
RuntimeClock::time_point after(RuntimeClock::time_point now, std::chrono::microseconds interval) noexcept {
  const auto duration = std::chrono::duration_cast<RuntimeClock::duration>(interval);
  return now > RuntimeClock::time_point::max() - duration ? RuntimeClock::time_point::max() : now + duration;
}
}
LspGenerationSchedule::LspGenerationSchedule(std::chrono::microseconds minimum_interval,
    std::chrono::microseconds refresh_interval, std::uint64_t random, RuntimeClock::time_point now)
    : minimum_(minimum_interval), refresh_(refresh_interval), random_(random),
      refresh_at_(now), changed_at_(now), hold_until_(now) {
  // Protocol lifetime fields bound useful refresh intervals well below this
  // clock-conversion bound. Reject rather than overflow on malformed programs.
  const auto maximum = std::chrono::duration_cast<std::chrono::microseconds>(RuntimeClock::duration::max());
  if (!random || minimum_.count() <= 0 || refresh_.count() <= 0 || refresh_ > maximum ||
      minimum_ > refresh_ - refresh_ / 4)
    throw std::invalid_argument("Invalid IS-IS LSP generation intervals");
  refresh_at_ = after(now, *jittered_interval(refresh_, random_));
}
void LspGenerationSchedule::changed(RuntimeClock::time_point now) noexcept {
  if (!dirty_) changed_at_ = now;
  dirty_ = true;
  if (pending_) changed_during_pending_ = true;
}
void LspGenerationSchedule::require_after(std::uint32_t sequence, RuntimeClock::time_point now) noexcept {
  observed_ = std::max(observed_, sequence);
  changed(now);
}
std::optional<RuntimeClock::time_point> LspGenerationSchedule::deadline() const noexcept {
  if (pending_ || blocked_ || stopped_) return std::nullopt;
  return std::max(hold_until_, dirty_ ? std::min(changed_at_, refresh_at_) : refresh_at_);
}
LspGeneration LspGenerationSchedule::prepare(RuntimeClock::time_point now) noexcept {
  const auto due = deadline();
  if (!due || *due > now) return {};
  const auto previous = std::max(committed_, observed_);
  if (previous == std::numeric_limits<std::uint32_t>::max()) {
    stopped_ = true;
    return {GenerationStatus::sequence_exhausted, 0U, 0U};
  }
  if (tickets_ == std::numeric_limits<std::uint64_t>::max()) {
    stopped_ = true;
    return {GenerationStatus::ticket_exhausted, 0U, 0U};
  }
  if (refresh_at_ <= now) refresh_at_ = after(now, *jittered_interval(refresh_, random_));
  pending_ = LspGeneration{GenerationStatus::ready, previous + 1U, ++tickets_};
  changed_during_pending_ = false;
  return *pending_;
}
bool LspGenerationSchedule::complete(std::uint64_t ticket, bool installed, RuntimeClock::time_point now) noexcept {
  if (!pending_ || pending_->ticket != ticket) return false;
  if (installed) {
    committed_ = pending_->sequence;
    dirty_ = changed_during_pending_ || observed_ > committed_;
    changed_at_ = now;
    hold_until_ = after(now, minimum_);
  } else {
    dirty_ = true;
    blocked_ = true;
  }
  pending_.reset();
  return true;
}
} // namespace router::isis
