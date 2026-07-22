// RFC 6675 scoreboard implementation. Sequence values remain in wire form;
// ordering is derived from offsets to HighACK inside the bounded live window,
// so wrap at 2^32 does not require widening or renumbering the byte stream.

#include "router/tcp_sack_scoreboard.hpp"

#include "router/tcp_sequence.hpp"

#include <algorithm>
#include <limits>

namespace router::transport::tcp {
namespace {

constexpr std::uint32_t duplicate_threshold = 3U;

[[nodiscard]] bool bounded_range(std::uint32_t first,
                                 std::uint32_t end) noexcept {
  const auto length = end - first;
  return length != 0U && length <= 0x40000000U;
}

[[nodiscard]] std::uint32_t saturating_u32(std::uint64_t value) noexcept {
  return value > std::numeric_limits<std::uint32_t>::max()
             ? std::numeric_limits<std::uint32_t>::max()
             : static_cast<std::uint32_t>(value);
}

} // namespace

SackScoreboard::SackScoreboard(std::span<SackRange> ranges,
                               std::span<SackRange> workspace,
                               std::uint32_t sender_mss) noexcept
    : ranges_(ranges), workspace_(workspace), sender_mss_(sender_mss),
      valid_(!ranges.empty() && ranges.size() == workspace.size() &&
             sender_mss != 0U) {
  if (valid_) {
    std::fill(ranges_.begin(), ranges_.end(), SackRange{});
    std::fill(workspace_.begin(), workspace_.end(), SackRange{});
  }
}

bool SackScoreboard::reset(std::uint32_t high_ack,
                           std::uint32_t high_data_end) noexcept {
  if (!valid_ || high_data_end - high_ack > 0x40000000U)
    return false;
  std::fill(ranges_.begin(), ranges_.end(), SackRange{});
  count_ = 0U;
  high_ack_ = high_ack;
  high_data_end_ = high_data_end;
  high_retransmitted_end_ = high_ack;
  recovery_point_ = high_data_end;
  rescue_retransmitted_ = 0U;
  duplicate_acknowledgments_ = 0U;
  recovery_ = false;
  rescue_present_ = false;
  recovery_suppressed_ = false;
  return true;
}

bool SackScoreboard::insert_workspace(SackRange incoming,
                                      std::size_t &count,
                                      std::uint32_t base) noexcept {
  const auto incoming_first = incoming.first - base;
  std::size_t position{};
  while (position < count && workspace_[position].end - base < incoming_first)
    ++position;

  std::size_t merge_end = position;
  auto first = incoming.first;
  auto end = incoming.end;
  while (merge_end < count &&
         workspace_[merge_end].first - base <= end - base) {
    if (workspace_[merge_end].first - base < first - base)
      first = workspace_[merge_end].first;
    if (workspace_[merge_end].end - base > end - base)
      end = workspace_[merge_end].end;
    ++merge_end;
  }

  const auto removed = merge_end - position;
  if (removed == 0U && count == workspace_.size())
    return false;
  if (removed == 0U) {
    for (auto index = count; index > position; --index)
      workspace_[index] = workspace_[index - 1U];
    ++count;
  } else if (removed > 1U) {
    const auto retained_after = count - merge_end;
    for (std::size_t index = 0; index < retained_after; ++index)
      workspace_[position + 1U + index] = workspace_[merge_end + index];
    count -= removed - 1U;
  }
  workspace_[position] = {.first = first, .end = end};
  return true;
}

SackUpdateStatus SackScoreboard::update(
    std::uint32_t high_ack, std::uint32_t high_data_end,
    std::span<const SackBlock> blocks) noexcept {
  last_update_added_sack_ = false;
  if (!valid_ || sequence::before(high_ack, high_ack_) ||
      sequence::before(high_data_end, high_data_end_) ||
      sequence::after(high_ack, high_data_end) ||
      high_data_end - high_ack > 0x40000000U)
    return SackUpdateStatus::malformed;

  std::fill(workspace_.begin(), workspace_.end(), SackRange{});
  std::size_t staged{};
  // Existing advisory state survives cumulative ACK advancement only above the
  // new HighACK. Clipping is staged and cannot damage the live scoreboard.
  for (std::size_t index = 0; index < count_; ++index) {
    auto candidate = ranges_[index];
    if (sequence::before_or_equal(candidate.end, high_ack))
      continue;
    if (sequence::before(candidate.first, high_ack))
      candidate.first = high_ack;
    if (!insert_workspace(candidate, staged, high_ack))
      return SackUpdateStatus::capacity_exhausted;
  }
  std::uint64_t prior_sacked{};
  for (std::size_t index = 0; index < staged; ++index)
    prior_sacked += workspace_[index].end - workspace_[index].first;

  for (const auto &block : blocks) {
    if (!bounded_range(block.left_edge, block.right_edge) ||
        sequence::after(block.right_edge, high_data_end) ||
        sequence::after_or_equal(block.left_edge, high_data_end))
      return SackUpdateStatus::malformed;
    if (sequence::before_or_equal(block.right_edge, high_ack))
      continue;
    SackRange candidate{.first = block.left_edge,
                        .end = block.right_edge};
    if (sequence::before(candidate.first, high_ack))
      candidate.first = high_ack;
    if (!insert_workspace(candidate, staged, high_ack))
      return SackUpdateStatus::capacity_exhausted;
  }
  std::uint64_t updated_sacked{};
  for (std::size_t index = 0; index < staged; ++index)
    updated_sacked += workspace_[index].end - workspace_[index].first;
  last_update_added_sack_ = updated_sacked > prior_sacked;

  const bool cumulative_advanced = sequence::after(high_ack, high_ack_);
  bool changed = high_ack != high_ack_ || high_data_end != high_data_end_ ||
                 staged != count_;
  for (std::size_t index = 0; !changed && index < staged; ++index)
    changed = workspace_[index].first != ranges_[index].first ||
              workspace_[index].end != ranges_[index].end;

  std::copy_n(workspace_.begin(), staged, ranges_.begin());
  std::fill(ranges_.begin() + static_cast<std::ptrdiff_t>(staged),
            ranges_.end(), SackRange{});
  count_ = staged;
  high_ack_ = high_ack;
  high_data_end_ = high_data_end;
  // HighRxt and RecoveryPoint are sequence coordinates inside the current
  // [HighACK,HighData] interval. A cumulative ACK can pass their old values;
  // clamp inactive recovery markers so an empty, fully acknowledged flight has
  // one canonical checkpoint representation instead of retaining stale space.
  if (sequence::before(high_retransmitted_end_, high_ack_))
    high_retransmitted_end_ = high_ack_;
  if (cumulative_advanced)
    duplicate_acknowledgments_ = 0U;
  if (recovery_ && sequence::before_or_equal(recovery_point_, high_ack_)) {
    recovery_ = false;
    rescue_present_ = false;
  }
  if (recovery_suppressed_ &&
      sequence::before_or_equal(recovery_point_, high_ack_))
    recovery_suppressed_ = false;
  if (!recovery_ && !recovery_suppressed_ &&
      sequence::before(recovery_point_, high_ack_))
    recovery_point_ = high_ack_;
  return changed ? SackUpdateStatus::updated : SackUpdateStatus::unchanged;
}

bool SackScoreboard::is_lost(std::uint32_t target) const noexcept {
  if (!valid_ || sequence::before(target, high_ack_) ||
      !sequence::before(target, high_data_end_))
    return false;
  std::uint32_t discontiguous{};
  std::uint64_t sacked_above{};
  const auto after_target = target + 1U;
  for (std::size_t index = 0; index < count_; ++index) {
    const auto &range = ranges_[index];
    if (sequence::before_or_equal(range.end, after_target))
      continue;
    const auto first = sequence::before(range.first, after_target)
                           ? after_target
                           : range.first;
    sacked_above += range.end - first;
    if (sequence::after(range.first, target))
      ++discontiguous;
  }
  return discontiguous >= duplicate_threshold ||
         sacked_above >
             static_cast<std::uint64_t>(duplicate_threshold - 1U) *
                 sender_mss_;
}

std::uint32_t SackScoreboard::pipe() const noexcept {
  if (!valid_)
    return 0U;
  std::uint64_t result{};
  auto cursor = high_ack_;
  const auto account_unsacked = [&](std::uint32_t first,
                                    std::uint32_t end) {
    if (first == end)
      return;
    const auto length = end - first;
    if (!is_lost(first))
      result += length;
    if (sequence::before(first, high_retransmitted_end_)) {
      const auto retransmitted_end =
          sequence::before(end, high_retransmitted_end_)
              ? end
              : high_retransmitted_end_;
      result += retransmitted_end - first;
    }
  };
  for (std::size_t index = 0; index < count_; ++index) {
    account_unsacked(cursor, ranges_[index].first);
    cursor = ranges_[index].end;
  }
  account_unsacked(cursor, high_data_end_);
  return saturating_u32(result);
}

bool SackScoreboard::duplicate_ack(bool carries_new_sack) noexcept {
  if (!valid_ || recovery_ || !carries_new_sack)
    return false;
  if (duplicate_acknowledgments_ !=
      std::numeric_limits<std::uint32_t>::max())
    ++duplicate_acknowledgments_;
  // RFC 6675 permits early entry when IsLost(HighACK) already proves that at
  // least three later sequences or more than two SMSS octets arrived.
  return duplicate_acknowledgments_ >= duplicate_threshold ||
         is_lost(high_ack_);
}

std::optional<SackRange> SackScoreboard::first_unsacked_from(
    std::uint32_t start, std::uint32_t ceiling) const noexcept {
  auto cursor = sequence::before(start, high_ack_) ? high_ack_ : start;
  if (!sequence::before(cursor, ceiling))
    return std::nullopt;
  for (std::size_t index = 0; index < count_; ++index) {
    const auto &sacked = ranges_[index];
    if (sequence::before_or_equal(sacked.end, cursor))
      continue;
    if (sequence::before(cursor, sacked.first)) {
      const auto end = sequence::before(sacked.first, ceiling)
                           ? sacked.first
                           : ceiling;
      return SackRange{.first = cursor, .end = end};
    }
    cursor = sacked.end;
    if (!sequence::before(cursor, ceiling))
      return std::nullopt;
  }
  return SackRange{.first = cursor, .end = ceiling};
}

std::optional<SackRange> SackScoreboard::highest_unsacked() const noexcept {
  std::optional<SackRange> result;
  auto cursor = high_ack_;
  for (std::size_t index = 0; index < count_; ++index) {
    if (sequence::before(cursor, ranges_[index].first))
      result = SackRange{.first = cursor, .end = ranges_[index].first};
    cursor = ranges_[index].end;
  }
  if (sequence::before(cursor, high_data_end_))
    result = SackRange{.first = cursor, .end = high_data_end_};
  return result;
}

SackNextSegment SackScoreboard::next_segment(
    std::optional<SackRange> unsent) const noexcept {
  if (!valid_ || !recovery_ || count_ == 0U)
    return {};
  const auto highest_sack = ranges_[count_ - 1U].end;

  // Rule 1 may need to skip an earlier unSACKed interval that is not yet lost
  // before finding the first interval meeting all three RFC 6675 predicates.
  auto search = high_retransmitted_end_;
  while (const auto candidate = first_unsacked_from(search, highest_sack)) {
    if (is_lost(candidate->first))
      return {.range = {.first = candidate->first,
                        .end = candidate->first +
                               std::min(sender_mss_,
                                        candidate->end - candidate->first)},
              .reason = SackNextReason::lost_retransmission};
    search = candidate->end;
    if (!sequence::before(search, highest_sack))
      break;
  }

  if (unsent && unsent->first == high_data_end_ &&
      bounded_range(unsent->first, unsent->end))
    return {.range = {.first = unsent->first,
                      .end = unsent->first +
                             std::min(sender_mss_,
                                      unsent->end - unsent->first)},
            .reason = SackNextReason::new_data};

  if (const auto candidate =
          first_unsacked_from(high_retransmitted_end_, highest_sack))
    return {.range = {.first = candidate->first,
                      .end = candidate->first +
                             std::min(sender_mss_,
                                      candidate->end - candidate->first)},
            .reason = SackNextReason::unsacked_retransmission};

  if ((!rescue_present_ || sequence::after(high_ack_, rescue_retransmitted_)))
    if (const auto candidate = highest_unsacked()) {
      const auto length = std::min(sender_mss_,
                                   candidate->end - candidate->first);
      return {.range = {.first = candidate->end - length,
                        .end = candidate->end},
              .reason = SackNextReason::rescue_retransmission};
    }
  return {};
}

void SackScoreboard::enter_recovery() noexcept {
  if (!valid_ || recovery_ || recovery_suppressed_)
    return;
  recovery_ = true;
  recovery_point_ = high_data_end_;
  high_retransmitted_end_ = high_ack_;
  rescue_present_ = false;
  rescue_retransmitted_ = 0U;
  duplicate_acknowledgments_ = 0U;
}

bool SackScoreboard::commit(const SackNextSegment &segment) noexcept {
  if (!valid_ || !segment || !recovery_ ||
      !bounded_range(segment.range.first, segment.range.end))
    return false;
  if (segment.reason == SackNextReason::new_data) {
    if (segment.range.first != high_data_end_)
      return false;
    high_data_end_ = segment.range.end;
    return true;
  }
  if (sequence::before(segment.range.first, high_ack_) ||
      sequence::after(segment.range.end, high_data_end_))
    return false;
  if (segment.reason == SackNextReason::rescue_retransmission) {
    rescue_retransmitted_ = recovery_point_;
    rescue_present_ = true;
  } else if (sequence::after(segment.range.end,
                             high_retransmitted_end_)) {
    const bool initial_fast_retransmission =
        segment.reason == SackNextReason::lost_retransmission &&
        high_retransmitted_end_ == high_ack_ && !rescue_present_;
    high_retransmitted_end_ = segment.range.end;
    // RFC 6675 step 4.3 initializes both HighRxt and RescueRxt for the first
    // fast retransmission. Later rule-1 repairs advance only HighRxt.
    if (initial_fast_retransmission) {
      rescue_retransmitted_ = segment.range.end;
      rescue_present_ = true;
    }
  }
  return true;
}

void SackScoreboard::on_retransmission_timeout() noexcept {
  if (!valid_)
    return;
  std::fill(ranges_.begin(), ranges_.end(), SackRange{});
  count_ = 0U;
  recovery_ = false;
  recovery_point_ = high_data_end_;
  recovery_suppressed_ = high_ack_ != high_data_end_;
  high_retransmitted_end_ = high_ack_;
  rescue_present_ = false;
  rescue_retransmitted_ = 0U;
  duplicate_acknowledgments_ = 0U;
}

void SackScoreboard::reduce_sender_mss(std::uint32_t sender_mss) noexcept {
  if (sender_mss != 0U && sender_mss < sender_mss_)
    sender_mss_ = sender_mss;
}

SackScoreboardCheckpoint SackScoreboard::checkpoint() const {
  SackScoreboardCheckpoint state;
  state.ranges.assign(ranges_.begin(),
                      ranges_.begin() + static_cast<std::ptrdiff_t>(count_));
  state.high_ack = high_ack_;
  state.high_data_end = high_data_end_;
  state.high_retransmitted_end = high_retransmitted_end_;
  state.recovery_point = recovery_point_;
  state.rescue_retransmitted = rescue_retransmitted_;
  state.duplicate_acknowledgments = duplicate_acknowledgments_;
  state.recovery = recovery_;
  state.rescue_present = rescue_present_;
  state.recovery_suppressed = recovery_suppressed_;
  return state;
}

bool SackScoreboard::validate_checkpoint(
    const SackScoreboardCheckpoint &state,
    std::size_t capacity) noexcept {
  if (capacity == 0U || state.ranges.size() > capacity ||
      state.high_data_end - state.high_ack > 0x40000000U ||
      sequence::after(state.high_retransmitted_end,
                      state.high_data_end) ||
      sequence::before(state.high_retransmitted_end, state.high_ack) ||
      sequence::before(state.recovery_point, state.high_ack) ||
      sequence::after(state.recovery_point, state.high_data_end) ||
      (state.recovery && state.recovery_suppressed) ||
      (state.rescue_present &&
       (!state.recovery ||
        sequence::before(state.rescue_retransmitted, state.high_ack) ||
        sequence::after(state.rescue_retransmitted,
                        state.recovery_point))) ||
      (state.recovery && state.duplicate_acknowledgments != 0U))
    return false;
  for (std::size_t index = 0; index < state.ranges.size(); ++index) {
    const auto &range = state.ranges[index];
    if (!bounded_range(range.first, range.end) ||
        sequence::before(range.first, state.high_ack) ||
        sequence::after(range.end, state.high_data_end) ||
        (index != 0U &&
         !sequence::before(state.ranges[index - 1U].end, range.first)))
      return false;
  }
  return true;
}

bool SackScoreboard::restore(const SackScoreboardCheckpoint &state) noexcept {
  if (!valid_ || !validate_checkpoint(state, ranges_.size()))
    return false;
  std::fill(workspace_.begin(), workspace_.end(), SackRange{});
  std::size_t staged{};
  for (const auto &range : state.ranges) {
    if (!bounded_range(range.first, range.end) ||
        sequence::before(range.first, state.high_ack) ||
        sequence::after(range.end, state.high_data_end) ||
        !insert_workspace(range, staged, state.high_ack))
      return false;
  }
  // A canonical checkpoint is already sorted and disjoint. Merging during
  // validation must therefore preserve its record count exactly.
  if (staged != state.ranges.size())
    return false;
  std::copy_n(workspace_.begin(), staged, ranges_.begin());
  std::fill(ranges_.begin() + static_cast<std::ptrdiff_t>(staged),
            ranges_.end(), SackRange{});
  count_ = staged;
  high_ack_ = state.high_ack;
  high_data_end_ = state.high_data_end;
  high_retransmitted_end_ = state.high_retransmitted_end;
  recovery_point_ = state.recovery_point;
  rescue_retransmitted_ = state.rescue_retransmitted;
  duplicate_acknowledgments_ = state.duplicate_acknowledgments;
  recovery_ = state.recovery;
  rescue_present_ = state.rescue_present;
  recovery_suppressed_ = state.recovery_suppressed;
  return true;
}

} // namespace router::transport::tcp
