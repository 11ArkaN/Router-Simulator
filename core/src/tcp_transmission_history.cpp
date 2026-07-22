// Admitted-segment history implementation. Serial comparisons are valid
// because every retained record and the complete live history stay inside the
// same 2^30 sequence-space bound as the owning send repository.

#include "router/tcp_transmission_history.hpp"

#include "router/tcp_sequence.hpp"

#include <algorithm>

namespace router::transport::tcp {
namespace {

[[nodiscard]] bool valid_range(std::uint32_t first,
                               std::uint32_t end) noexcept {
  const auto length = end - first;
  return length != 0U && length <= 0x40000000U;
}

[[nodiscard]] bool overlaps(std::uint32_t left_first,
                            std::uint32_t left_end,
                            std::uint32_t right_first,
                            std::uint32_t right_end) noexcept {
  // All ranges share one bounded live sequence domain. The usual half-open
  // test can therefore use RFC serial ordering even when values wrap at 2^32.
  return sequence::before(left_first, right_end) &&
         sequence::before(right_first, left_end);
}

} // namespace

TransmissionHistory::TransmissionHistory(
    std::span<TransmissionRecord> records) noexcept
    : records_(records), valid_(!records.empty()) {
  // Stale caller storage cannot become observable through a zero-count ring.
  // Clearing it also makes checkpoints and owner diagnostics deterministic.
  if (valid_)
    std::fill(records_.begin(), records_.end(), TransmissionRecord{});
}

std::size_t TransmissionHistory::physical(std::size_t logical) const noexcept {
  return (head_ + logical) % records_.size();
}

bool TransmissionHistory::record_original(std::uint32_t first,
                                          std::uint32_t end,
                                          Clock::time_point now) noexcept {
  if (!can_record_original(first, end, now))
    return false;
  records_[physical(count_++)] = {.first_transmitted_at = now,
                                  .last_transmitted_at = now,
                                  .first = first,
                                  .end = end};
  return true;
}

bool TransmissionHistory::can_record_original(
    std::uint32_t first, std::uint32_t end,
    Clock::time_point now) const noexcept {
  if (!valid_ || count_ >= records_.size() || !valid_range(first, end))
    return false;
  if (count_ == 0U)
    return true;
  const auto &last = records_[physical(count_ - 1U)];
  // New SND.NXT data is contiguous. Accepting a gap or overlap here would
  // make later ACK removal invent bytes that were never admitted to IP.
  return last.end == first && now >= last.first_transmitted_at;
}

bool TransmissionHistory::can_record_retransmission(
    std::uint32_t first, std::uint32_t end,
    Clock::time_point now) const noexcept {
  if (!valid_ || !valid_range(first, end))
    return false;
  bool overlap_found{};
  for (std::size_t logical = 0; logical < count_; ++logical) {
    const auto &record = records_[physical(logical)];
    if (!overlaps(first, end, record.first, record.end))
      continue;
    if (now < record.last_transmitted_at)
      return false;
    overlap_found = true;
  }
  return overlap_found;
}

std::size_t TransmissionHistory::record_retransmission(
    std::uint32_t first, std::uint32_t end,
    Clock::time_point now) noexcept {
  if (!can_record_retransmission(first, end, now))
    return 0U;
  std::size_t updated{};
  for (std::size_t logical = 0; logical < count_; ++logical) {
    auto &record = records_[physical(logical)];
    if (!overlaps(first, end, record.first, record.end))
      continue;
    ++updated;
  }
  if (updated == 0U)
    return 0U;
  for (std::size_t logical = 0; logical < count_; ++logical) {
    auto &record = records_[physical(logical)];
    if (!overlaps(first, end, record.first, record.end))
      continue;
    if (record.retransmissions != 0xffffffffU)
      ++record.retransmissions;
    record.last_transmitted_at = now;
  }
  return updated;
}

void TransmissionHistory::acknowledge(
    std::uint32_t acknowledgment) noexcept {
  while (count_ != 0U) {
    auto &record = records_[head_];
    if (sequence::before_or_equal(record.end, acknowledgment)) {
      record = {};
      head_ = (head_ + 1U) % records_.size();
      --count_;
      continue;
    }
    if (sequence::after(acknowledgment, record.first))
      record.first = acknowledgment;
    break;
  }
  if (count_ == 0U)
    head_ = 0U;
}

std::optional<TransmissionRecord>
TransmissionHistory::oldest() const noexcept {
  return count_ == 0U ? std::nullopt
                      : std::optional<TransmissionRecord>{records_[head_]};
}

bool TransmissionHistory::contains(std::uint32_t sequence) const noexcept {
  for (std::size_t logical = 0; logical < count_; ++logical) {
    const auto &record = records_[physical(logical)];
    if (!router::transport::tcp::sequence::before(sequence, record.first) &&
        router::transport::tcp::sequence::before(sequence, record.end))
      return true;
  }
  return false;
}

TransmissionHistoryCheckpoint
TransmissionHistory::checkpoint(Clock::time_point now) const {
  TransmissionHistoryCheckpoint state;
  state.records.reserve(count_);
  for (std::size_t logical = 0; logical < count_; ++logical) {
    const auto &record = records_[physical(logical)];
    const auto first_age = now > record.first_transmitted_at
                               ? now - record.first_transmitted_at
                               : Clock::duration::zero();
    const auto last_age = now > record.last_transmitted_at
                              ? now - record.last_transmitted_at
                              : Clock::duration::zero();
    state.records.push_back({
        .first = record.first,
        .end = record.end,
        .retransmissions = record.retransmissions,
        .first_age_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(first_age)
                .count(),
        .last_age_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(last_age)
                .count()});
  }
  return state;
}

bool TransmissionHistory::validate_checkpoint(
    const TransmissionHistoryCheckpoint &state, std::size_t capacity,
    Clock::time_point now) noexcept {
  if (capacity == 0U || state.records.size() > capacity)
    return false;
  for (std::size_t index = 0; index < state.records.size(); ++index) {
    const auto &record = state.records[index];
    if (!valid_range(record.first, record.end) ||
        record.first_age_nanoseconds < 0 ||
        record.last_age_nanoseconds < 0 ||
        record.first_age_nanoseconds < record.last_age_nanoseconds ||
        std::chrono::nanoseconds{record.first_age_nanoseconds} >
            now.time_since_epoch() ||
        (index != 0U && state.records[index - 1U].end != record.first))
      return false;
  }
  return true;
}

bool TransmissionHistory::restore(const TransmissionHistoryCheckpoint &state,
                                  Clock::time_point now) noexcept {
  if (!valid_ || !validate_checkpoint(state, records_.size(), now))
    return false;

  // Only after the complete vector validates do we replace the live ring. A
  // malformed late record therefore cannot erase already admitted segments.
  std::fill(records_.begin(), records_.end(), TransmissionRecord{});
  head_ = 0U;
  count_ = state.records.size();
  for (std::size_t index = 0; index < count_; ++index) {
    const auto &source = state.records[index];
    records_[index] = {
        .first_transmitted_at =
            now - std::chrono::nanoseconds{source.first_age_nanoseconds},
        .last_transmitted_at =
            now - std::chrono::nanoseconds{source.last_age_nanoseconds},
        .first = source.first,
        .end = source.end,
        .retransmissions = source.retransmissions};
  }
  return true;
}

} // namespace router::transport::tcp
