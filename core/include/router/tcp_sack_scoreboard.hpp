// RFC 6675 sender SACK scoreboard for one TCP connection. The endpoint owner
// supplies equally sized range and workspace arenas. No packet, socket, clock,
// congestion window or retransmission buffer is owned by this module.

#pragma once

#include "router/tcp_options.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::transport::tcp {

struct SackRange {
  std::uint32_t first{};
  std::uint32_t end{};
};

enum class SackUpdateStatus : std::uint8_t {
  updated,
  unchanged,
  malformed,
  capacity_exhausted
};

enum class SackNextReason : std::uint8_t {
  lost_retransmission,
  new_data,
  unsacked_retransmission,
  rescue_retransmission
};

struct SackNextSegment {
  SackRange range{};
  SackNextReason reason{SackNextReason::lost_retransmission};

  [[nodiscard]] explicit operator bool() const noexcept {
    return range.first != range.end;
  }
};

struct SackScoreboardCheckpoint {
  std::vector<SackRange> ranges;
  std::uint32_t high_ack{};
  std::uint32_t high_data_end{};
  std::uint32_t high_retransmitted_end{};
  std::uint32_t recovery_point{};
  std::uint32_t rescue_retransmitted{};
  std::uint32_t duplicate_acknowledgments{};
  bool recovery{};
  bool rescue_present{};
  bool recovery_suppressed{};
};

class SackScoreboard final {
public:
  // ranges owns the canonical sorted disjoint SACK intervals. workspace is
  // scratch for transactional updates and must have exactly the same nonzero
  // capacity. sender_mss is the current effective SMSS used by IsLost.
  SackScoreboard(std::span<SackRange> ranges,
                 std::span<SackRange> workspace,
                 std::uint32_t sender_mss) noexcept;

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] bool reset(std::uint32_t high_ack,
                           std::uint32_t high_data_end) noexcept;

  // Update applies a cumulative ACK and advisory SACK blocks transactionally.
  // A malformed or unrepresentable update leaves the previous scoreboard
  // untouched so lower resource pressure cannot fabricate acknowledgment.
  [[nodiscard]] SackUpdateStatus update(
      std::uint32_t high_ack, std::uint32_t high_data_end,
      std::span<const SackBlock> blocks) noexcept;

  [[nodiscard]] bool is_lost(std::uint32_t sequence) const noexcept;
  [[nodiscard]] std::uint32_t pipe() const noexcept;
  [[nodiscard]] bool duplicate_ack(bool carries_new_sack) noexcept;
  [[nodiscard]] bool last_update_added_sack() const noexcept {
    return last_update_added_sack_;
  }

  // The caller supplies an already window-checked unsent range for NextSeg
  // rule 2. nullopt means no new data is currently eligible.
  [[nodiscard]] SackNextSegment next_segment(
      std::optional<SackRange> unsent) const noexcept;

  void enter_recovery() noexcept;
  [[nodiscard]] bool commit(const SackNextSegment &segment) noexcept;
  void on_retransmission_timeout() noexcept;
  // PMTUD may only lower SMSS from network input. Existing SACK sequence
  // ranges remain valid byte coordinates; only IsLost and NextSeg granularity
  // changes for future transmissions.
  void reduce_sender_mss(std::uint32_t sender_mss) noexcept;

  [[nodiscard]] bool in_recovery() const noexcept { return recovery_; }
  [[nodiscard]] std::size_t range_count() const noexcept { return count_; }
  [[nodiscard]] std::size_t capacity() const noexcept {
    return valid_ ? ranges_.size() : 0U;
  }

  [[nodiscard]] SackScoreboardCheckpoint checkpoint() const;
  [[nodiscard]] static bool validate_checkpoint(
      const SackScoreboardCheckpoint &state,
      std::size_t capacity) noexcept;
  [[nodiscard]] bool restore(const SackScoreboardCheckpoint &state) noexcept;

private:
  [[nodiscard]] std::uint32_t offset(std::uint32_t sequence) const noexcept {
    return sequence - high_ack_;
  }
  [[nodiscard]] bool insert_workspace(SackRange range,
                                      std::size_t &count,
                                      std::uint32_t base) noexcept;
  [[nodiscard]] std::optional<SackRange>
  first_unsacked_from(std::uint32_t start,
                      std::uint32_t ceiling) const noexcept;
  [[nodiscard]] std::optional<SackRange> highest_unsacked() const noexcept;

  std::span<SackRange> ranges_;
  std::span<SackRange> workspace_;
  std::uint32_t sender_mss_{};
  std::uint32_t high_ack_{};
  std::uint32_t high_data_end_{};
  std::uint32_t high_retransmitted_end_{};
  std::uint32_t recovery_point_{};
  std::uint32_t rescue_retransmitted_{};
  std::uint32_t duplicate_acknowledgments_{};
  std::size_t count_{};
  bool recovery_{};
  bool rescue_present_{};
  bool recovery_suppressed_{};
  bool last_update_added_sack_{};
  bool valid_{};
};

} // namespace router::transport::tcp
