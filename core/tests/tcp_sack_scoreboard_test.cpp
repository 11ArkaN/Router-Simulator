// RFC 6675 tests cover transactional Update, IsLost, SetPipe, all NextSeg
// repair classes, timeout reneging, wrap and exact checkpoint continuation.

#include "router/tcp_sack_scoreboard.hpp"

#include <array>
#include <stdexcept>

void tcp_sack_scoreboard_tests() {
  using namespace router::transport::tcp;

  std::array<SackRange, 8> ranges{};
  std::array<SackRange, 8> workspace{};
  SackScoreboard scoreboard{ranges, workspace, 1000U};
  const std::array sacks{SackBlock{2000U, 3000U},
                         SackBlock{4000U, 6000U}};
  if (!scoreboard.valid() || !scoreboard.reset(1000U, 6000U) ||
      scoreboard.update(1000U, 6000U, sacks) !=
          SackUpdateStatus::updated ||
      !scoreboard.is_lost(1000U) || scoreboard.is_lost(3000U) ||
      scoreboard.pipe() != 1000U)
    throw std::runtime_error("TCP SACK Update, IsLost or SetPipe was incorrect");

  scoreboard.enter_recovery();
  const auto lost = scoreboard.next_segment(std::nullopt);
  if (!lost || lost.reason != SackNextReason::lost_retransmission ||
      lost.range.first != 1000U || lost.range.end != 2000U ||
      !scoreboard.commit(lost))
    throw std::runtime_error("TCP SACK rule 1 did not repair the first loss");

  // Rule 2 outranks a less-certain retransmission and respects one SMSS even
  // when the caller has already admitted a larger new-data allowance.
  const auto fresh = scoreboard.next_segment(SackRange{6000U, 8000U});
  if (!fresh || fresh.reason != SackNextReason::new_data ||
      fresh.range.first != 6000U || fresh.range.end != 7000U ||
      !scoreboard.commit(fresh))
    throw std::runtime_error("TCP SACK rule 2 did not select eligible new data");

  const auto unsacked = scoreboard.next_segment(std::nullopt);
  if (!unsacked ||
      unsacked.reason != SackNextReason::unsacked_retransmission ||
      unsacked.range.first != 3000U || unsacked.range.end != 4000U ||
      !scoreboard.commit(unsacked))
    throw std::runtime_error("TCP SACK rule 3 did not sustain the ACK clock");
  const std::array later_sack{SackBlock{4000U, 6000U}};
  if (scoreboard.update(3000U, 7000U, later_sack) !=
      SackUpdateStatus::updated)
    throw std::runtime_error("TCP SACK partial recovery ACK was rejected");
  const auto rescue = scoreboard.next_segment(std::nullopt);
  if (!rescue || rescue.reason != SackNextReason::rescue_retransmission ||
      !scoreboard.commit(rescue) || scoreboard.next_segment(std::nullopt))
    throw std::runtime_error("TCP SACK allowed more than one rescue retransmission");

  const auto saved = scoreboard.checkpoint();
  std::array<SackRange, 8> restored_ranges{};
  std::array<SackRange, 8> restored_workspace{};
  SackScoreboard restored{restored_ranges, restored_workspace, 1000U};
  if (!restored.restore(saved) || !restored.in_recovery() ||
      restored.range_count() != 1U)
    throw std::runtime_error("TCP SACK checkpoint lost active recovery state");

  // RTO discards advisory SACK state because the receiver may have reneged.
  // Recovery cannot restart until cumulative ACK reaches the preserved point.
  restored.on_retransmission_timeout();
  restored.enter_recovery();
  if (restored.in_recovery() || restored.range_count() != 0U ||
      restored.update(7000U, 7000U, {}) != SackUpdateStatus::updated)
    throw std::runtime_error("TCP SACK timeout did not suppress premature recovery");
  restored.enter_recovery();
  if (!restored.in_recovery())
    throw std::runtime_error("TCP SACK recovery stayed suppressed after RecoveryPoint");

  // A scoreboard with two caller slots reports overload without accepting a
  // partial subset of three disjoint blocks.
  std::array<SackRange, 2> short_ranges{};
  std::array<SackRange, 2> short_workspace{};
  SackScoreboard short_board{short_ranges, short_workspace, 100U};
  const std::array too_many{SackBlock{1100U, 1200U},
                            SackBlock{1300U, 1400U},
                            SackBlock{1500U, 1600U}};
  if (!short_board.reset(1000U, 1700U) ||
      short_board.update(1000U, 1700U, too_many) !=
          SackUpdateStatus::capacity_exhausted ||
      short_board.range_count() != 0U)
    throw std::runtime_error("TCP SACK capacity failure published partial state");

  // Live offsets, sorting and merging continue to work across sequence wrap.
  std::array<SackRange, 4> wrap_ranges{};
  std::array<SackRange, 4> wrap_workspace{};
  SackScoreboard wrap{wrap_ranges, wrap_workspace, 8U};
  const std::array wrap_sacks{SackBlock{0xfffffff8U, 0U},
                              SackBlock{0U, 8U}};
  if (!wrap.reset(0xfffffff0U, 16U) ||
      wrap.update(0xfffffff0U, 16U, wrap_sacks) !=
          SackUpdateStatus::updated ||
      wrap.range_count() != 1U)
    throw std::runtime_error("TCP SACK serial wrap split adjacent blocks");
}
