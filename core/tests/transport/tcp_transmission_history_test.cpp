// Transmission-history tests cover caller capacity, wrap, PMTU resegmentation,
// partial cumulative ACKs and checkpoint-relative first-transmission ages.

#include "router/tcp_transmission_history.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

void tcp_transmission_history_tests() {
  using namespace router::transport::tcp;
  using namespace std::chrono_literals;
  using Clock = TransmissionHistory::Clock;

  std::array<TransmissionRecord, 3> storage{};
  TransmissionHistory history{storage};
  const auto start = Clock::time_point{100s};
  if (!history.valid() || !history.record_original(0xfffffff0U, 0U, start) ||
      !history.record_original(0U, 16U, start + 1ms) ||
      !history.record_original(16U, 32U, start + 2ms) ||
      history.can_record_original(32U, 33U, start + 3ms) ||
      history.record_original(33U, 34U, start + 3ms))
    throw std::runtime_error("TCP transmission history lost capacity or contiguity");

  // An RFC 792 quotation carries the sequence at the start of the quoted TCP
  // segment. Association must accept every still-outstanding byte, including
  // ranges crossing serial-number wrap, but reject both the exclusive end and
  // unrelated sequence space. This is the anti-spoofing gate used by PMTUD.
  if (!history.contains(0xfffffff0U) || !history.contains(0xffffffffU) ||
      !history.contains(0U) || !history.contains(31U) || history.contains(32U))
    throw std::runtime_error("TCP transmission quotation lookup lost serial arithmetic");

  // A smaller repair after a PMTU reduction overlaps the tail of the first
  // original segment and the head of the second. Both retain the same repair
  // evidence without changing their original boundaries.
  if (history.record_retransmission(0xfffffff8U, 8U, start + 1s) != 2U)
    throw std::runtime_error("TCP transmission history missed a resegmented repair");
  history.acknowledge(4U);
  const auto oldest = history.oldest();
  if (!oldest || oldest->first != 4U || oldest->end != 16U ||
      oldest->retransmissions != 1U || history.size() != 2U ||
      history.contains(3U) || !history.contains(4U))
    throw std::runtime_error("TCP partial ACK changed original transmission age");

  const auto checkpoint = history.checkpoint(start + 50s);
  std::array<TransmissionRecord, 3> restored_storage{};
  TransmissionHistory restored{restored_storage};
  const auto restored_at = Clock::time_point{500s};
  if (!restored.restore(checkpoint, restored_at) || restored.size() != 2U)
    throw std::runtime_error("TCP transmission history checkpoint was rejected");
  const auto restored_oldest = restored.oldest();
  if (!restored_oldest || restored_oldest->first != 4U ||
      restored_oldest->first_transmitted_at !=
          restored_at - (50s - 1ms) ||
      restored_oldest->last_transmitted_at != restored_at - 49s)
    throw std::runtime_error("TCP transmission history restore extended R2 age");

  auto invalid = checkpoint;
  invalid.records.back().first = 17U;
  const auto before = restored.checkpoint(restored_at);
  if (restored.restore(invalid, restored_at) ||
      restored.checkpoint(restored_at).records.front().first !=
          before.records.front().first)
    throw std::runtime_error("TCP history restore mutated before full validation");
}
