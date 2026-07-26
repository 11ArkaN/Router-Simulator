// TCP serial arithmetic tests concentrate on wrap boundaries and all four
// receive-window cases from RFC 9293. These are pure tests, not a simulated
// clock or a shortcut around encoded packet processing.

#include "router/tcp_sequence.hpp"

#include <stdexcept>

void tcp_sequence_tests() {
  using namespace router::transport::tcp::sequence;

  if (!before(0xfffffff0U, 0x00000010U) ||
      !after(0x00000010U, 0xfffffff0U) || before(7U, 7U) ||
      !before_or_equal(7U, 7U) || !after_or_equal(7U, 7U))
    throw std::runtime_error("TCP serial comparison failed across wrap");

  // Zero window accepts only a zero-length probe exactly at RCV.NXT.
  if (!segment_acceptable(100U, 0U, 100U, 0U) ||
      segment_acceptable(99U, 0U, 100U, 0U) ||
      segment_acceptable(100U, 1U, 100U, 0U))
    throw std::runtime_error("TCP zero-window acceptability drifted");

  // In a nonzero window, either the first or final sequence number may fall
  // inside. A segment spanning the whole window with neither endpoint inside
  // is deliberately rejected by the exact RFC 9293 four-case test.
  if (!segment_acceptable(100U, 0U, 100U, 10U) ||
      !segment_acceptable(109U, 0U, 100U, 10U) ||
      segment_acceptable(110U, 0U, 100U, 10U) ||
      !segment_acceptable(95U, 6U, 100U, 10U) ||
      !segment_acceptable(109U, 20U, 100U, 10U) ||
      segment_acceptable(90U, 30U, 100U, 10U))
    throw std::runtime_error("TCP receive-window endpoint tests drifted");

  if (!segment_acceptable(0xfffffff8U, 8U, 0xfffffff0U, 32U) ||
      !segment_acceptable(0x00000008U, 1U, 0xfffffff0U, 32U))
    throw std::runtime_error("TCP receive window failed across sequence wrap");

  if (!acknowledgment_advances(0x00000008U, 0xfffffff8U, 0x00000010U) ||
      acknowledgment_advances(0xfffffff8U, 0xfffffff8U, 0x00000010U) ||
      acknowledgment_advances(0x00000011U, 0xfffffff8U, 0x00000010U))
    throw std::runtime_error("TCP ACK range accepted duplicate or unsent bytes");
}
