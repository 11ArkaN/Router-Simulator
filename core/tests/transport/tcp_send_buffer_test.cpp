// TCP send-repository tests exercise caller-defined capacity, partial ACKs,
// sequence wrap, retransmission, two-phase admission and live checkpointing.

#include "router/tcp_send_buffer.hpp"

#include <array>
#include <stdexcept>

void tcp_send_buffer_tests() {
  using namespace router::transport::tcp;

  std::array<std::uint8_t, 17> storage{};
  SendBuffer buffer{storage, 0xfffffff8U};
  constexpr std::array<std::uint8_t, 20> stream{
      1U,  2U,  3U,  4U,  5U,  6U,  7U,  8U,  9U,  10U,
      11U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U};
  if (!buffer.valid() || buffer.write(stream) != storage.size() ||
      buffer.writable_octets() != 0U)
    throw std::runtime_error("TCP send arena did not apply backpressure");

  // Preparing a segment must not claim sequence space. A stale intent is then
  // rejected after any state-changing write, ACK or successful commit.
  const auto first = buffer.prepare_new(8U);
  std::array<std::uint8_t, 8> packet{};
  if (!first || buffer.send_next() != 0xfffffff8U ||
      !buffer.copy(first, packet) || packet.front() != 1U ||
      packet.back() != 8U || !buffer.commit(first) || buffer.commit(first) ||
      buffer.send_next() != 0U || buffer.flight_size() != 8U)
    throw std::runtime_error("TCP send two-phase admission changed SND.NXT");

  const auto second = buffer.prepare_new(9U);
  std::array<std::uint8_t, 9> packet_two{};
  if (!buffer.copy(second, packet_two) || !buffer.commit(second) ||
      buffer.send_next() != 9U || buffer.unsent_octets() != 0U)
    throw std::runtime_error("TCP send sequence wrap corrupted segmentation");

  if (buffer.acknowledge(1U).newly_acknowledged != 9U ||
      buffer.flight_size() != 8U || buffer.writable_octets() != 9U)
    throw std::runtime_error("TCP partial cumulative ACK released wrong bytes");
  if (buffer.acknowledge(20U).status != SendAcknowledgeStatus::beyond_sent ||
      buffer.acknowledge(1U).status != SendAcknowledgeStatus::duplicate)
    throw std::runtime_error("TCP accepted an ACK outside sent sequence space");

  // The retransmission starts at SND.UNA and preserves the original stream,
  // even though the physical arena head moved across a non-power-of-two ring.
  const auto repair = buffer.prepare_retransmission(5U);
  std::array<std::uint8_t, 5> repaired{};
  if (!repair.retransmission || repair.sequence != 1U ||
      !buffer.copy(repair, repaired) || repaired.front() != 10U ||
      repaired.back() != 14U || !buffer.commit(repair) ||
      buffer.send_next() != 9U)
    throw std::runtime_error("TCP retransmission changed sequence ownership");
  const auto selective = buffer.prepare_retransmission_at(4U, 3U);
  std::array<std::uint8_t, 3> selectively_repaired{};
  if (!selective || selective.sequence != 4U ||
      !buffer.copy(selective, selectively_repaired) ||
      selectively_repaired.front() != 13U ||
      selectively_repaired.back() != 15U || !buffer.commit(selective) ||
      buffer.prepare_retransmission_at(9U, 1U))
    throw std::runtime_error("TCP SACK repair could not select retained sequence data");

  constexpr std::array<std::uint8_t, 9> continuation{
      18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 26U};
  if (buffer.write(continuation) != continuation.size())
    throw std::runtime_error("TCP send ring did not reuse acknowledged slots");
  const auto saved = buffer.checkpoint();

  std::array<std::uint8_t, 17> restored_storage{};
  SendBuffer restored{restored_storage, 0U};
  if (!restored.restore(saved) || restored.flight_size() != 8U ||
      restored.unsent_octets() != 9U || restored.queued_octets() != 17U)
    throw std::runtime_error("TCP send checkpoint lost live byte ranges");
  const auto restored_new = restored.prepare_new(9U);
  std::array<std::uint8_t, 9> restored_packet{};
  if (!restored.copy(restored_new, restored_packet) ||
      restored_packet.front() != 18U || restored_packet.back() != 26U)
    throw std::runtime_error("TCP restored stream changed application bytes");

  auto invalid = saved;
  invalid.write_next = invalid.send_unacknowledged + 18U;
  if (restored.restore(invalid))
    throw std::runtime_error("TCP send checkpoint exceeded owner capacity");
}
