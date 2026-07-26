// TCP send repository implementation. Sequence-space offsets address a
// circular byte arena so acknowledging a prefix is O(1) and never shifts the
// remaining stream. Copies occur only from the arena into an actual packet.

#include "router/tcp_send_buffer.hpp"

#include "router/tcp_sequence.hpp"

#include <algorithm>

namespace router::transport::tcp {

SendBuffer::SendBuffer(std::span<std::uint8_t> storage,
                       std::uint32_t initial_data_sequence) noexcept
    : storage_(storage), send_unacknowledged_(initial_data_sequence),
      send_next_(initial_data_sequence), write_next_(initial_data_sequence) {
  valid_ = !storage_.empty() && storage_.size() <= 0x40000000U;
  if (valid_)
    std::fill(storage_.begin(), storage_.end(), std::uint8_t{0});
}

std::size_t SendBuffer::physical(std::uint32_t offset) const noexcept {
  return (static_cast<std::size_t>(head_) + offset) % storage_.size();
}

std::uint32_t SendBuffer::flight_size() const noexcept {
  return valid_ ? send_next_ - send_unacknowledged_ : 0U;
}

std::uint32_t SendBuffer::unsent_octets() const noexcept {
  return valid_ ? write_next_ - send_next_ : 0U;
}

std::uint32_t SendBuffer::queued_octets() const noexcept {
  return valid_ ? write_next_ - send_unacknowledged_ : 0U;
}

std::uint32_t SendBuffer::writable_octets() const noexcept {
  return valid_ ? static_cast<std::uint32_t>(storage_.size()) - queued_octets()
                : 0U;
}

std::size_t SendBuffer::write(std::span<const std::uint8_t> input) noexcept {
  if (!valid_ || input.empty())
    return 0U;
  const auto accepted = std::min<std::size_t>(input.size(), writable_octets());
  const auto tail_offset = queued_octets();
  for (std::size_t index = 0U; index < accepted; ++index)
    storage_[physical(tail_offset + static_cast<std::uint32_t>(index))] =
        input[index];
  write_next_ += static_cast<std::uint32_t>(accepted);
  if (accepted != 0U)
    ++generation_;
  return accepted;
}

PreparedSendRange
SendBuffer::prepare_new(std::uint32_t maximum_payload) const noexcept {
  if (!valid_ || maximum_payload == 0U)
    return {};
  return {.sequence = send_next_,
          .length = std::min(maximum_payload, unsent_octets()),
          .generation = generation_,
          .retransmission = false};
}

PreparedSendRange SendBuffer::prepare_retransmission(
    std::uint32_t maximum_payload) const noexcept {
  if (!valid_ || maximum_payload == 0U)
    return {};
  // RFC 6298 restarts from the earliest unacknowledged sequence. Restricting
  // one repair to maximum_payload lets the owner apply the current SMSS after
  // a path-MTU decrease instead of reproducing an obsolete segment boundary.
  return {.sequence = send_unacknowledged_,
          .length = std::min(maximum_payload, flight_size()),
          .generation = generation_,
          .retransmission = true};
}

PreparedSendRange SendBuffer::prepare_retransmission_at(
    std::uint32_t sequence, std::uint32_t maximum_payload) const noexcept {
  if (!valid_ || maximum_payload == 0U ||
      sequence::before(sequence, send_unacknowledged_) ||
      !sequence::before(sequence, send_next_))
    return {};
  const auto retained = send_next_ - sequence;
  return {.sequence = sequence,
          .length = std::min(maximum_payload, retained),
          .generation = generation_,
          .retransmission = true};
}

bool SendBuffer::range_is_current(
    const PreparedSendRange &range) const noexcept {
  if (!valid_ || range.length == 0U || range.generation != generation_)
    return false;
  const auto offset = range.sequence - send_unacknowledged_;
  if (offset >= queued_octets() || range.length > queued_octets() - offset)
    return false;
  if (range.retransmission)
    return offset < flight_size() &&
           range.length <= flight_size() - offset;
  return range.sequence == send_next_ && range.length <= unsent_octets();
}

bool SendBuffer::copy(const PreparedSendRange &range,
                      std::span<std::uint8_t> output) const noexcept {
  if (!range_is_current(range) || output.size() < range.length)
    return false;
  const auto offset = range.sequence - send_unacknowledged_;
  for (std::uint32_t index = 0U; index < range.length; ++index)
    output[index] = storage_[physical(offset + index)];
  return true;
}

bool SendBuffer::commit(const PreparedSendRange &range) noexcept {
  if (!range_is_current(range))
    return false;
  // A retransmission consumes no new sequence space. Incrementing the token is
  // still necessary because the endpoint may attach new RTT and timer state to
  // this actual transmission, invalidating a second copy of the same intent.
  if (!range.retransmission)
    send_next_ += range.length;
  ++generation_;
  return true;
}

SendAcknowledgeResult
SendBuffer::acknowledge(std::uint32_t acknowledgment) noexcept {
  if (!valid_)
    return {};
  if (sequence::after(acknowledgment, send_next_))
    return {.status = SendAcknowledgeStatus::beyond_sent};
  if (!sequence::after(acknowledgment, send_unacknowledged_))
    return {.status = SendAcknowledgeStatus::duplicate};

  const auto count = acknowledgment - send_unacknowledged_;
  // Clearing acknowledged bytes is not required for TCP correctness, but it
  // prevents stale application data from leaking into a diagnostic checkpoint
  // after the circular slots become free.
  for (std::uint32_t index = 0U; index < count; ++index)
    storage_[physical(index)] = 0U;
  head_ = static_cast<std::uint32_t>((head_ + count) % storage_.size());
  send_unacknowledged_ = acknowledgment;
  ++generation_;
  return {.status = SendAcknowledgeStatus::advanced,
          .newly_acknowledged = count};
}

SendBufferCheckpoint SendBuffer::checkpoint() const {
  return {.storage = {storage_.begin(), storage_.end()},
          .send_unacknowledged = send_unacknowledged_,
          .send_next = send_next_,
          .write_next = write_next_,
          .head = head_,
          .generation = generation_};
}

bool SendBuffer::restore(const SendBufferCheckpoint &state) noexcept {
  if (!valid_ || state.storage.size() != storage_.size() ||
      state.head >= storage_.size() || state.generation == 0U)
    return false;
  const auto flight = state.send_next - state.send_unacknowledged;
  const auto queued = state.write_next - state.send_unacknowledged;
  // Both live ranges must remain below 2^31. The constructor's 2^30 capacity
  // makes the simple unsigned differences unambiguous even across wrap.
  if (flight > queued || queued > storage_.size())
    return false;
  std::copy(state.storage.begin(), state.storage.end(), storage_.begin());
  send_unacknowledged_ = state.send_unacknowledged;
  send_next_ = state.send_next;
  write_next_ = state.write_next;
  head_ = state.head;
  generation_ = state.generation;
  return true;
}

} // namespace router::transport::tcp
