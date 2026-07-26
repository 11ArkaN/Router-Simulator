// TCP byte-stream receive repository. Sequence offsets map onto a circular
// owner-provided arena, while a physical receipt bitmap distinguishes a real
// zero octet from a hole and avoids copying already accepted overlap bytes.

#include "router/tcp_receive_buffer.hpp"

#include "router/tcp_sequence.hpp"

#include <algorithm>

namespace router::transport::tcp {

ReceiveBuffer::ReceiveBuffer(std::span<std::uint8_t> storage,
                             std::span<std::uint8_t> received_bitmap,
                             std::uint32_t initial_receive_sequence) noexcept
    : storage_(storage), received_bitmap_(received_bitmap),
      read_sequence_(initial_receive_sequence),
      receive_next_(initial_receive_sequence) {
  valid_ = !storage_.empty() && storage_.size() <= 0x40000000U &&
           received_bitmap_.size() == (storage_.size() + 7U) / 8U;
  if (valid_) {
    std::fill(storage_.begin(), storage_.end(), std::uint8_t{0});
    std::fill(received_bitmap_.begin(), received_bitmap_.end(),
              std::uint8_t{0});
  }
}

bool ReceiveBuffer::received(std::size_t physical_index) const noexcept {
  return (received_bitmap_[physical_index / 8U] &
          static_cast<std::uint8_t>(1U << (physical_index % 8U))) != 0U;
}

void ReceiveBuffer::set_received(std::size_t physical_index,
                                 bool value) noexcept {
  auto &byte = received_bitmap_[physical_index / 8U];
  const auto mask = static_cast<std::uint8_t>(1U << (physical_index % 8U));
  byte = value ? static_cast<std::uint8_t>(byte | mask)
               : static_cast<std::uint8_t>(byte & ~mask);
}

std::size_t ReceiveBuffer::physical(std::uint32_t offset) const noexcept {
  return (static_cast<std::size_t>(head_) + offset) % storage_.size();
}

void ReceiveBuffer::advance_contiguous() noexcept {
  // RCV.NXT can advance across bytes already buffered beyond a former gap,
  // but never past the fixed right edge based on unread application data.
  while (static_cast<std::uint32_t>(receive_next_ - read_sequence_) <
         storage_.size()) {
    const auto offset = receive_next_ - read_sequence_;
    if (!received(physical(offset)))
      break;
    ++receive_next_;
  }
}

ReceiveInsertResult
ReceiveBuffer::accept(std::uint32_t sequence,
                      std::span<const std::uint8_t> payload) noexcept {
  if (!valid_)
    return {};
  if (payload.empty())
    return {.status = ReceiveInsertStatus::duplicate,
            .receive_next = receive_next_};

  // Bytes before RCV.NXT have already been accepted and acknowledged. Trim
  // that prefix rather than overwriting buffered unread data with an overlap.
  if (sequence::before(sequence, receive_next_)) {
    const auto old = static_cast<std::uint32_t>(receive_next_ - sequence);
    if (old >= payload.size())
      return {.status = ReceiveInsertStatus::duplicate,
              .receive_next = receive_next_};
    payload = payload.subspan(old);
    sequence = receive_next_;
  }

  const auto offset = static_cast<std::uint32_t>(sequence - read_sequence_);
  if (offset >= storage_.size())
    return {.status = ReceiveInsertStatus::outside_window,
            .receive_next = receive_next_};
  const auto admitted = std::min(payload.size(), storage_.size() - offset);
  std::size_t newly_stored{};
  std::uint32_t first_new_sequence{};
  for (std::size_t index = 0U; index < admitted; ++index) {
    const auto position = physical(offset + static_cast<std::uint32_t>(index));
    if (received(position))
      continue;
    storage_[position] = payload[index];
    set_received(position, true);
    if (newly_stored == 0U)
      first_new_sequence = sequence + static_cast<std::uint32_t>(index);
    ++newly_stored;
  }
  if (newly_stored != 0U) {
    recent_sequence_ = first_new_sequence;
    recent_sequence_present_ = true;
  }
  advance_contiguous();
  return {.status = newly_stored == 0U ? ReceiveInsertStatus::duplicate
                                       : ReceiveInsertStatus::accepted,
          .receive_next = receive_next_,
          .newly_stored = newly_stored};
}

std::size_t ReceiveBuffer::read(std::span<std::uint8_t> output) noexcept {
  if (!valid_)
    return 0U;
  const auto count = std::min(output.size(), readable_octets());
  for (std::size_t index = 0U; index < count; ++index) {
    const auto position = physical(static_cast<std::uint32_t>(index));
    output[index] = storage_[position];
    set_received(position, false);
  }
  head_ = static_cast<std::uint32_t>((head_ + count) % storage_.size());
  read_sequence_ += static_cast<std::uint32_t>(count);
  return count;
}

std::uint32_t ReceiveBuffer::advertised_window() const noexcept {
  if (!valid_)
    return 0U;
  return static_cast<std::uint32_t>(storage_.size()) -
         static_cast<std::uint32_t>(receive_next_ - read_sequence_);
}

std::size_t ReceiveBuffer::readable_octets() const noexcept {
  return valid_ ? static_cast<std::uint32_t>(receive_next_ - read_sequence_)
                : 0U;
}

std::size_t ReceiveBuffer::sack_blocks(
    std::span<SackBlock> output) const noexcept {
  if (!valid_ || output.empty())
    return 0U;
  const auto first_offset = receive_next_ - read_sequence_;
  if (first_offset >= storage_.size())
    return 0U;

  auto block_at = [&](std::uint32_t offset) -> std::optional<SackBlock> {
    if (offset < first_offset || offset >= storage_.size() ||
        !received(physical(offset)))
      return std::nullopt;
    auto left = offset;
    while (left > first_offset && received(physical(left - 1U)))
      --left;
    auto right = offset + 1U;
    while (right < storage_.size() && received(physical(right)))
      ++right;
    return SackBlock{.left_edge = read_sequence_ + left,
                     .right_edge = read_sequence_ + right};
  };

  std::optional<SackBlock> recent;
  if (recent_sequence_present_) {
    const auto recent_offset = recent_sequence_ - read_sequence_;
    recent = block_at(recent_offset);
    if (recent)
      output[0U] = *recent;
  }
  std::size_t count = recent ? 1U : 0U;

  // Scan from the right edge so the remaining reports describe the newest
  // sequence-space holes first. No fixed scoreboard truncates receive state;
  // caller capacity alone limits how many blocks fit in this ACK's options.
  auto cursor = static_cast<std::uint32_t>(storage_.size());
  while (cursor > first_offset && count < output.size()) {
    --cursor;
    if (!received(physical(cursor)))
      continue;
    const auto block = block_at(cursor);
    if (!block)
      continue;
    cursor = block->left_edge - read_sequence_;
    if (recent && block->left_edge == recent->left_edge &&
        block->right_edge == recent->right_edge)
      continue;
    output[count++] = *block;
  }
  return count;
}

ReceiveBufferCheckpoint ReceiveBuffer::checkpoint() const {
  return {.storage = {storage_.begin(), storage_.end()},
          .received = {received_bitmap_.begin(), received_bitmap_.end()},
          .read_sequence = read_sequence_,
          .receive_next = receive_next_,
          .head = head_,
          .recent_sequence = recent_sequence_,
          .recent_sequence_present = recent_sequence_present_};
}

bool ReceiveBuffer::restore(const ReceiveBufferCheckpoint &state) noexcept {
  if (!valid_ || state.storage.size() != storage_.size() ||
      state.received.size() != received_bitmap_.size() ||
      state.head >= storage_.size() ||
      static_cast<std::uint32_t>(state.receive_next - state.read_sequence) >
          storage_.size())
    return false;
  // Every byte below RCV.NXT remains unread and therefore must be present.
  // Check against the saved head before mutating the live arena.
  for (std::uint32_t offset = 0U;
       offset < state.receive_next - state.read_sequence; ++offset) {
    const auto position = (state.head + offset) % state.storage.size();
    if ((state.received[position / 8U] &
         static_cast<std::uint8_t>(1U << (position % 8U))) == 0U)
      return false;
  }
  // Padding bits do not correspond to arena bytes and must remain zero so a
  // corrupt checkpoint cannot hide state outside the declared capacity.
  for (std::size_t bit = storage_.size();
       bit < received_bitmap_.size() * 8U; ++bit)
    if ((state.received[bit / 8U] &
         static_cast<std::uint8_t>(1U << (bit % 8U))) != 0U)
      return false;
  std::copy(state.storage.begin(), state.storage.end(), storage_.begin());
  std::copy(state.received.begin(), state.received.end(),
            received_bitmap_.begin());
  read_sequence_ = state.read_sequence;
  receive_next_ = state.receive_next;
  head_ = state.head;
  recent_sequence_ = state.recent_sequence;
  recent_sequence_present_ = state.recent_sequence_present;
  return true;
}

} // namespace router::transport::tcp
