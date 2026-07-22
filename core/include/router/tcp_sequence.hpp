// RFC 9293 serial-number arithmetic and receive-window acceptability. These
// pure helpers own no TCB state. Callers must keep compared spans below 2^31,
// which TCP window scaling already requires for unambiguous modulo ordering.

#pragma once

#include <cstdint>

namespace router::transport::tcp::sequence {

inline constexpr std::uint32_t half_space = 0x80000000U;

[[nodiscard]] constexpr bool before(std::uint32_t left,
                                    std::uint32_t right) noexcept {
  return left != right && (right - left) < half_space;
}

[[nodiscard]] constexpr bool before_or_equal(std::uint32_t left,
                                             std::uint32_t right) noexcept {
  return left == right || before(left, right);
}

[[nodiscard]] constexpr bool after(std::uint32_t left,
                                   std::uint32_t right) noexcept {
  return before(right, left);
}

[[nodiscard]] constexpr bool after_or_equal(std::uint32_t left,
                                            std::uint32_t right) noexcept {
  return left == right || after(left, right);
}

// RFC 9293 section 3.10.7.4 defines four receive tests based on SEG.LEN and
// RCV.WND. segment_length includes data plus one sequence number for SYN and
// one for FIN. Addition intentionally wraps in the 32-bit sequence space.
[[nodiscard]] constexpr bool segment_acceptable(
    std::uint32_t segment_sequence, std::uint32_t segment_length,
    std::uint32_t receive_next, std::uint32_t receive_window) noexcept {
  if (segment_length == 0U && receive_window == 0U)
    return segment_sequence == receive_next;
  if (receive_window == 0U)
    return false;
  const auto window_end = receive_next + receive_window;
  const auto first_inside = after_or_equal(segment_sequence, receive_next) &&
                            before(segment_sequence, window_end);
  if (segment_length == 0U)
    return first_inside;
  const auto last_sequence = segment_sequence + segment_length - 1U;
  const auto last_inside = after_or_equal(last_sequence, receive_next) &&
                           before(last_sequence, window_end);
  return first_inside || last_inside;
}

// A cumulative ACK advances SND.UNA only when it lies in (SND.UNA,SND.NXT].
// Equal ACKs are duplicates and ACKs beyond SND.NXT acknowledge unsent bytes.
[[nodiscard]] constexpr bool acknowledgment_advances(
    std::uint32_t acknowledgment, std::uint32_t send_unacknowledged,
    std::uint32_t send_next) noexcept {
  return after(acknowledgment, send_unacknowledged) &&
         before_or_equal(acknowledgment, send_next);
}

} // namespace router::transport::tcp::sequence
