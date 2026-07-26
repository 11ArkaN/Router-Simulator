// Receiver SWS avoidance implementation. The advertised value changes by
// subtraction as RCV.NXT advances and by thresholded expansion after reads,
// preventing both right-edge retraction and streams of tiny window updates.

#include "router/tcp_receive_window.hpp"

#include <algorithm>

namespace router::transport::tcp {

ReceiveWindow::ReceiveWindow(std::uint32_t capacity,
                             std::uint32_t effective_send_mss) noexcept
    : capacity_(capacity), effective_send_mss_(effective_send_mss),
      advertised_(capacity) {
  valid_ = capacity_ != 0U && capacity_ <= 0x40000000U &&
           effective_send_mss_ != 0U;
}

std::uint32_t ReceiveWindow::update_threshold() const noexcept {
  // Fr is the RFC 1122 recommended one half. Integer division rounds the half
  // upward so an odd-byte arena never advertises a smaller-than-half update.
  const auto half = capacity_ / 2U + capacity_ % 2U;
  return std::min(half, effective_send_mss_);
}

void ReceiveWindow::receive_next_advanced(std::uint32_t octets) noexcept {
  if (!valid_)
    return;
  // An owner reporting more advancement than the advertised range indicates a
  // violated sequence-acceptability invariant. Closing the window is safe and
  // prevents unsigned underflow from manufacturing several gigabytes of room.
  advertised_ = octets >= advertised_ ? 0U : advertised_ - octets;
}

bool ReceiveWindow::application_space_available(
    std::uint32_t available) noexcept {
  if (!valid_ || available > capacity_ || available <= advertised_)
    return false;
  const auto reduction = available - advertised_;
  if (reduction < update_threshold())
    return false;
  advertised_ = available;
  return true;
}

ReceiveWindowCheckpoint ReceiveWindow::checkpoint() const noexcept {
  return {.capacity = capacity_,
          .effective_send_mss = effective_send_mss_,
          .advertised = advertised_};
}

bool ReceiveWindow::restore(const ReceiveWindowCheckpoint &state) noexcept {
  if (!valid_ || state.capacity != capacity_ ||
      state.effective_send_mss != effective_send_mss_ ||
      state.advertised > capacity_)
    return false;
  advertised_ = state.advertised;
  return true;
}

} // namespace router::transport::tcp
