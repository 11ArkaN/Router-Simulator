// RFC 1122 receiver silly-window-avoidance state for one TCP connection. The
// receive-buffer owner reports RCV.NXT advancement and application reads. This
// value object decides only the true window later encoded by TCP options.

#pragma once

#include <cstdint>

namespace router::transport::tcp {

struct ReceiveWindowCheckpoint {
  std::uint32_t capacity{};
  std::uint32_t effective_send_mss{};
  std::uint32_t advertised{};
};

class ReceiveWindow final {
public:
  // capacity is the receive arena and must stay below 2^30. The effective MSS
  // is this endpoint's current outgoing value, as recommended by RFC 1122 when
  // estimating the peer's segment size for receiver SWS avoidance.
  ReceiveWindow(std::uint32_t capacity,
                std::uint32_t effective_send_mss) noexcept;

  [[nodiscard]] bool valid() const noexcept { return valid_; }

  // Advancing RCV.NXT consumes the same amount from RCV.WND, keeping the right
  // edge fixed. Out-of-order bytes that do not advance RCV.NXT are not passed.
  void receive_next_advanced(std::uint32_t octets) noexcept;

  // available is the receive arena's current maximum free sequence range after
  // the application reads. The advertised edge advances only after at least
  // min(RCV.BUFF/2, Eff.snd.MSS) bytes accumulate.
  [[nodiscard]] bool application_space_available(
      std::uint32_t available) noexcept;

  [[nodiscard]] std::uint32_t advertised() const noexcept {
    return valid_ ? advertised_ : 0U;
  }

  [[nodiscard]] ReceiveWindowCheckpoint checkpoint() const noexcept;
  [[nodiscard]] bool restore(const ReceiveWindowCheckpoint &state) noexcept;

private:
  [[nodiscard]] std::uint32_t update_threshold() const noexcept;

  std::uint32_t capacity_{};
  std::uint32_t effective_send_mss_{};
  std::uint32_t advertised_{};
  bool valid_{};
};

} // namespace router::transport::tcp
