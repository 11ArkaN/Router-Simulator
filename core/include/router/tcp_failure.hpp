// RFC 9293 excessive-retransmission policy for one TCP connection. The TCB
// owner supplies admitted transmissions, acknowledgments and steady-clock
// values. This object reports actions but never closes a socket or calls IP.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

namespace router::transport::tcp {

enum class FailureAction : std::uint8_t {
  none,
  negative_ip_advice,
  abort_connection
};

struct FailureCheckpoint {
  std::uint32_t segment_first{};
  std::uint32_t segment_end{};
  std::uint32_t retransmissions{};
  std::int64_t segment_age_nanoseconds{};
  std::int64_t data_r2_nanoseconds{};
  bool active{};
  bool syn{};
  bool negative_advice_reported{};
  bool data_r2_infinite{};
};

class FailureDetector final {
public:
  using Clock = std::chrono::steady_clock;
  using Duration = Clock::duration;

  // nullopt gives an application an infinite data R2. A finite override is
  // connection-local and may be shorter than the default because RFC 9293
  // permits the application to abandon the operation sooner. SYN retains the
  // mandatory three-minute protocol floor independently of this data value.
  [[nodiscard]] bool
  set_data_r2(std::optional<Duration> timeout) noexcept;

  // Begin tracking only after the original segment enters the IP path. The
  // half-open range is its occupied sequence interval and must not exceed the
  // unambiguous 2^30 serial-arithmetic domain used by the stream repositories.
  [[nodiscard]] bool begin(std::uint32_t first, std::uint32_t end, bool syn,
                           Clock::time_point now) noexcept;

  // Record only a successful retransmission of the exact tracked segment.
  // R1 advice is emitted once. R2 abort takes precedence if both thresholds
  // become true on the same transmission.
  [[nodiscard]] FailureAction retransmitted(
      std::uint32_t first, std::uint32_t end,
      Clock::time_point now) noexcept;

  // A cumulative ACK covering the tracked end proves delivery and resets both
  // thresholds. Earlier or duplicate acknowledgments leave the owner intact.
  void acknowledge(std::uint32_t acknowledgment) noexcept;

  // Time-based R2 is a local deadline. Polling it does not advance time and is
  // needed even when queue backpressure prevents another retransmission.
  [[nodiscard]] FailureAction service(Clock::time_point now) const noexcept;
  [[nodiscard]] std::optional<Clock::time_point> deadline() const noexcept;
  void reset() noexcept;

  [[nodiscard]] std::uint32_t retransmissions() const noexcept {
    return retransmissions_;
  }
  [[nodiscard]] bool active() const noexcept { return active_; }

  [[nodiscard]] FailureCheckpoint
  checkpoint(Clock::time_point now) const noexcept;
  [[nodiscard]] static bool
  validate_checkpoint(const FailureCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const FailureCheckpoint &state,
                             Clock::time_point now) noexcept;

private:
  [[nodiscard]] std::optional<Duration> active_r2() const noexcept;

  Clock::time_point first_transmitted_at_{};
  std::optional<Duration> data_r2_{device_catalog::tcp_failure_data_r2};
  std::uint32_t segment_first_{};
  std::uint32_t segment_end_{};
  std::uint32_t retransmissions_{};
  bool active_{};
  bool syn_{};
  bool negative_advice_reported_{};
};

} // namespace router::transport::tcp
