// Per-connection TCP delayed-ACK and zero-window persist timers. The endpoint
// owner supplies steady_clock values and sends the returned packet intents.
// These local deadlines never enter a global event queue or simulated clock.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

namespace router::transport::tcp {

enum class AckSchedule : std::uint8_t {
  none,
  delayed,
  immediate
};

struct DelayedAckCheckpoint {
  std::int64_t remaining_nanoseconds{};
  std::uint8_t data_segments_since_ack{};
  bool deadline_present{};
};

class DelayedAcknowledger final {
public:
  using Clock = std::chrono::steady_clock;

  // in_order describes sequence acceptability after receive reassembly. FIN,
  // an out-of-order segment and a second unacknowledged data segment request an
  // immediate ACK. The first in-order data segment starts the bounded delay.
  [[nodiscard]] AckSchedule on_segment(bool in_order,
                                       std::uint32_t data_octets, bool fin,
                                       Clock::time_point now) noexcept;
  [[nodiscard]] bool due(Clock::time_point now) const noexcept;

  // Window updates and other receiver events can require an ACK without an
  // arriving data segment. A due-now deadline preserves retry state when the
  // next queue is full, unlike returning a one-shot boolean intent.
  void request_immediate(Clock::time_point now) noexcept;

  // Call only after the ACK packet enters the next queue. A failed admission
  // leaves the pending deadline intact so the owner retries without losing it.
  void acknowledge_committed() noexcept;

  [[nodiscard]] std::optional<Clock::time_point> deadline() const noexcept {
    return deadline_;
  }
  [[nodiscard]] DelayedAckCheckpoint
  checkpoint(Clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const DelayedAckCheckpoint &state,
                             Clock::time_point now) noexcept;

private:
  std::optional<Clock::time_point> deadline_;
  std::uint8_t data_segments_since_ack_{};
};

struct PersistCheckpoint {
  std::int64_t remaining_nanoseconds{};
  std::int64_t interval_nanoseconds{};
  bool active{};
};

class PersistTimer final {
public:
  using Clock = std::chrono::steady_clock;
  using Duration = Clock::duration;

  // A zero advertised window with queued data starts persistence after the
  // current RTO. Opening the window or emptying the send queue cancels it.
  void update(bool zero_window, bool queued_data, Duration current_rto,
              Clock::time_point now) noexcept;
  [[nodiscard]] bool due(Clock::time_point now) const noexcept;

  // Commit only after the one-octet probe enters the packet path. The interval
  // doubles to the generated endpoint ceiling without changing normal RTO.
  [[nodiscard]] bool probe_committed(Clock::time_point now) noexcept;

  [[nodiscard]] std::optional<Clock::time_point> deadline() const noexcept {
    return deadline_;
  }
  [[nodiscard]] Duration interval() const noexcept { return interval_; }
  [[nodiscard]] PersistCheckpoint checkpoint(Clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const PersistCheckpoint &state,
                             Clock::time_point now) noexcept;

private:
  std::optional<Clock::time_point> deadline_;
  Duration interval_{};
};

} // namespace router::transport::tcp
