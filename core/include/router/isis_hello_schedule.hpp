// One circuit and Hello class owns its local transmission deadlines and PRNG.
// The IS-IS control shard alone mutates it. No shared simulation clock or
// cross-device scheduler is used; the caller supplies host monotonic time.

#pragma once

#include "router/isis_jitter.hpp"

namespace router::isis {

class HelloSchedule final {
public:
  using Clock = std::chrono::steady_clock;
  // effective_interval is resolved by the circuit configuration owner. LAN
  // classes enforce ISO 10589 8.4.4 one-second same-level emission spacing.
  // DIS uses the unjittered timer exception; other periods use clause 10.1.
  // Nonpositive intervals or zero random state throw before publication.
  HelloSchedule(std::chrono::microseconds effective_interval, bool broadcast,
      bool designated, std::uint64_t random_state, Clock::time_point now);

  // Changes in advertised contents request another Hello without restarting
  // the periodic timer. Requests arriving while output is pending survive its
  // completion. This method allocates nothing and runs on the control owner.
  void changed() noexcept { dirty_ = true; }
  // A DIS role change restarts its periodic timer and requests a fresh Hello.
  // Invalid interval preserves all state and returns false.
  [[nodiscard]] bool role(std::chrono::microseconds effective_interval,
      bool designated, Clock::time_point now) noexcept;
  // Advances an expired periodic timer before the caller performs send work.
  // Exactly one send may be outstanding. true reserves it until complete().
  // A false result makes no claim that a packet was transmitted.
  [[nodiscard]] bool begin(Clock::time_point now) noexcept;
  // Called after actual port-queue admission, or immediately after publication
  // refusal. A refused Hello retries at its next periodic expiration; it has
  // no reliable-delivery obligation. Later content requests remain dirty.
  // This avoids a busy retry loop on a full queue. Receipt observation time
  // is a conservative spacing anchor for successful physical admission.
  [[nodiscard]] bool complete(bool enqueued, Clock::time_point now) noexcept;
  [[nodiscard]] Clock::time_point deadline() const noexcept;
  [[nodiscard]] std::uint64_t random_state() const noexcept { return random_; }
  [[nodiscard]] bool pending() const noexcept { return pending_; }

private:
  void restart(Clock::time_point now) noexcept;
  std::chrono::microseconds interval_;
  Clock::time_point periodic_{};
  Clock::time_point last_sent_{};
  std::uint64_t random_{};
  bool broadcast_{};
  bool designated_{};
  bool sent_{};
  bool dirty_{true};
  bool pending_{};
};

} // namespace router::isis
