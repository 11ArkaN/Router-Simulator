// RFC 9915 client exchange reliability primitive. One DHCPv6 client owner
// mutates one instance. The class owns deadlines and deterministic PRNG state,
// but never sends packets or inspects another endpoint, UDP socket or link.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace router::dhcpv6 {

enum class ExchangeKind : std::uint8_t {
  solicit,
  request,
  confirm,
  renew,
  rebind,
  information_request,
  release,
  decline
};

enum class ExchangeAction : std::uint8_t { none, transmit, failed };

struct RetransmissionParameters {
  std::chrono::seconds initial_retransmission_time{};
  std::chrono::seconds maximum_retransmission_time{};
  std::chrono::seconds maximum_retransmission_duration{};
  std::chrono::milliseconds maximum_initial_delay{};
  std::uint16_t maximum_transmission_count{};
};

// This mapping is protocol data from RFC 9915 Table 1 and sections 18.2.1
// through 18.2.8. A zero count or duration has the RFC meaning "unlimited".
[[nodiscard]] RetransmissionParameters
parameters(ExchangeKind kind) noexcept;

struct RetransmissionCheckpoint {
  std::int64_t next_deadline_remaining_nanoseconds{};
  std::int64_t first_transmission_ago_nanoseconds{};
  std::int64_t previous_timeout_nanoseconds{};
  std::int64_t maximum_retransmission_override_nanoseconds{};
  std::uint32_t transaction_id{};
  std::uint32_t random_state{};
  std::uint16_t transmissions{};
  ExchangeKind kind{ExchangeKind::solicit};
  bool active{};
  bool transmitted{};
};

class Retransmission final {
public:
  using Clock = std::chrono::steady_clock;

  // Preconditions: transaction_id occupies the DHCPv6 24-bit domain and seed
  // is nonzero. A new exchange atomically replaces prior inactive or active
  // state. The first poll transmits immediately except for exchanges whose RFC
  // procedure requires a randomized initial delay.
  [[nodiscard]] bool begin(ExchangeKind kind, std::uint32_t transaction_id,
                           std::uint32_t seed,
                           Clock::time_point now = Clock::now(),
                           std::chrono::seconds maximum_retransmission_time =
                               std::chrono::seconds::zero()) noexcept;

  // SOL_MAX_RT and INF_MAX_RT may arrive after the first transmission. This
  // setter affects subsequent backoff calculations without moving the current
  // deadline, which RFC 9915 already derived from the prior parameter value.
  void set_maximum_retransmission_time(
      std::chrono::seconds maximum_retransmission_time) noexcept;

  // Poll is owner-affine and side-effecting. `transmit` means the caller must
  // rebuild the same exchange message with its unchanged transaction ID and
  // updated Elapsed Time option, then submit bytes through UDP. The reliability
  // owner never treats an attempted action as successful packet delivery.
  [[nodiscard]] ExchangeAction
  poll(Clock::time_point now = Clock::now()) noexcept;
  void complete() noexcept;

  [[nodiscard]] bool active() const noexcept { return active_; }
  [[nodiscard]] std::uint32_t transaction_id() const noexcept {
    return transaction_id_;
  }
  [[nodiscard]] std::uint16_t transmissions() const noexcept {
    return transmissions_;
  }
  [[nodiscard]] std::uint16_t
  elapsed_centiseconds(Clock::time_point now = Clock::now()) const noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  [[nodiscard]] RetransmissionCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const noexcept;
  [[nodiscard]] static bool
  validate_checkpoint(const RetransmissionCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const RetransmissionCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  [[nodiscard]] std::uint32_t random() noexcept;
  [[nodiscard]] std::chrono::nanoseconds
  randomized(std::chrono::nanoseconds base) noexcept;
  [[nodiscard]] std::chrono::nanoseconds next_timeout() noexcept;

  Clock::time_point next_deadline_{Clock::time_point::max()};
  Clock::time_point first_transmission_{};
  std::chrono::nanoseconds previous_timeout_{};
  std::chrono::nanoseconds maximum_retransmission_override_{};
  std::uint32_t transaction_id_{};
  std::uint32_t random_state_{};
  std::uint16_t transmissions_{};
  ExchangeKind kind_{ExchangeKind::solicit};
  bool active_{};
  bool transmitted_{};
};

} // namespace router::dhcpv6
