// IKEv2 request retransmission and directional Message ID ownership. One IKE
// service shard owns each tracker. Encoded requests and cached responses remain
// in that shard's bounded packet store and are referenced by opaque tokens, so
// timers never copy datagrams or send directly to another device.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace router::ikev2 {

struct RetransmissionPolicy {
  // RFC 7296 does not mandate concrete intervals. Values are supplied by the
  // release timing profile or measured peer profile, never invented here.
  std::chrono::milliseconds initial{};
  std::chrono::milliseconds maximum{};
  std::uint8_t maximum_retransmissions{};
};

enum class RequestStartResult : std::uint8_t {
  started,
  request_already_active,
  invalid_policy,
  invalid_token
};

enum class ResponseResult : std::uint8_t { matched, stale, unexpected };
enum class RequestTimerAction : std::uint8_t {
  none,
  retransmit,
  exchange_failed
};

struct RequestTimerResult {
  RequestTimerAction action{RequestTimerAction::none};
  std::uint64_t packet_token{};
  std::uint32_t message_id{};
};

struct RequestCheckpoint {
  bool active{};
  std::uint32_t message_id{};
  std::uint64_t packet_token{};
  std::uint8_t retransmissions{};
  std::int64_t remaining_nanoseconds{};
};

class RequestTracker final {
public:
  using Clock = std::chrono::steady_clock;

  explicit RequestTracker(RetransmissionPolicy policy) noexcept;

  // The initial datagram has already entered the UDP output owner when start is
  // called. maximum_retransmissions therefore counts only later transmissions.
  [[nodiscard]] RequestStartResult
  start(std::uint32_t message_id, std::uint64_t packet_token,
        Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ResponseResult receive_response(std::uint32_t message_id) noexcept;
  [[nodiscard]] RequestTimerResult
  poll(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  [[nodiscard]] RequestCheckpoint checkpoint(Clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const RequestCheckpoint &checkpoint,
                             Clock::time_point now) noexcept;

private:
  [[nodiscard]] bool policy_valid() const noexcept;
  [[nodiscard]] std::chrono::milliseconds interval() const noexcept;

  RetransmissionPolicy policy_{};
  Clock::time_point deadline_{};
  std::uint32_t message_id_{};
  std::uint64_t packet_token_{};
  std::uint8_t retransmissions_{};
  bool active_{};
};

enum class InboundRequestResult : std::uint8_t {
  new_request,
  duplicate_with_cached_response,
  duplicate_response_not_ready,
  outside_window
};

struct InboundRequestDecision {
  InboundRequestResult result{InboundRequestResult::outside_window};
  std::uint64_t response_token{};
};

struct ResponderCheckpoint {
  std::uint32_t expected{};
  std::uint32_t last_completed{};
  std::uint64_t response_token{};
  bool has_completed{};
  bool request_pending{};
};

class ResponderMessageIds final {
public:
  // Default IKEv2 window size is one. Future SET_WINDOW_SIZE support may allow
  // multiple in-flight IDs, but this owner never pretends a larger window.
  [[nodiscard]] InboundRequestDecision receive(std::uint32_t message_id) noexcept;
  [[nodiscard]] bool cache_response(std::uint32_t message_id,
                                    std::uint64_t packet_token) noexcept;

  [[nodiscard]] std::uint32_t expected() const noexcept { return expected_; }
  [[nodiscard]] std::optional<std::uint32_t> last_completed() const noexcept {
    return has_completed_ ? std::optional<std::uint32_t>{last_completed_}
                          : std::nullopt;
  }
  [[nodiscard]] ResponderCheckpoint checkpoint() const noexcept;
  [[nodiscard]] bool restore(const ResponderCheckpoint &checkpoint) noexcept;

  // Kept as a narrow compatibility overload for existing isolated tests. New
  // owners persist the named value contract above.
  [[nodiscard]] bool restore(std::uint32_t expected, bool has_completed,
                             std::uint32_t last_completed,
                             std::uint64_t response_token,
                             bool request_pending = false) noexcept;

private:
  std::uint32_t expected_{};
  std::uint32_t last_completed_{};
  std::uint64_t response_token_{};
  bool has_completed_{};
  bool request_pending_{};
};

} // namespace router::ikev2
