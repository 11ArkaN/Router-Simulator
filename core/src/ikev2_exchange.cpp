// RFC 7296 section 2.1 request/response reliability. Only the request sender
// schedules retransmission. The responder caches a response and sends it again
// solely after a duplicate request, avoiding an independent response timer.

#include "router/ikev2_exchange.hpp"

#include <algorithm>
#include <limits>

namespace router::ikev2 {
namespace {

template <typename Duration>
bool add_deadline(std::chrono::steady_clock::time_point now, Duration delay,
                  std::chrono::steady_clock::time_point &result) noexcept {
  using Clock = std::chrono::steady_clock;
  if (delay < Duration::zero())
    return false;
  const auto maximum_delay =
      std::chrono::duration_cast<Duration>(Clock::duration::max());
  if (delay > maximum_delay)
    return false;
  const auto clock_delay =
      std::chrono::duration_cast<Clock::duration>(delay);
  if (now.time_since_epoch() > Clock::duration::max() - clock_delay)
    return false;
  result = now + clock_delay;
  return true;
}

} // namespace

RequestTracker::RequestTracker(RetransmissionPolicy policy) noexcept
    : policy_(policy) {}

bool RequestTracker::policy_valid() const noexcept {
  return policy_.initial > std::chrono::milliseconds::zero() &&
         policy_.maximum >= policy_.initial &&
         policy_.maximum_retransmissions > 0U;
}

RequestStartResult RequestTracker::start(std::uint32_t message_id,
                                         std::uint64_t packet_token,
                                         Clock::time_point now) noexcept {
  if (active_)
    return RequestStartResult::request_already_active;
  if (!policy_valid())
    return RequestStartResult::invalid_policy;
  if (packet_token == 0U)
    return RequestStartResult::invalid_token;
  message_id_ = message_id;
  packet_token_ = packet_token;
  retransmissions_ = 0U;
  if (!add_deadline(now, policy_.initial, deadline_)) {
    packet_token_ = 0U;
    return RequestStartResult::invalid_policy;
  }
  active_ = true;
  return RequestStartResult::started;
}

ResponseResult RequestTracker::receive_response(std::uint32_t message_id) noexcept {
  if (!active_)
    return ResponseResult::unexpected;
  if (message_id != message_id_)
    return message_id < message_id_ ? ResponseResult::stale
                                    : ResponseResult::unexpected;
  active_ = false;
  packet_token_ = 0U;
  return ResponseResult::matched;
}

std::chrono::milliseconds RequestTracker::interval() const noexcept {
  auto result = policy_.initial;
  for (std::uint8_t index = 0U; index < retransmissions_; ++index) {
    if (result >= policy_.maximum / 2)
      return policy_.maximum;
    result *= 2;
  }
  return std::min(result, policy_.maximum);
}

RequestTimerResult RequestTracker::poll(Clock::time_point now) noexcept {
  if (!active_ || now < deadline_)
    return {};
  if (retransmissions_ >= policy_.maximum_retransmissions) {
    const auto failed_id = message_id_;
    active_ = false;
    packet_token_ = 0U;
    return {.action = RequestTimerAction::exchange_failed,
            .packet_token = 0U,
            .message_id = failed_id};
  }
  ++retransmissions_;
  // Anchor the next interval at the actual owner turn. A suspended browser does
  // not trigger a burst of historical retransmissions or fast-forward IKE time.
  if (!add_deadline(now, interval(), deadline_)) {
    const auto failed_id = message_id_;
    active_ = false;
    packet_token_ = 0U;
    return {.action = RequestTimerAction::exchange_failed,
            .packet_token = 0U,
            .message_id = failed_id};
  }
  return {.action = RequestTimerAction::retransmit,
          .packet_token = packet_token_,
          .message_id = message_id_};
}

std::optional<RequestTracker::Clock::time_point>
RequestTracker::next_deadline() const noexcept {
  return active_ ? std::optional<Clock::time_point>{deadline_} : std::nullopt;
}

RequestCheckpoint RequestTracker::checkpoint(Clock::time_point now) const noexcept {
  return {.active = active_,
          .message_id = message_id_,
          .packet_token = packet_token_,
          .retransmissions = retransmissions_,
          .remaining_nanoseconds =
              active_ ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                            deadline_ > now ? deadline_ - now
                                            : Clock::duration::zero())
                            .count()
                      : 0};
}

bool RequestTracker::restore(const RequestCheckpoint &checkpoint_value,
                             Clock::time_point now) noexcept {
  if (!policy_valid() ||
      (checkpoint_value.active && checkpoint_value.packet_token == 0U) ||
      checkpoint_value.retransmissions > policy_.maximum_retransmissions ||
      checkpoint_value.remaining_nanoseconds < 0)
    return false;
  Clock::time_point restored_deadline{};
  if (!add_deadline(
          now,
          std::chrono::nanoseconds{checkpoint_value.active
                                       ? checkpoint_value.remaining_nanoseconds
                                       : 0},
          restored_deadline))
    return false;
  active_ = checkpoint_value.active;
  message_id_ = checkpoint_value.message_id;
  packet_token_ = checkpoint_value.active ? checkpoint_value.packet_token : 0U;
  retransmissions_ = checkpoint_value.retransmissions;
  deadline_ = restored_deadline;
  return true;
}

InboundRequestDecision
ResponderMessageIds::receive(std::uint32_t message_id) noexcept {
  if (message_id == expected_ && !request_pending_) {
    request_pending_ = true;
    return {.result = InboundRequestResult::new_request,
            .response_token = 0U};
  }
  if (message_id == expected_)
    return {.result = InboundRequestResult::duplicate_response_not_ready,
            .response_token = 0U};
  if (has_completed_ && message_id == last_completed_) {
    return {.result = response_token_ != 0U
                          ? InboundRequestResult::duplicate_with_cached_response
                          : InboundRequestResult::duplicate_response_not_ready,
            .response_token = response_token_};
  }
  return {};
}

bool ResponderMessageIds::cache_response(std::uint32_t message_id,
                                         std::uint64_t packet_token) noexcept {
  if (!request_pending_ || message_id != expected_ || packet_token == 0U ||
      expected_ == std::numeric_limits<std::uint32_t>::max())
    return false;
  last_completed_ = message_id;
  response_token_ = packet_token;
  has_completed_ = true;
  request_pending_ = false;
  ++expected_;
  return true;
}

ResponderCheckpoint ResponderMessageIds::checkpoint() const noexcept {
  return {.expected = expected_,
          .last_completed = last_completed_,
          .response_token = response_token_,
          .has_completed = has_completed_,
          .request_pending = request_pending_};
}

bool ResponderMessageIds::restore(
    const ResponderCheckpoint &checkpoint_value) noexcept {
  return restore(checkpoint_value.expected, checkpoint_value.has_completed,
                 checkpoint_value.last_completed,
                 checkpoint_value.response_token,
                 checkpoint_value.request_pending);
}

bool ResponderMessageIds::restore(std::uint32_t expected, bool has_completed,
                                  std::uint32_t last_completed,
                                  std::uint64_t response_token,
                                  bool request_pending) noexcept {
  if ((has_completed && (response_token == 0U || expected == 0U ||
                         last_completed != expected - 1U)) ||
      (!has_completed &&
       (expected != 0U || last_completed != 0U || response_token != 0U)))
    return false;
  expected_ = expected;
  has_completed_ = has_completed;
  last_completed_ = last_completed;
  response_token_ = response_token;
  request_pending_ = request_pending;
  return true;
}

} // namespace router::ikev2
