// IKEv2 reliability tests use explicit steady-clock points. They prove that
// only requests own timers, duplicate requests reuse cached responses and
// checkpoint restore preserves the next real-time deadline.

#include "router/ikev2_exchange.hpp"

#include <chrono>
#include <stdexcept>

void ikev2_exchange_tests() {
  using namespace router::ikev2;
  using Clock = RequestTracker::Clock;
  const auto start = Clock::time_point{} + std::chrono::seconds{10};
  RequestTracker requests{{.initial = std::chrono::milliseconds{500},
                           .maximum = std::chrono::milliseconds{2000},
                           .maximum_retransmissions = 3U}};
  if (requests.start(0U, 41U, start) != RequestStartResult::started ||
      requests.poll(start + std::chrono::milliseconds{499}).action !=
          RequestTimerAction::none)
    throw std::runtime_error("IKEv2 request timer started incorrectly");

  const auto first = requests.poll(start + std::chrono::milliseconds{500});
  if (first.action != RequestTimerAction::retransmit ||
      first.packet_token != 41U || first.message_id != 0U ||
      requests.next_deadline() !=
          start + std::chrono::milliseconds{1500})
    throw std::runtime_error("IKEv2 first retransmission interval failed");

  // A stale or future response cannot cancel the outstanding request. The
  // matching response does, and subsequent poll turns remain idle.
  if (requests.receive_response(1U) != ResponseResult::unexpected ||
      requests.receive_response(0U) != ResponseResult::matched ||
      requests.next_deadline() ||
      requests.poll(start + std::chrono::seconds{30}).action !=
          RequestTimerAction::none)
    throw std::runtime_error("IKEv2 response Message ID matching failed");

  RequestTracker restored{{.initial = std::chrono::milliseconds{500},
                           .maximum = std::chrono::milliseconds{2000},
                           .maximum_retransmissions = 3U}};
  if (restored.start(7U, 99U, start) != RequestStartResult::started)
    throw std::runtime_error("IKEv2 checkpoint request setup failed");
  const auto image = restored.checkpoint(start + std::chrono::milliseconds{200});
  const auto restore_time = start + std::chrono::seconds{5};
  RequestTracker destination{{.initial = std::chrono::milliseconds{500},
                              .maximum = std::chrono::milliseconds{2000},
                              .maximum_retransmissions = 3U}};
  if (!destination.restore(image, restore_time) ||
      destination.next_deadline() !=
          restore_time + std::chrono::milliseconds{300} ||
      destination.poll(restore_time + std::chrono::milliseconds{299}).action !=
          RequestTimerAction::none ||
      destination.poll(restore_time + std::chrono::milliseconds{300}).action !=
          RequestTimerAction::retransmit)
    throw std::runtime_error("IKEv2 relative timer checkpoint failed");

  // A responder never schedules a response retransmission. It marks a request
  // in progress, caches the emitted packet token and reuses it only if the peer
  // repeats the completed Message ID.
  ResponderMessageIds responder;
  const auto new_request = responder.receive(0U);
  const auto in_progress_duplicate = responder.receive(0U);
  if (new_request.result != InboundRequestResult::new_request ||
      in_progress_duplicate.result !=
          InboundRequestResult::duplicate_response_not_ready ||
      !responder.cache_response(0U, 500U) || responder.expected() != 1U)
    throw std::runtime_error("IKEv2 responder request ownership failed");
  const auto duplicate = responder.receive(0U);
  if (duplicate.result !=
          InboundRequestResult::duplicate_with_cached_response ||
      duplicate.response_token != 500U ||
      responder.receive(2U).result != InboundRequestResult::outside_window)
    throw std::runtime_error("IKEv2 cached response handling failed");
}
