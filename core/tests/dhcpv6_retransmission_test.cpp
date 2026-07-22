// RFC 9915 reliability tests use injected steady-clock points. They verify
// randomized bounds, exact MRC semantics, duration termination and checkpoint
// continuity without sleeping or exposing a simulated clock to production.

#include "router/dhcpv6_retransmission.hpp"

#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void dhcpv6_retransmission_tests() {
  using namespace router::dhcpv6;
  using namespace std::chrono_literals;
  using Clock = Retransmission::Clock;
  const auto origin = Clock::time_point{} + 100s;

  require(parameters(ExchangeKind::solicit).maximum_initial_delay == 1s &&
              parameters(ExchangeKind::solicit)
                      .maximum_retransmission_time ==
                  3600s &&
              parameters(ExchangeKind::request).maximum_transmission_count ==
                  10U &&
              parameters(ExchangeKind::confirm)
                      .maximum_retransmission_duration ==
                  10s &&
              parameters(ExchangeKind::renew)
                      .initial_retransmission_time ==
                  10s &&
              parameters(ExchangeKind::rebind)
                      .maximum_retransmission_time ==
                  600s &&
              parameters(ExchangeKind::release)
                      .maximum_transmission_count ==
                  4U,
          "DHCPv6 exchange parameter table diverged from RFC 9915");

  Retransmission solicit;
  require(solicit.begin(ExchangeKind::solicit, 0x123456U, 0x10203040U,
                        origin),
          "DHCPv6 Solicit exchange did not start");
  const auto initial_deadline = solicit.next_deadline();
  require(initial_deadline && *initial_deadline >= origin &&
              *initial_deadline <= origin + 1s &&
              solicit.poll(*initial_deadline - 1ns) == ExchangeAction::none &&
              solicit.poll(*initial_deadline) == ExchangeAction::transmit &&
              solicit.transmissions() == 1U,
          "DHCPv6 initial Solicit delay or first transmission was invalid");
  const auto first_timeout = *solicit.next_deadline() - *initial_deadline;
  require(first_timeout >= 900ms && first_timeout <= 1100ms,
          "DHCPv6 first Solicit RT was outside the RFC RAND interval");

  Retransmission request;
  require(request.begin(ExchangeKind::request, 7U, 0x55667788U, origin),
          "DHCPv6 Request exchange did not start");
  for (std::uint16_t transmission = 1U; transmission <= 10U; ++transmission) {
    const auto deadline = request.next_deadline();
    require(deadline && request.poll(*deadline) == ExchangeAction::transmit &&
                request.transmissions() == transmission,
            "DHCPv6 Request stopped before REQ_MAX_RC");
  }
  require(request.next_deadline() &&
              request.poll(*request.next_deadline()) == ExchangeAction::failed &&
              !request.active(),
          "DHCPv6 Request exceeded REQ_MAX_RC");

  Retransmission confirm;
  require(confirm.begin(ExchangeKind::confirm, 8U, 0xa5a5a5a5U, origin),
          "DHCPv6 Confirm exchange did not start");
  auto confirm_time = *confirm.next_deadline();
  require(confirm.poll(confirm_time) == ExchangeAction::transmit,
          "DHCPv6 Confirm first send was unavailable");
  while (confirm.active()) {
    confirm_time = *confirm.next_deadline();
    const auto action = confirm.poll(confirm_time);
    if (action == ExchangeAction::failed)
      break;
  }
  require(!confirm.active() && confirm_time <= origin + 11s,
          "DHCPv6 Confirm did not terminate at CNF_MAX_RD");

  // Restored and uninterrupted owners must produce the same next randomized
  // timeout. The PRNG state is part of protocol state, not a test convenience.
  Retransmission uninterrupted;
  require(uninterrupted.begin(ExchangeKind::renew, 9U, 0xcafebabeU, origin) &&
              uninterrupted.poll(origin) == ExchangeAction::transmit,
          "DHCPv6 Renew fixture did not transmit");
  const auto saved_at = origin + 3s;
  const auto checkpoint = uninterrupted.checkpoint(saved_at);
  Retransmission restored;
  require(Retransmission::validate_checkpoint(checkpoint) &&
              restored.restore(checkpoint, saved_at) &&
              restored.next_deadline() == uninterrupted.next_deadline(),
          "DHCPv6 retransmission checkpoint changed its local deadline");
  const auto retry_at = *uninterrupted.next_deadline();
  require(uninterrupted.poll(retry_at) == ExchangeAction::transmit &&
              restored.poll(retry_at) == ExchangeAction::transmit &&
              restored.next_deadline() == uninterrupted.next_deadline(),
          "DHCPv6 restored RAND sequence diverged after retransmission");
  require(restored.elapsed_centiseconds(saved_at + 700s) == 65535U,
          "DHCPv6 Elapsed Time did not saturate at the wire maximum");

  auto invalid = checkpoint;
  invalid.transaction_id = 0x01000000U;
  require(!Retransmission::validate_checkpoint(invalid) &&
              !restored.restore(invalid, saved_at) &&
              !restored.begin(ExchangeKind::solicit, 1U, 0U, saved_at),
          "DHCPv6 reliability accepted invalid transaction or PRNG state");
}
