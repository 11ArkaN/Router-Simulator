// Host-clock implementation of RFC 9915 sections 14 and 15. No global event
// queue exists: the client owner asks for the local deadline and polls it after
// a real steady_clock wake-up.

#include "router/dhcpv6_retransmission.hpp"

#include <algorithm>
#include <limits>

namespace router::dhcpv6 {
namespace {

using namespace std::chrono_literals;

constexpr std::uint32_t maximum_transaction_id = 0x00ffffffU;

[[nodiscard]] bool valid_kind(ExchangeKind kind) noexcept {
  return kind <= ExchangeKind::decline;
}

} // namespace

RetransmissionParameters parameters(ExchangeKind kind) noexcept {
  // Values are written beside their named RFC constants rather than shared as
  // anonymous numbers. That makes a standards update reviewable without
  // changing state-machine code or introducing per-command timing branches.
  switch (kind) {
  case ExchangeKind::solicit:
    return {.initial_retransmission_time = 1s,     // SOL_TIMEOUT
            .maximum_retransmission_time = 3600s, // SOL_MAX_RT
            .maximum_initial_delay = 1000ms};     // SOL_MAX_DELAY
  case ExchangeKind::request:
    return {.initial_retransmission_time = 1s,   // REQ_TIMEOUT
            .maximum_retransmission_time = 30s, // REQ_MAX_RT
            .maximum_transmission_count = 10U}; // REQ_MAX_RC
  case ExchangeKind::confirm:
    return {.initial_retransmission_time = 1s,    // CNF_TIMEOUT
            .maximum_retransmission_time = 4s,   // CNF_MAX_RT
            .maximum_retransmission_duration = 10s, // CNF_MAX_RD
            .maximum_initial_delay = 1000ms};    // CNF_MAX_DELAY
  case ExchangeKind::renew:
    // MRD is the caller's T2 boundary, so the generic protocol table leaves it
    // zero. The IA lifecycle owner terminates Renew and starts Rebind at T2.
    return {.initial_retransmission_time = 10s,     // REN_TIMEOUT
            .maximum_retransmission_time = 600s};  // REN_MAX_RT
  case ExchangeKind::rebind:
    // MRD is the last valid-lifetime boundary and remains IA-owner policy.
    return {.initial_retransmission_time = 10s,     // REB_TIMEOUT
            .maximum_retransmission_time = 600s};  // REB_MAX_RT
  case ExchangeKind::information_request:
    return {.initial_retransmission_time = 1s,      // INF_TIMEOUT
            .maximum_retransmission_time = 3600s,  // INF_MAX_RT
            .maximum_initial_delay = 1000ms};      // INF_MAX_DELAY
  case ExchangeKind::release:
    return {.initial_retransmission_time = 1s,      // REL_TIMEOUT
            .maximum_transmission_count = 4U};     // REL_MAX_RC
  case ExchangeKind::decline:
    return {.initial_retransmission_time = 1s,      // DEC_TIMEOUT
            .maximum_transmission_count = 4U};     // DEC_MAX_RC
  }
  return {};
}

std::uint32_t Retransmission::random() noexcept {
  // xorshift32 is intentionally not cryptographic. RFC 9915 permits that for
  // RAND, while requiring different invocation sequences. The client owner
  // supplies a persisted nonzero seed and separately generates an unpredictable
  // transaction ID; this PRNG never substitutes for the transaction ID source.
  auto value = random_state_;
  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  random_state_ = value;
  return value;
}

std::chrono::nanoseconds
Retransmission::randomized(std::chrono::nanoseconds base) noexcept {
  // Map 32 random bits uniformly to 200001 integer points representing
  // -100000 through +100000 millionths. Integer arithmetic makes native and
  // Wasm deadlines identical and avoids floating-point rounding drift.
  constexpr std::int64_t scale = 1'000'000;
  constexpr std::uint64_t points = 200'001U;
  const auto signed_factor = static_cast<std::int64_t>(
                                 (static_cast<std::uint64_t>(random()) * points) >>
                                 32U) -
                             100'000;
  const auto delta = (base.count() / scale) * signed_factor;
  return base + std::chrono::nanoseconds{delta};
}

std::chrono::nanoseconds Retransmission::next_timeout() noexcept {
  const auto config = parameters(kind_);
  const auto maximum = maximum_retransmission_override_.count() != 0
                           ? maximum_retransmission_override_
                           : std::chrono::duration_cast<
                                 std::chrono::nanoseconds>(
                                 config.maximum_retransmission_time);
  auto timeout = previous_timeout_.count() == 0
                     ? randomized(config.initial_retransmission_time)
                     : randomized(previous_timeout_ * 2);
  if (maximum.count() != 0 && timeout > maximum)
    timeout = randomized(maximum);
  previous_timeout_ = timeout;
  return timeout;
}

bool Retransmission::begin(ExchangeKind kind, std::uint32_t transaction_id,
                           std::uint32_t seed, Clock::time_point now,
                           std::chrono::seconds maximum_retransmission_time)
    noexcept {
  const bool override_kind = kind == ExchangeKind::solicit ||
                             kind == ExchangeKind::information_request;
  if (!valid_kind(kind) || transaction_id > maximum_transaction_id || !seed ||
      maximum_retransmission_time.count() < 0 ||
      (maximum_retransmission_time.count() != 0 && !override_kind))
    return false;
  kind_ = kind;
  transaction_id_ = transaction_id;
  random_state_ = seed;
  transmissions_ = 0U;
  previous_timeout_ = {};
  maximum_retransmission_override_ = maximum_retransmission_time;
  first_transmission_ = {};
  active_ = true;
  transmitted_ = false;
  const auto initial_delay = parameters(kind).maximum_initial_delay;
  if (initial_delay.count() == 0) {
    next_deadline_ = now;
  } else {
    // Inclusive uniform selection over nanoseconds would require a wider
    // multiply. Millisecond resolution is well below the protocol's one-second
    // bound and matches the scheduler's observable deadline resolution.
    const auto slots = static_cast<std::uint64_t>(initial_delay.count()) + 1U;
    const auto delay = (static_cast<std::uint64_t>(random()) * slots) >> 32U;
    next_deadline_ = now + std::chrono::milliseconds{delay};
  }
  return true;
}

void Retransmission::set_maximum_retransmission_time(
    std::chrono::seconds maximum_retransmission_time) noexcept {
  if (active_ && (kind_ == ExchangeKind::solicit ||
                  kind_ == ExchangeKind::information_request) &&
      maximum_retransmission_time.count() > 0)
    maximum_retransmission_override_ = maximum_retransmission_time;
}

ExchangeAction Retransmission::poll(Clock::time_point now) noexcept {
  if (!active_ || now < next_deadline_)
    return ExchangeAction::none;
  const auto config = parameters(kind_);
  if (transmitted_) {
    const bool count_exhausted = config.maximum_transmission_count != 0U &&
                                 transmissions_ >=
                                     config.maximum_transmission_count;
    const bool duration_exhausted =
        config.maximum_retransmission_duration.count() != 0 &&
        now - first_transmission_ >= config.maximum_retransmission_duration;
    if (count_exhausted || duration_exhausted) {
      complete();
      return ExchangeAction::failed;
    }
  } else {
    first_transmission_ = now;
    transmitted_ = true;
  }
  if (transmissions_ != std::numeric_limits<std::uint16_t>::max())
    ++transmissions_;
  const auto timeout = next_timeout();
  next_deadline_ = now + timeout;
  if (config.maximum_retransmission_duration.count() != 0) {
    const auto end = first_transmission_ +
                     config.maximum_retransmission_duration;
    if (next_deadline_ > end)
      next_deadline_ = end;
  }
  return ExchangeAction::transmit;
}

void Retransmission::complete() noexcept {
  active_ = false;
  next_deadline_ = Clock::time_point::max();
}

std::uint16_t Retransmission::elapsed_centiseconds(
    Clock::time_point now) const noexcept {
  if (!transmitted_ || now <= first_transmission_)
    return 0U;
  const auto value = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - first_transmission_)
                         .count() /
                     10;
  return static_cast<std::uint16_t>(
      std::min<std::int64_t>(value,
                             std::numeric_limits<std::uint16_t>::max()));
}

std::optional<Retransmission::Clock::time_point>
Retransmission::next_deadline() const noexcept {
  return active_ ? std::optional{next_deadline_} : std::nullopt;
}

RetransmissionCheckpoint Retransmission::checkpoint(
    Clock::time_point now) const noexcept {
  return {
      .next_deadline_remaining_nanoseconds =
          active_ ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                        next_deadline_ > now ? next_deadline_ - now
                                             : Clock::duration::zero())
                        .count()
                  : 0,
      .first_transmission_ago_nanoseconds =
          transmitted_
              ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                    now > first_transmission_ ? now - first_transmission_
                                              : Clock::duration::zero())
                    .count()
              : 0,
      .previous_timeout_nanoseconds = previous_timeout_.count(),
      .maximum_retransmission_override_nanoseconds =
          maximum_retransmission_override_.count(),
      .transaction_id = transaction_id_,
      .random_state = random_state_,
      .transmissions = transmissions_,
      .kind = kind_,
      .active = active_,
      .transmitted = transmitted_};
}

bool Retransmission::validate_checkpoint(
    const RetransmissionCheckpoint &state) noexcept {
  if (!valid_kind(state.kind) || state.transaction_id > maximum_transaction_id ||
      (state.active && !state.random_state) ||
      state.next_deadline_remaining_nanoseconds < 0 ||
      state.first_transmission_ago_nanoseconds < 0 ||
      state.previous_timeout_nanoseconds < 0 ||
      state.maximum_retransmission_override_nanoseconds < 0 ||
      state.transmitted != (state.transmissions != 0U) ||
      (!state.active && state.next_deadline_remaining_nanoseconds != 0))
    return false;
  const auto config = parameters(state.kind);
  const auto override = std::chrono::nanoseconds{
      state.maximum_retransmission_override_nanoseconds};
  const auto override_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(override);
  const bool valid_override =
      override.count() == 0 ||
      ((state.kind == ExchangeKind::solicit ||
        state.kind == ExchangeKind::information_request) &&
       override == override_seconds && override_seconds.count() >= 60 &&
       override_seconds.count() <= 86400);
  if (!valid_override)
    return false;
  if (config.maximum_transmission_count != 0U &&
      state.transmissions > config.maximum_transmission_count)
    return false;
  return true;
}

bool Retransmission::restore(const RetransmissionCheckpoint &state,
                             Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  kind_ = state.kind;
  transaction_id_ = state.transaction_id;
  random_state_ = state.random_state;
  transmissions_ = state.transmissions;
  previous_timeout_ =
      std::chrono::nanoseconds{state.previous_timeout_nanoseconds};
  maximum_retransmission_override_ = std::chrono::nanoseconds{
      state.maximum_retransmission_override_nanoseconds};
  first_transmission_ =
      now - std::chrono::nanoseconds{state.first_transmission_ago_nanoseconds};
  active_ = state.active;
  transmitted_ = state.transmitted;
  next_deadline_ =
      active_ ? now + std::chrono::nanoseconds{
                          state.next_deadline_remaining_nanoseconds}
              : Clock::time_point::max();
  return true;
}

} // namespace router::dhcpv6
