// Counter classification for RFC 4293 and the SR OS ICMPv6 operational view.
// All mutations happen on the calling forwarding shard and require no atomics.

#include "router/icmpv6_statistics.hpp"

#include "router/neighbor_discovery_packet.hpp"
#include "router/packet.hpp"

#include <limits>

namespace router::lab {
namespace {

void increment(std::uint64_t &counter) noexcept {
  // Operational counters are monotonic between explicit clears. Saturation is
  // preferable to modulo wrap because the public value is wider than the
  // Counter32 minimum in RFC 4293 and is checkpointed across browser reloads.
  if (counter != std::numeric_limits<std::uint64_t>::max())
    ++counter;
}

} // namespace

void count_icmpv6_message(Icmpv6DirectionStatistics &statistics,
                          std::uint8_t type) noexcept {
  increment(statistics.total);
  switch (type) {
  case packet::icmpv6_destination_unreachable_type:
    increment(statistics.destination_unreachable);
    break;
  case packet::icmpv6_packet_too_big_type:
    increment(statistics.packet_too_big);
    break;
  case packet::icmpv6_time_exceeded_type:
    increment(statistics.time_exceeded);
    break;
  case packet::icmpv6_parameter_problem_type:
    increment(statistics.parameter_problem);
    break;
  case packet::icmpv6_echo_request_type:
    increment(statistics.echo_request);
    break;
  case packet::icmpv6_echo_reply_type:
    increment(statistics.echo_reply);
    break;
  case packet::nd::router_solicitation_type:
    increment(statistics.router_solicitation);
    break;
  case packet::nd::router_advertisement_type:
    increment(statistics.router_advertisement);
    break;
  case packet::nd::neighbor_solicitation_type:
    increment(statistics.neighbor_solicitation);
    break;
  case packet::nd::neighbor_advertisement_type:
    increment(statistics.neighbor_advertisement);
    break;
  case packet::nd::redirect_type:
    increment(statistics.redirects);
    break;
  default:
    // RFC 4293 requires all type values to be counted. Nokia's compact output
    // has no row for MLD or unknown future types, so Total is their only field.
    break;
  }
}

void count_icmpv6_error(Icmpv6DirectionStatistics &statistics) noexcept {
  increment(statistics.total);
  increment(statistics.errors);
}

void count_icmpv6_discard(Icmpv6DirectionStatistics &statistics) noexcept {
  increment(statistics.discarded);
}

} // namespace router::lab
