// Unit coverage for ICMPv6 counter classification and overflow behavior. The
// test deliberately covers every category printed by SR OS plus unknown types.

#include "router/icmpv6_statistics.hpp"

#include "router/neighbor_discovery_packet.hpp"
#include "router/packet.hpp"

#include <array>
#include <limits>
#include <stdexcept>

void icmpv6_statistics_tests() {
  using namespace router;
  using namespace router::lab;

  Icmpv6DirectionStatistics counters;
  const std::array types{
      packet::icmpv6_destination_unreachable_type,
      packet::icmpv6_packet_too_big_type,
      packet::icmpv6_time_exceeded_type,
      packet::icmpv6_parameter_problem_type,
      packet::icmpv6_echo_request_type,
      packet::icmpv6_echo_reply_type,
      packet::nd::router_solicitation_type,
      packet::nd::router_advertisement_type,
      packet::nd::neighbor_solicitation_type,
      packet::nd::neighbor_advertisement_type,
      packet::nd::redirect_type,
      static_cast<std::uint8_t>(250U)};
  for (const auto type : types)
    count_icmpv6_message(counters, type);

  if (counters.total != types.size() ||
      counters.destination_unreachable != 1U ||
      counters.packet_too_big != 1U || counters.time_exceeded != 1U ||
      counters.parameter_problem != 1U || counters.echo_request != 1U ||
      counters.echo_reply != 1U || counters.router_solicitation != 1U ||
      counters.router_advertisement != 1U ||
      counters.neighbor_solicitation != 1U ||
      counters.neighbor_advertisement != 1U || counters.redirects != 1U)
    throw std::runtime_error("ICMPv6 displayed type classification diverged");

  count_icmpv6_error(counters);
  count_icmpv6_discard(counters);
  if (counters.total != types.size() + 1U || counters.errors != 1U ||
      counters.discarded != 1U)
    throw std::runtime_error("ICMPv6 error or discard semantics diverged");

  counters.total = std::numeric_limits<std::uint64_t>::max();
  count_icmpv6_message(counters, 250U);
  if (counters.total != std::numeric_limits<std::uint64_t>::max())
    throw std::runtime_error("ICMPv6 counter wrapped instead of saturating");
}
