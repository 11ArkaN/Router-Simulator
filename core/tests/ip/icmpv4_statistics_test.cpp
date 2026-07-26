// ICMPv4 counter tests cover every category exposed by the SR OS report and
// the separate parse-error path. They use no RouterForwarder state so a wrong
// Type mapping fails independently of packet routing or CLI formatting.

#include "router/icmpv4_statistics.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void icmpv4_statistics_tests() {
  using namespace router::lab;

  Icmpv4DirectionStatistics statistics;
  constexpr std::array<std::uint8_t, 12U> types{
      0U, 3U, 4U, 5U, 8U, 11U, 12U, 13U, 14U, 17U, 18U, 42U};
  for (const auto type : types)
    count_icmpv4_message(statistics, type);
  count_icmpv4_error(statistics);

  require(statistics.total == types.size() + 1U && statistics.errors == 1U,
          "ICMPv4 total or error classification is incorrect");
  require(statistics.echo_reply == 1U &&
              statistics.destination_unreachable == 1U &&
              statistics.source_quench == 1U && statistics.redirects == 1U &&
              statistics.echo_request == 1U &&
              statistics.time_exceeded == 1U &&
              statistics.parameter_problem == 1U &&
              statistics.timestamp_request == 1U &&
              statistics.timestamp_reply == 1U &&
              statistics.address_mask_request == 1U &&
              statistics.address_mask_reply == 1U,
          "ICMPv4 Type did not reach its sourced operational category");
}
