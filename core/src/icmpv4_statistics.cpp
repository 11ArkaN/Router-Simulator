// ICMPv4 counter classification for RFC 792 and the SR OS 26.7 operational
// report. All mutations remain owner-affine and require no atomic operations.

#include "router/icmpv4_statistics.hpp"

#include <limits>

namespace router::lab {
namespace {

void increment(std::uint64_t &counter) noexcept {
  // Saturation preserves monotonicity and is preferable to reporting a lower
  // value after uint64_t wrap. Explicit CLI clear remains the only reset path.
  if (counter != std::numeric_limits<std::uint64_t>::max())
    ++counter;
}

} // namespace

void count_icmpv4_message(Icmpv4DirectionStatistics &statistics,
                          std::uint8_t type) noexcept {
  increment(statistics.total);
  switch (type) {
  case 0U:
    increment(statistics.echo_reply);
    break;
  case 3U:
    increment(statistics.destination_unreachable);
    break;
  case 4U:
    // Source Quench is historic and must not be generated, but SR OS retains
    // its received counter for wire observability and compatibility.
    increment(statistics.source_quench);
    break;
  case 5U:
    increment(statistics.redirects);
    break;
  case 8U:
    increment(statistics.echo_request);
    break;
  case 11U:
    increment(statistics.time_exceeded);
    break;
  case 12U:
    increment(statistics.parameter_problem);
    break;
  case 13U:
    increment(statistics.timestamp_request);
    break;
  case 14U:
    increment(statistics.timestamp_reply);
    break;
  case 17U:
    increment(statistics.address_mask_request);
    break;
  case 18U:
    increment(statistics.address_mask_reply);
    break;
  default:
    // Total is authoritative for a valid but undisplayed Type. No synthetic
    // "other" row is added because it does not exist in the sourced output.
    break;
  }
}

void count_icmpv4_error(Icmpv4DirectionStatistics &statistics) noexcept {
  increment(statistics.total);
  increment(statistics.errors);
}

} // namespace router::lab
