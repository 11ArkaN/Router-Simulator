// ICMPv4 operational counters shared by forwarding checkpoints and the SR OS
// operational CLI. RouterForwarder is the only mutable owner. This module
// classifies wire Type values and has no dependency on routing, sessions or UI.

#pragma once

#include <cstdint>

namespace router::lab {

// SR OS 26.7 displays these counters in paired Received and Sent sections.
// Unknown informational Types still increase Total so future protocol values
// cannot disappear from accounting merely because the current CLI has no row.
struct Icmpv4DirectionStatistics {
  std::uint64_t total{};
  std::uint64_t errors{};
  std::uint64_t destination_unreachable{};
  std::uint64_t redirects{};
  std::uint64_t echo_request{};
  std::uint64_t echo_reply{};
  std::uint64_t time_exceeded{};
  std::uint64_t source_quench{};
  std::uint64_t timestamp_request{};
  std::uint64_t timestamp_reply{};
  std::uint64_t address_mask_request{};
  std::uint64_t address_mask_reply{};
  std::uint64_t parameter_problem{};

  bool operator==(const Icmpv4DirectionStatistics &) const = default;
};

struct Icmpv4Statistics {
  Icmpv4DirectionStatistics received{};
  Icmpv4DirectionStatistics sent{};

  bool operator==(const Icmpv4Statistics &) const = default;
};

// Preconditions: type is copied from a validated or sufficiently long ICMPv4
// header. Postcondition: Total and at most one displayed category advance.
// Every increment saturates so a long-lived lab cannot wrap a visible counter.
void count_icmpv4_message(Icmpv4DirectionStatistics &statistics,
                          std::uint8_t type) noexcept;

// A checksum, length or locally generated encoding failure belongs to both
// Total and Error in the operational view. The caller remains responsible for
// ensuring the failure reached the ICMP layer rather than an earlier IP check.
void count_icmpv4_error(Icmpv4DirectionStatistics &statistics) noexcept;

} // namespace router::lab
