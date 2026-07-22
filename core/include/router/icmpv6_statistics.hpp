// ICMPv6 operational counter primitives shared by forwarding owners and CLI
// snapshots. RouterForwarder is the sole mutable owner. This module depends
// only on wire type values and never reaches into a device, session or UI.

#pragma once

#include <cstdint>

namespace router::lab {

// Nokia's operational display names a stable subset of the RFC 4293
// per-message counters. Unknown and MLD types still contribute to Total, but
// do not acquire a fabricated SR OS display category.
struct Icmpv6DirectionStatistics {
  std::uint64_t total{};
  std::uint64_t errors{};
  std::uint64_t destination_unreachable{};
  std::uint64_t redirects{};
  std::uint64_t time_exceeded{};
  std::uint64_t packet_too_big{};
  std::uint64_t echo_request{};
  std::uint64_t echo_reply{};
  std::uint64_t router_solicitation{};
  std::uint64_t router_advertisement{};
  std::uint64_t neighbor_solicitation{};
  std::uint64_t neighbor_advertisement{};
  std::uint64_t parameter_problem{};
  // SR OS exposes Discarded only in the Sent half. Keeping the field in this
  // direction-neutral value makes checkpoint and formatting code symmetric;
  // receive-side callers leave it zero.
  std::uint64_t discarded{};

  bool operator==(const Icmpv6DirectionStatistics &) const = default;
};

struct Icmpv6Statistics {
  Icmpv6DirectionStatistics received{};
  Icmpv6DirectionStatistics sent{};

  bool operator==(const Icmpv6Statistics &) const = default;
};

// Preconditions: type is the exact 8-bit ICMPv6 Type field from a validated
// or at least long-enough ICMPv6 message. Postcondition: Total and at most one
// displayed type counter increase with saturating arithmetic. Saturation keeps
// a long-running browser lab from wrapping an operational counter backwards.
void count_icmpv6_message(Icmpv6DirectionStatistics &statistics,
                          std::uint8_t type) noexcept;

// Records an ICMP-layer parse/checksum/length failure. RFC 4293 explicitly
// includes these messages in Total, so the two counters advance together.
void count_icmpv6_error(Icmpv6DirectionStatistics &statistics) noexcept;

// Records an ICMPv6 generation attempt that SR OS discarded because of its
// ICMP policy, for example an exceeded Redirect rate. It is not an OutErrors
// increment because RFC 4293 reserves that counter for failures inside ICMP.
void count_icmpv6_discard(Icmpv6DirectionStatistics &statistics) noexcept;

} // namespace router::lab
