// IPv6 destination-side extension-header semantics. The packet parser owns
// structural bounds; this module decides option actions and exact ICMPv6
// Parameter Problem pointers without owning a route, interface or packet queue.

#pragma once

#include "router/packet.hpp"

#include <cstdint>

namespace router::packet {

enum class Ipv6ExtensionAction : std::uint8_t {
  accept,
  silent_discard,
  parameter_problem
};

struct Ipv6ExtensionValidation {
  Ipv6ExtensionAction action{Ipv6ExtensionAction::accept};
  // code and pointer are meaningful only for parameter_problem. The pointer
  // is relative to the first IPv6 header octet, exactly as RFC 4443 transmits.
  std::uint32_t pointer{};
  std::uint8_t code{};
  bool allow_multicast_response{};
};

// at_destination controls Destination Options and Routing processing.
// process_hop_by_hop is an explicit forwarding policy because RFC 8200 no
// longer requires every transit router to inspect Hop-by-Hop Options.
[[nodiscard]] Ipv6ExtensionValidation validate_ipv6_extensions(
    const Frame &frame, const Ipv6View &view, bool at_destination,
    bool process_hop_by_hop) noexcept;

} // namespace router::packet
