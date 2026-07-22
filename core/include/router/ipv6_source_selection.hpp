// RFC 6724 source-address selection over immutable candidate values. The
// caller owns interface and lifetime state; this module performs no routing,
// allocation, timer work or mutation and may be used by hosts and routers.

#pragma once

#include "router/ip_address.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace router::ip {

enum class Ipv6Scope : std::uint8_t {
  interface_local = 1,
  link_local = 2,
  admin_local = 4,
  site_local = 5,
  organization_local = 8,
  global = 14
};

struct Ipv6SourceCandidate {
  // interface_id is a stable control-plane identity, not a current array
  // ordinal. A hardware rebuild therefore cannot change Rule 5 comparisons.
  Ipv6 address{};
  std::uint64_t interface_id{};
  std::uint8_t prefix_length{};
  bool preferred{true};
  bool home{};
  bool care_of{};
  bool temporary{};
  bool advertised_by_next_hop{};
};

struct Ipv6SourceSelectionContext {
  Ipv6 destination{};
  std::uint64_t outgoing_interface_id{};
  // RFC 6724 requires an application mechanism to reverse Rule 7. Keeping the
  // policy in the call value avoids one global preference shared by sessions.
  bool prefer_temporary{true};
  bool track_advertising_next_hop{};
};

[[nodiscard]] Ipv6Scope ipv6_scope(const Ipv6 &address) noexcept;
[[nodiscard]] std::uint8_t ipv6_policy_label(const Ipv6 &address) noexcept;
[[nodiscard]] std::uint8_t ipv6_common_prefix_length(
    const Ipv6 &first, const Ipv6 &second,
    std::uint8_t maximum = ipv6_address_bits) noexcept;

// Preconditions: candidates is stable for the duration of the call. Invalid
// entries such as multicast, unspecified or prefix lengths over 128 are
// ignored. Postcondition: the returned index refers to the original span and
// no candidate state has changed. nullopt means no legal source exists.
[[nodiscard]] std::optional<std::size_t> select_ipv6_source(
    std::span<const Ipv6SourceCandidate> candidates,
    const Ipv6SourceSelectionContext &context) noexcept;

} // namespace router::ip
