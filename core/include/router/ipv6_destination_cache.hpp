// Host-owned IPv6 Destination Cache for RFC 4861 Redirect processing. The
// owner stores only validated next-hop decisions and never routes a packet or
// mutates the Neighbor Cache directly. Forwarding asks for a value next hop,
// then resolves its link-layer address through the ordinary ND packet path.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/neighbor_discovery_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

struct Ipv6DestinationCheckpoint {
  packet::Ipv6 destination{};
  packet::Ipv6 next_hop{};
  // Redirect information remains valid only while ordinary routing selects
  // this same first hop. This anchor invalidates stale advice after an RA,
  // Prefix List or route change without requiring a global cache walk.
  packet::Ipv6 route_first_hop{};
  std::uint16_t port_ordinal{};
  std::uint64_t use_generation{};
};

class Ipv6DestinationCache final {
public:
  Ipv6DestinationCache();

  // The caller supplies the currently selected first-hop router for the ICMP
  // Destination Address. This is the state-dependent RFC 4861 section 8.1
  // validation that a wire codec cannot perform. A false return changes no
  // entry and must be treated as a silent Redirect discard.
  [[nodiscard]] bool accept_redirect(
      std::uint16_t port_ordinal, const packet::nd::RedirectView &redirect,
      const packet::Ipv6 &current_first_hop,
      const packet::Ipv6 &route_first_hop) noexcept;

  // A cached redirect is usable only while the same default or route-selected
  // first hop remains current. This prevents a stale redirect from a former
  // router overriding a later RA or route change.
  [[nodiscard]] packet::Ipv6 current_next_hop(
      std::uint16_t port_ordinal, const packet::Ipv6 &destination,
      const packet::Ipv6 &route_first_hop) noexcept;

  void remove_port(std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::vector<Ipv6DestinationCheckpoint> checkpoint() const;
  [[nodiscard]] static bool validate_checkpoint(
      std::span<const Ipv6DestinationCheckpoint> state) noexcept;
  [[nodiscard]] bool restore(
      std::span<const Ipv6DestinationCheckpoint> state) noexcept;

private:
  struct Entry {
    bool valid{};
    std::uint16_t port_ordinal{};
    packet::Ipv6 destination{};
    packet::Ipv6 next_hop{};
    packet::Ipv6 route_first_hop{};
    std::uint64_t use_generation{};
  };

  [[nodiscard]] Entry *find(std::uint16_t port_ordinal,
                            const packet::Ipv6 &destination) noexcept;
  [[nodiscard]] Entry *allocate() noexcept;
  void touch(Entry &entry) noexcept;

  // Capacity is generated from the selected runtime profile. The vector is
  // allocated once at owner construction, so Redirect receive and next-hop
  // lookup never allocate or retain pointers outside this owner turn.
  std::vector<Entry> entries_;
  std::uint64_t use_generation_{};
};

} // namespace router::lab
