// Control-owned RIB selection and immutable FIB programs consumed by
// forwarding. Route values contain no pointers and may cross the SPSC shard
// boundary.

#pragma once

#include "router/generated_profile.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace router::routing {

constexpr std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                             std::uint8_t d) noexcept {
  return static_cast<std::uint32_t>(a) << 24 |
         static_cast<std::uint32_t>(b) << 16 |
         static_cast<std::uint32_t>(c) << 8 | d;
}

constexpr std::uint32_t prefix_mask(std::uint8_t length) noexcept {
  // Addresses use network bit order inside uint32_t values. A zero-length
  // prefix needs a separate branch because shifting a 32-bit value by 32 is
  // undefined in C++ rather than a portable way to produce zero.
  return length ? 0xffffffffU << (32U - length) : 0;
}

struct HostNextHopInput {
  // Named fields prevent four integer address arguments from being reordered
  // at a call site while keeping the calculation allocation-free.
  std::uint32_t source{};
  std::uint8_t prefix_length{};
  std::uint32_t destination{};
  std::uint32_t gateway{};
};

constexpr std::uint32_t host_next_hop(HostNextHopInput input) noexcept {
  // Source: ietf.host_requirements.rfc1122. A host resolves the destination
  // itself when it is on-link and resolves its selected gateway otherwise.
  // Returning an IPv4 value keeps ARP responsible for deriving the MAC.
  const auto mask = prefix_mask(input.prefix_length);
  return (input.source & mask) == (input.destination & mask) ? input.destination
                                                             : input.gateway;
}

struct Route {
  // Routes contain values and indices only. A FIB program may cross a thread
  // boundary without leaking control-plane pointers into forwarding state.
  std::uint32_t network{};
  std::uint8_t prefix_length{};
  std::uint8_t port_index{};
  // Zero denotes a directly connected destination. A non-zero value is the
  // protocol address that adjacency resolution must use for a static route.
  std::uint32_t next_hop{};
};

struct FibProgram {
  // Generation makes programming monotonic. A delayed older message cannot
  // overwrite a newer forwarding table after a topology change.
  std::uint64_t generation{};
  std::array<Route, 8> entries{};
  std::uint8_t count{};
  std::array<bool, profile::port_count> port_operational{};
};

struct ConnectedRouteInput {
  // Runtime projects only route-relevant interface values. The route manager
  // cannot inspect hardware inventory, CLI sessions, counters or alarms.
  bool valid{};
  bool operational{};
  std::uint32_t network{};
  std::uint8_t prefix_length{};
  std::uint8_t port_index{};
};

struct StaticRouteInput {
  bool valid{};
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint8_t prefix_length{};
};

struct RibInput {
  // Fixed capacities mirror profile and configuration limits, so rebuilding a
  // RIB performs no allocation and the input may be assembled on the stack.
  std::array<ConnectedRouteInput, profile::port_count> connected{};
  std::uint8_t connected_count{};
  std::array<StaticRouteInput, 8> statics{};
};

class ConnectedRib final {
public:
  // The route manager is the sole owner of this RIB projection. rebuild returns
  // false when no operational input changed, avoiding redundant FIB messages.
  bool rebuild(const RibInput &input) noexcept;
  [[nodiscard]] std::span<const Route> entries() const noexcept {
    return {entries_.data(), count_};
  }
  [[nodiscard]] FibProgram compile(std::uint64_t generation) const noexcept;

private:
  std::array<Route, 8> entries_{};
  std::uint8_t count_{};
};

[[nodiscard]] bool lookup(const FibProgram &fib, std::uint32_t destination,
                          std::uint8_t &port_index,
                          std::uint32_t *next_hop = nullptr) noexcept;

} // namespace router::routing
