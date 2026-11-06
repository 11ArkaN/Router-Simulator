// Complete OSPF generations move from the sole OSPF pthread to the sole route
// manager through fixed shared slots. Common ownership mechanics remain in
// the protocol SPSC channel; no OSPF state crosses this boundary.

#pragma once

#include "router/owned_spsc_channel.hpp"
#include "router/route_generation.hpp"

namespace router::ospf {
using RouteGeneration = routing::RouteGeneration;
template <std::size_t Capacity> class RouteGenerationChannel final {
public:
  using Handle = typename protocol::OwnedSpscChannel<RouteGeneration, Capacity>::Handle;
  struct Writable { Handle handle{}; RouteGeneration *generation{}; };
  struct Borrowed { Handle handle{}; const RouteGeneration *generation{}; };
  // One OSPF producer and one route-manager consumer. Capacity bounds in-flight
  // generations, not router scale. Both directions are FIFO release/acquire;
  // exhaustion is backpressure, and duplicate lease operations reject.
  [[nodiscard]] std::optional<Writable> try_acquire() noexcept {
    const auto lease = channel_.acquire();
    return lease ? std::optional{Writable{lease->handle, lease->value}} : std::nullopt;
  }
  [[nodiscard]] bool publish(Handle handle) noexcept { return channel_.publish(handle); }
  [[nodiscard]] bool cancel(Handle handle) noexcept { return channel_.cancel(handle); }
  [[nodiscard]] std::optional<Borrowed> try_receive() noexcept {
    const auto lease = channel_.receive();
    return lease ? std::optional{Borrowed{lease->handle, lease->value}} : std::nullopt;
  }
  [[nodiscard]] bool release(Handle handle) noexcept { return channel_.release(handle); }
private:
  protocol::OwnedSpscChannel<RouteGeneration, Capacity> channel_;
};
// One generation may be consumed while another is assembled. No installation
// receipt is implied by this legacy OSPF consumption-only transfer contract.
using RouteChannel = RouteGenerationChannel<2U>;
} // namespace router::ospf
