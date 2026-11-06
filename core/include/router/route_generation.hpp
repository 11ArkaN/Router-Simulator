// Complete local protocol route generations cross ownership as immutable values.
// The selected protocol owns construction, and the router RIB owner validates
// and merges accepted generations. No LSDB or foreign router state is borrowed.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/lab_registry.hpp"
#include "router/multi_device_routing.hpp"

namespace router::routing {
struct RouteGeneration {
  // One protocol owner publishes all of its instances for one router together.
  // The route manager must reject an older device generation or an incomplete
  // count before replacing its dynamic candidate set.
  lab::DeviceHandle device{};
  std::uint64_t generation{};
  std::array<lab::routing::DynamicInput,
             device_catalog::maximum_dynamic_routes_per_router>
      ipv4{};
  std::array<lab::routing::Ipv6DynamicInput,
             device_catalog::maximum_dynamic_routes_per_router>
      ipv6{};
  std::uint32_t ipv4_count{};
  std::uint32_t ipv6_count{};
};
} // namespace router::routing
