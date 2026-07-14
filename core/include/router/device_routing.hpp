// Narrow adapter from the control-owned device aggregate to route candidates.
// It is the only module allowed to combine configuration with hardware-derived
// interface state for consumption by the independent routing library.

#pragma once

#include "router/device.hpp"
#include "router/routing.hpp"

namespace router {

// Preconditions: device belongs to the calling control shard. The returned
// value owns all data and contains no references, pointers or mutable aliases.
[[nodiscard]] routing::RibInput
make_rib_input(const DeviceState &device) noexcept;

} // namespace router
