// The local RIB owner exposes its existing IS-IS distance preselection through
// a narrow value interface. No protocol owner, LSDB or forwarding state is read.
#pragma once
#include "router/multi_device_routing.hpp"
namespace router::lab::routing {
// Both immutable spans remain alive for this call. Output has exactly their
// combined size, bounded by the generated dynamic route capacity. Success
// overwrites every output bit using the same rank/metric/secondary-metric
// comparison as RIB rebuild. Repairs and unavailable inputs are not selected.
// Invalid bounds or configured IS-IS prefix extents return false without output mutation. No allocation or view
// retention occurs. This is protocol preselection, before the final RIB choice.
[[nodiscard]] bool select_isis_candidates(std::span<const DynamicInput> first,
    std::span<const DynamicInput> second, std::span<bool> output) noexcept;
[[nodiscard]] bool select_isis_candidates(std::span<const Ipv6DynamicInput> first,
    std::span<const Ipv6DynamicInput> second, std::span<bool> output) noexcept;
}
