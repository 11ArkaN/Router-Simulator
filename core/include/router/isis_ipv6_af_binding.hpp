// The cold runtime coordinator joins detached protocol and forwarding AF
// images. It owns only the returned subscription values; DAD and protocol state
// remain with their writers. Dependencies point to explicit owner checkpoints.
#pragma once
#include "router/isis_control_checkpoint.hpp"
#include "router/router_forwarder.hpp"
namespace router::lab {
// Requires a validated detached forwarding image and one local device image.
// Checks every managed IPv6 candidate against configured AF ownership and exact
// DAD assignment, including Hello gates. Returns a sorted unique physical watch
// set within the AF owner's generated capacity. Logical System candidates have
// no DAD subscription. Invalid input/allocation returns no partial result and
// changes neither image. Cold coordinator only; no live shard reads or clocks.
[[nodiscard]] std::optional<std::vector<Ipv6ReadinessWatch>> prepare_isis_ipv6_af_binding(
    const isis::ControlDeviceCheckpoint &, const RouterForwarderCheckpoint &) noexcept;
}
