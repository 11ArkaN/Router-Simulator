// The serialized network owner publishes copied committed RIB selections to
// the IS-IS control owner. No database, RIB or candidate pointer crosses shards.
// Source: ietf.isis.selected_interlevel_export
#pragma once
#include "router/isis_route_selection.hpp"
#include "router/owned_spsc_channel.hpp"
namespace router::routing {
// Producer: network RIB shard. Consumer: IS-IS control pthread. Two usable
// slots, FIFO release/acquire publication and return credits. Capacity is an
// emulator transfer budget, not a vendor limit. Full preserves the producer's
// latest dirty projection for a later retry; it never drops a withdrawal.
// Consumer copies any retained value before release and wakes the producer
// after returning credit. Identity/epoch validation belongs to that consumer.
// Capture/restore require both owners quiescent and preserve exact slot states.
using IsisSelectionChannel = protocol::OwnedSpscChannel<IsisRouteSelection, 2U>;
}
