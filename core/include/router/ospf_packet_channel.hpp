// OSPF-facing name for the shared bounded frame channel. The paired forwarding
// and OSPF shards retain their producer/consumer ownership. Dependencies point
// to the protocol-neutral channel and never from that channel back to OSPF.

#pragma once

#include "router/protocol_packet_channel.hpp"

namespace router::ospf {

template <std::size_t Capacity>
using PacketChannel = protocol::PacketChannel<Capacity>;

} // namespace router::ospf
