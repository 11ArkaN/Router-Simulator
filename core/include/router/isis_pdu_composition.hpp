// Bounded composition storage shared by IS-IS PDU families. The control owner
// retains option inputs and exclusively reuses scratch; no protocol state or
// borrowed key survives a composition call. Dependencies are wire values only.

#pragma once

#include "router/isis_ethernet.hpp"
#include "router/isis_instance_tlv.hpp"

namespace router::isis {

struct PduInstanceOption {
  packet::isis::InstanceFormat format{};
  std::uint16_t instance{};
  std::span<const std::uint16_t> topologies;
};

struct PduScratch {
  // Producer: owning control shard. No consumer accesses scratch directly;
  // complete frames are copied into a bounded egress slot before publication.
  std::array<std::uint8_t, packet::maximum_frame_octets> options;
  std::array<std::uint8_t, packet::maximum_frame_octets> pdu;
};

} // namespace router::isis
