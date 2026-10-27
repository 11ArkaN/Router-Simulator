// IS-IS forwarding projection and physical egress. The forwarding shard owns
// multicast membership and port state; the protocol owner supplies only encoded
// frames. Dependencies point to shared wire codecs and the forwarding contract.
// Source: iso.10589.2002.ethernet_dispatch

#include "router/router_forwarder.hpp"
#include "router/isis_ethernet.hpp"

#include <algorithm>
#include <new>

namespace router::lab {

bool RouterForwarder::configure_isis_punt(std::uint16_t port_ordinal,
    std::span<const packet::Mac> groups) noexcept {
  if (port_ordinal >= ports_.size() || !ports_[port_ordinal].configured ||
      groups.size() > isis_groups_[port_ordinal].max_size() ||
      std::any_of(groups.begin(), groups.end(), [](const auto &group) { return (group[0U] & 1U) == 0U; }))
    return false;
  try {
    std::vector<packet::Mac> staged(groups.begin(), groups.end());
    std::sort(staged.begin(), staged.end());
    staged.erase(std::unique(staged.begin(), staged.end()), staged.end());
    isis_groups_[port_ordinal].swap(staged);
    return true;
  } catch (const std::bad_alloc &) { return false; }
}

bool RouterForwarder::originate_isis(std::uint16_t port_ordinal,
    const packet::Frame &frame, void *context, EgressSink sink) noexcept {
  const auto *egress_port = port(port_ordinal);
  if (!egress_port || !egress_port->operational) {
    drop(ForwardDrop::port_down);
    return false;
  }
  packet::isis::EthernetDecodeError error;
  const auto pdu = packet::isis::parse_ethernet_pdu(frame.view(), error);
  if (!pdu || pdu->ethernet.vlan_tag_count ||
      !std::binary_search(isis_groups_[port_ordinal].begin(), isis_groups_[port_ordinal].end(),
                          pdu->ethernet.destination)) {
    drop(ForwardDrop::malformed);
    return false;
  }
  if (frame.size() > egress_port->mtu) {
    drop(ForwardDrop::mtu_exceeded);
    return false;
  }
  packet::Frame wire;
  packet::copy_frame(wire, frame);
  packet::rewrite_ethernet(wire, egress_port->mac, pdu->ethernet.destination);
  return emit(port_ordinal, wire, context, sink);
}

} // namespace router::lab
