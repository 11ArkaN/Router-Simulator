// Detached forwarding/link validation joins exact borrowed protocol credits to
// their sole remaining transfer owner. It never reads live shards or changes a
// queue. Dependencies point to transport contracts and encoded packet parsing.

#include "router/network_transfer_checkpoint.hpp"
#include "router/isis_ethernet.hpp"

#include <algorithm>

namespace router::lab {
bool valid_forward_transfers(const ForwardShardTransferCheckpoint &saved,
    const IsisCheckpointEgress::Checkpoint &channel, std::size_t shard, std::size_t shards,
    std::uint64_t barrier_epoch) noexcept {
  if (!barrier_epoch || saved.version != 1U || saved.barrier_epoch != barrier_epoch ||
      !shards || shards > device_catalog::high_forwarding_shards || shard >= shards ||
      saved.egress.size() >= device_catalog::forwarding_ring_frames ||
      saved.receipts.size() > device_catalog::isis_packet_ring_frames ||
      !IsisCheckpointEgress::valid_checkpoint(channel, barrier_epoch)) return false;
  std::array<bool, device_catalog::isis_packet_ring_frames> referenced{};
  const auto receipt = [&](const IsisLinkReceiptCheckpoint &value) {
    const auto &metadata = value.metadata;
    if (value.handle >= referenced.size() || referenced[value.handle] ||
        !std::binary_search(channel.borrowed.begin(), channel.borrowed.end(), value.handle) ||
        !metadata.device || metadata.device.index >= device_catalog::maximum_routers ||
        metadata.device.index % shards != shard || !metadata.interface_id || !metadata.configuration_generation ||
        !metadata.transmission_id || metadata.instance_id > device_catalog::isis_instance_last ||
        metadata.physical_port_ordinal >= device_catalog::maximum_ports_per_router) return false;
    const auto slot = std::lower_bound(channel.occupied.begin(), channel.occupied.end(), value.handle,
        [](const auto &entry, auto handle) { return entry.handle < handle; });
    if (slot == channel.occupied.end() || slot->handle != value.handle || slot->metadata != metadata) return false;
    packet::isis::EthernetDecodeError error{};
    const auto wire = packet::isis::parse_ethernet_pdu(slot->bytes, error);
    if (!wire || metadata.transmission_class != static_cast<std::uint8_t>(wire->pdu.type)) return false;
    referenced[value.handle] = true;
    return true;
  };
  for (const auto &frame : saved.egress) {
    if (frame.kind > ForwardTransferKind::isis_transmit || frame.source.kind > NodeKind::ethernet_switch ||
        !frame.source.generation || frame.bytes.size() > packet::maximum_frame_octets ||
        frame.ordinal >= device_catalog::maximum_ports_per_router ||
        frame.isis_receipt.has_value() != (frame.kind == ForwardTransferKind::isis_transmit)) return false;
    if (!frame.isis_receipt) continue;
    const auto &metadata = frame.isis_receipt->metadata;
    if (frame.isis_receipt->enqueued || !receipt(*frame.isis_receipt) ||
        frame.source != node(metadata.device) || frame.ordinal != metadata.physical_port_ordinal ||
        frame.expected_port.node != frame.source || frame.expected_port.ordinal != frame.ordinal ||
        !frame.expected_port.generation) return false;
    const auto slot = std::lower_bound(channel.occupied.begin(), channel.occupied.end(), frame.isis_receipt->handle,
        [](const auto &entry, auto handle) { return entry.handle < handle; });
    // The queued physical frame can contain the forwarding owner's Ethernet
    // encapsulation. Its protocol selector must still agree with the credit;
    // byte equality would incorrectly reject legitimate link encapsulation.
    packet::isis::EthernetDecodeError error{};
    const auto wire = packet::isis::parse_ethernet_pdu(frame.bytes, error);
    const auto original = packet::isis::parse_ethernet_pdu(slot->bytes, error);
    if (!wire || !original || wire->ethernet.source != original->ethernet.source ||
        wire->ethernet.destination != original->ethernet.destination ||
        wire->ethernet.vlan_tag_count != original->ethernet.vlan_tag_count || metadata.transmission_class != static_cast<std::uint8_t>(wire->pdu.type) ||
        !std::equal(wire->pdu.bytes.begin(), wire->pdu.bytes.end(), original->pdu.bytes.begin(), original->pdu.bytes.end())) return false;
  }
  for (const auto &value : saved.receipts) if (!receipt(value)) return false;
  if (saved.retained_receipt && !receipt(*saved.retained_receipt)) return false;
  for (const auto handle : channel.borrowed) if (!referenced[handle]) return false;
  return true;
}
} // namespace router::lab
