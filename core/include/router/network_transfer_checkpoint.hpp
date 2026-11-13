// Detached forwarding/link transfer images belong to the quiescent network
// coordinator. Packet producers and consumers must acknowledge the same barrier
// before capture or replacement. Only owned live prefixes cross this boundary.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/protocol_packet_channel.hpp"

namespace router::lab {
using IsisCheckpointEgress = protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>;
struct IsisLinkReceiptCheckpoint {
  IsisCheckpointEgress::Handle handle{};
  IsisCheckpointEgress::Metadata metadata{};
  bool enqueued{};
  bool operator==(const IsisLinkReceiptCheckpoint &) const = default;
};
enum class ForwardTransferKind : std::uint8_t { transmit, cpm_punt, isis_transmit };
struct ForwardTransferCheckpoint {
  ForwardTransferKind kind{};
  NodeHandle source{};
  std::uint16_t ordinal{};
  PortHandle expected_port{};
  std::optional<IsisLinkReceiptCheckpoint> isis_receipt;
  std::vector<std::uint8_t> bytes;
  protocol::FrameExpiryCheckpoint expiry{};
};
struct ForwardShardTransferCheckpoint {
  std::uint32_t version{1U};
  std::uint64_t barrier_epoch{};
  // Producer: forwarding shard; consumer: link owner. FIFO order is exact.
  // Capacity is forwarding_ring_frames - 1; no queued frame is replayed during
  // capture. CPM observations remain ordered with ordinary physical egress.
  std::vector<ForwardTransferCheckpoint> egress;
  // Producer: link owner; consumer: forwarding shard. Capacity is one per
  // protocol frame credit. Returned results retain actual physical admission.
  std::vector<IsisLinkReceiptCheckpoint> receipts;
  // Link-owner overflow retention has already attempted physical admission.
  // Restore must publish its receipt, never enqueue the corresponding wire again.
  std::optional<IsisLinkReceiptCheckpoint> retained_receipt;
};
// Coordinator only after forwarding/protocol acknowledgement. Validates the
// complete packet partition, cohort and a bijection from borrowed protocol slots
// to outstanding wire/receipt references. Stale canceled protocol generations
// remain legal transport work; protocol reservation validation is separate.
// No allocation, mutation, packet admission or receipt consumption occurs.
[[nodiscard]] bool valid_forward_transfers(const ForwardShardTransferCheckpoint &saved,
    const IsisCheckpointEgress::Checkpoint &channel, std::size_t shard, std::size_t shards,
    std::uint64_t barrier_epoch) noexcept;
} // namespace router::lab
