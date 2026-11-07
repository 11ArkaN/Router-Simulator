// Quiescent forwarding/link images preserve one physical-admission reference
// per borrowed protocol credit. Detached corruption must never invent a second
// enqueue or completion. The original channel dies before receipt continuation.

#include "router/network_transfer_checkpoint.hpp"
#include "router/isis_ethernet.hpp"
#include "router/isis_lsp_builder.hpp"

#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

void network_transfer_checkpoint_tests() {
  using namespace router;
  using namespace router::lab;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("Network transfer checkpoint invariant at " + std::to_string(where.line()));
  };
  auto scratch = std::make_unique<isis::PduScratch>();
  auto frame = std::make_unique<packet::Frame>();
  isis::LspContents contents;
  contents.header = {packet::isis::PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U};
  contents.maximum_pdu_octets = 1492U;
  const auto pdu = isis::build_lsp_pdu(contents, scratch->options, scratch->pdu);
  require(pdu.status == isis::LspBuildStatus::encoded && packet::isis::ethernet_pdu_into(*frame,
      {2U, 0U, 0U, 0U, 0U, 1U}, {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U}, pdu.bytes));
  auto channel = std::make_unique<IsisCheckpointEgress>();
  std::array<IsisLinkReceiptCheckpoint, 4U> references;
  for (std::size_t index{}; index < references.size(); ++index) {
    const IsisCheckpointEgress::Metadata metadata{{1U, 7U}, 99U, 3U, 11U, index + 1U,
        static_cast<std::uint8_t>(packet::isis::PduType::lsp_l1), 2U, 41U};
    require(channel->try_send(metadata, *frame));
    const auto borrowed = channel->try_receive();
    require(borrowed.has_value());
    references[index] = {borrowed->handle, borrowed->metadata, index != 0U};
  }
  require(channel->release(references[3U].handle, references[3U].metadata, false));
  require(channel->try_send(references[3U].metadata, *frame)); // Ready work has no external borrower yet.
  constexpr std::uint64_t cohort{61U};
  const auto image = channel->checkpoint_quiescent(cohort);
  ForwardShardTransferCheckpoint saved;
  saved.barrier_epoch = cohort;
  ForwardTransferCheckpoint queued;
  queued.kind = ForwardTransferKind::isis_transmit;
  queued.source = node(references[0U].metadata.device);
  queued.ordinal = 3U;
  queued.expected_port = {queued.source, 3U, 9U};
  queued.isis_receipt = references[0U];
  queued.bytes.assign(frame->view().begin(), frame->view().end());
  saved.egress.push_back(queued);
  queued.kind = ForwardTransferKind::cpm_punt;
  queued.isis_receipt.reset();
  saved.egress.push_back(queued);
  queued.kind = ForwardTransferKind::transmit;
  saved.egress.push_back(queued);
  saved.receipts.push_back(references[1U]);
  saved.retained_receipt = references[2U];
  const auto valid = [&](const auto &value) { return valid_forward_transfers(value, image, 1U, 3U, cohort); };
  require(valid(saved) && !valid_forward_transfers(saved, image, 0U, 3U, cohort));
  const auto refuses = [&](auto corrupt) { auto changed = saved; corrupt(changed); require(!valid(changed)); };
  refuses([](auto &value) { ++value.version; });
  refuses([](auto &value) { ++value.barrier_epoch; });
  refuses([](auto &value) { value.receipts.clear(); });
  refuses([](auto &value) { value.retained_receipt.reset(); });
  refuses([](auto &value) { value.receipts.push_back(*value.retained_receipt); });
  refuses([](auto &value) { value.egress[0U].isis_receipt->enqueued = true; });
  refuses([](auto &value) { ++value.receipts[0U].metadata.protocol_epoch; });
  refuses([](auto &value) { ++value.egress[0U].expected_port.ordinal; });
  refuses([](auto &value) { value.egress[0U].bytes.resize(4U); });
  refuses([](auto &value) { value.egress[0U].bytes[packet::ethernet_header_octets + packet::llc_ui_header_octets + 12U] ^= 1U; });
  refuses([](auto &value) { value.egress[1U].isis_receipt = value.egress[0U].isis_receipt; });
  auto changed = saved;
  changed.receipts[0U] = references[3U];
  require(!valid(changed)); // A returned credit must not retain another physical reference.
  changed = saved;
  // Link padding is not protocol information and can differ after encapsulation.
  packet::isis::EthernetDecodeError error{};
  const auto wire = packet::isis::parse_ethernet_pdu(changed.egress[0U].bytes, error);
  require(wire.has_value());
  const auto end = static_cast<std::size_t>(wire->pdu.bytes.data() - changed.egress[0U].bytes.data()) + wire->pdu.bytes.size();
  require(end < changed.egress[0U].bytes.size());
  changed.egress[0U].bytes[end] ^= 1U;
  require(valid(changed));
  channel.reset();
  auto restored = std::make_unique<IsisCheckpointEgress>();
  require(restored->restore_quiescent(image, cohort));
  for (const auto &receipt : saved.receipts)
    require(restored->release(receipt.handle, receipt.metadata, receipt.enqueued));
  require(restored->release(saved.retained_receipt->handle, saved.retained_receipt->metadata, saved.retained_receipt->enqueued));
  require(!restored->release(saved.retained_receipt->handle, saved.retained_receipt->metadata, saved.retained_receipt->enqueued));
  const auto pending = *saved.egress[0U].isis_receipt;
  require(restored->release(pending.handle, pending.metadata, true));
  for (const auto ticket : {4U, 2U, 3U, 1U}) {
    const auto receipt = restored->try_completion();
    require(receipt && receipt->metadata.transmission_id == ticket);
  }
  const auto ready = restored->try_receive();
  require(ready && ready->metadata.transmission_id == 4U && restored->release(ready->handle, ready->metadata, false));

  struct Packet { std::array<std::uint8_t, 512U> bytes{}; std::uint16_t length{}; };
  SpscRing<Packet, 4U> fifo;
  Packet packet;
  packet.bytes.fill(0xa5U); packet.length = 3U;
  require(fifo.try_push(packet));
  const auto prefixes = fifo.checkpoint_quiescent([](const auto &value) {
    return std::vector<std::uint8_t>(value.bytes.begin(), value.bytes.begin() + value.length);
  });
  require(prefixes == std::vector<std::vector<std::uint8_t>>{{0xa5U, 0xa5U, 0xa5U}} && !fifo.empty());
}
