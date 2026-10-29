// LSP egress tests exercise encoded lifetime reduction and actual queue receipts.
// Same-shard owners retain flood obligations across refusal and stale versions.

#include "router/isis_lsp_exchange.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/protocol_packet_channel.hpp"

#include <memory>
#include <stdexcept>

void isis_lsp_exchange_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS LSP exchange invariant failed");
  };
  const std::array circuits{FloodCircuit{true, true}, FloodCircuit{false, true}};
  LevelDatabase database(PduType::lsp_l1, {4U, 1024U}, circuits);
  LspExchange lan(database, 0U, 7U), p2p(database, 1U, 7U);
  const auto now = RuntimeClock::time_point{100s};
  const LspId id{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  const packet::Mac source{2U, 0U, 0U, 0U, 0U, 1U};
  const packet::Mac destination{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  std::array<std::uint8_t, 128U> bytes{};
  const auto originate = [&](std::uint32_t sequence, std::uint16_t lifetime) {
    const auto wire = encode_lsp(bytes, {PduType::lsp_l1, id, lifetime, sequence, 3U}, {});
    require(wire && database.originate(*wire, now, 1200U, 60s) == LspInstallResult::installed);
  };
  originate(1U, 1200U);
  auto scratch = std::make_unique<PduScratch>();
  packet::Frame frame;
  auto sent = lan.prepare(id, source, destination, 1492U, 1U, frame, *scratch, now + 10s);
  require(sent.status == LspEmissionStatus::encoded);
  EthernetDecodeError error;
  const auto decoded = parse_ethernet_pdu(frame.view(), error);
  require(decoded && lsp(decoded->pdu)->remaining_seconds == 1189U && valid_lsp_checksum(decoded->pdu));
  require(database.database().find(id, now)->header.remaining_seconds == 1200U);
  require(lan.prepare(id, source, destination, 1492U, 1U, frame, *scratch, now).status == LspEmissionStatus::pending);
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const lab::LinkHandle link{0U, 1U};
  require(fabric->configure(link, {lab::node(lab::DeviceHandle{0U, 1U}), 0U, 1U},
      {lab::node(lab::DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 100ns, true));
  auto channel = std::make_unique<protocol::PacketChannel<2U, true>>();
  const auto transmit = [&](LspExchange &owner, LspTransmission transmission) {
    require(channel->try_send({{0U, 1U}, 11U, 0U, 7U, transmission.ticket}, frame));
    const auto borrowed = channel->try_receive();
    require(borrowed.has_value());
    const bool enqueued = fabric->enqueue(link, 0U, *borrowed->frame) == lab::MultiDeviceFabric::DropReason::none;
    require(channel->release(borrowed->handle, enqueued));
    const auto receipt = channel->try_completion();
    require(receipt.has_value());
    return owner.complete(receipt->metadata.configuration_generation, receipt->metadata.transmission_id,
        receipt->enqueued, now + 10s);
  };
  auto receipt = transmit(lan, sent);
  require(receipt.accepted && receipt.current_version && !database.flags(id, 0U)->srm);
  require(!lan.complete(7U, sent.ticket, true, now).accepted);
  sent = p2p.prepare(id, source, destination, 1492U, 3U, frame, *scratch, now);
  require(sent.status == LspEmissionStatus::encoded);
  receipt = transmit(p2p, sent);
  require(receipt.accepted && receipt.current_version && database.flags(id, 1U)->srm);
  originate(2U, 1200U);
  sent = lan.prepare(id, source, destination, 1492U, 1U, frame, *scratch, now);
  originate(3U, 1200U);
  receipt = transmit(lan, sent);
  require(receipt.accepted && !receipt.current_version && database.flags(id, 0U)->srm);
  while (fabric->enqueue(link, 0U, frame) == lab::MultiDeviceFabric::DropReason::none) {}
  sent = lan.prepare(id, source, destination, 1492U, 1U, frame, *scratch, now);
  receipt = transmit(lan, sent);
  require(receipt.accepted && receipt.current_version && database.flags(id, 0U)->srm);
  require(lan.prepare(id, source, destination, 10U, 1U, frame, *scratch, now).status == LspEmissionStatus::capacity);
  require(lan.prepare(id, source, destination, 1492U, 1U, frame, *scratch, now + 1199s).status == LspEmissionStatus::purge_required);
  require(lan.prepare(id, source, destination, 1492U, 1U, frame, *scratch, now + 1200s).status == LspEmissionStatus::purge_required);
  sent = lan.prepare(id, source, destination, 1492U, 0U, frame, *scratch, now);
  require(sent.status == LspEmissionStatus::encoded);
  lan.cancel();
  const auto replacement = lan.prepare(id, source, destination, 1492U, 0U, frame, *scratch, now);
  require(replacement.status == LspEmissionStatus::encoded && replacement.ticket != sent.ticket);
  require(!lan.complete(7U, sent.ticket, true, now).accepted);
  require(lan.replace_epoch(8U) && !lan.complete(7U, replacement.ticket, true, now).accepted);
  originate(4U, 0U);
  sent = lan.prepare(id, source, destination, 1492U, 1U, frame, *scratch, now);
  require(sent.status == LspEmissionStatus::encoded);
  const auto purge = parse_ethernet_pdu(frame.view(), error);
  require(purge && lsp(purge->pdu)->remaining_seconds == 0U);
}
