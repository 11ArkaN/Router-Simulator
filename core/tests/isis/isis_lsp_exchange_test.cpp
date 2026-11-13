// LSP egress tests exercise encoded lifetime reduction and actual queue receipts.
// Same-shard owners retain flood obligations across refusal and stale versions.

#include "router/isis_lsp_exchange.hpp"
#include "router/isis_lsp_lifetime.hpp"

#include "router/multi_device_fabric.hpp"
#include "router/protocol_packet_channel.hpp"

#include <memory>
#include <source_location>
#include <string>
#include <stdexcept>

void isis_lsp_exchange_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS LSP exchange invariant failed at line " + std::to_string(location.line()));
  };
  require(lsp_transmission_lifetime(1200U, 0ns, 0ns) == 1199U);
  require(lsp_transmission_lifetime(1200U, 1999ms, 1s) == 1198U);
  require(lsp_transmission_lifetime(1200U, 2s, 1001ms) == 1196U);
  require(lsp_transmission_lifetime(1200U, 2s, 2s) == 1196U);
  require(!lsp_transmission_lifetime(3U, 2s, 1s));
  require(!lsp_transmission_lifetime(1U, 0ns, 0ns));
  require(!lsp_transmission_lifetime(0U, 100s, 100s));
  require(lsp_transmission_lifetime(0U, 100s, 100s, true) == 0U);
  require(!lsp_transmission_lifetime(1U, 0ns, 1s, true));
  require(!lsp_transmission_lifetime(1200U, -1ns, 1s));
  require(!lsp_transmission_lifetime(0U, 0ns, -1ns));
  require(!lsp_transmission_lifetime(65535U,
      std::chrono::nanoseconds::max(), std::chrono::nanoseconds::max()));
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
  {
    auto timed = std::make_unique<protocol::PacketChannel<2U, true>>();
    require(timed->try_send({}, frame, sent.expiry));
    const auto channel_image = timed->checkpoint_quiescent(31U, now + 11500ms);
    require(valid_queued_lsp_expiry(channel_image.occupied[0].bytes, channel_image.occupied[0].expiry));
    auto wrong_field = channel_image.occupied[0].expiry;
    ++wrong_field.offset;
    require(!valid_queued_lsp_expiry(channel_image.occupied[0].bytes, wrong_field));
    require(channel_image.occupied.size() == 1U &&
        channel_image.occupied[0].expiry.holding_nanoseconds == 1500000000LL);
    require(timed->restore_quiescent(channel_image, 31U, RuntimeClock::time_point{900s}));
    const auto queued = timed->try_receive();
    require(queued.has_value());
    auto delayed = std::make_unique<lab::MultiDeviceFabric>();
    const lab::LinkHandle delayed_link{0U, 1U};
    require(delayed->configure(delayed_link, {lab::node(lab::DeviceHandle{0U, 1U}), 0U, 1U},
        {lab::node(lab::DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 2300ms, true));
    require(delayed->enqueue(delayed_link, 0U, *queued->frame, queued->expiry) == lab::MultiDeviceFabric::DropReason::none);
    const auto medium_image = delayed->checkpoint(RuntimeClock::time_point{901s});
    require(medium_image.links[0].directions[0].transmit[0].expiry.holding_nanoseconds == 2500000000LL);
    require(delayed->restore(medium_image, RuntimeClock::time_point{1000s}));
    std::optional<packet::Frame> received, emitted;
    const auto deliver = +[](void *context, const lab::MultiDeviceFabric::Delivery &delivery) {
      auto &value = *static_cast<std::optional<packet::Frame> *>(context);
      value.emplace();
      packet::copy_frame(*value, delivery.frame);
    };
    delayed->pump_transmit(RuntimeClock::time_point{1000500ms}, &emitted, deliver);
    require(emitted.has_value());
    const auto observed = parse_ethernet_pdu(emitted->view(), error);
    require(observed && lsp(observed->pdu)->remaining_seconds == 1184U);
    const auto flight_image = delayed->checkpoint(RuntimeClock::time_point{1001s});
    require(flight_image.links[0].directions[0].in_flight.size() == 1U &&
        !flight_image.links[0].directions[0].in_flight[0].expiry.offset);
    require(delayed->restore(flight_image, RuntimeClock::time_point{2000s}));
    delayed->pump_delivery(&received, deliver, RuntimeClock::time_point{2004s});
    require(received.has_value());
    const auto aged = parse_ethernet_pdu(received->view(), error);
    require(aged && lsp(aged->pdu)->remaining_seconds == 1184U && valid_lsp_checksum(aged->pdu));
    require(lsp(parse_ethernet_pdu(frame.view(), error)->pdu)->remaining_seconds == 1189U);
    auto newly_published = sent.expiry;
    newly_published.prepared = RuntimeClock::time_point{2010s};
    require(delayed->enqueue(delayed_link, 0U, frame, newly_published) == lab::MultiDeviceFabric::DropReason::none);
    emitted.reset();
    delayed->pump_transmit(RuntimeClock::time_point{2009s}, &emitted, deliver);
    require(emitted.has_value());
    const auto fresh = parse_ethernet_pdu(emitted->view(), error);
    require(fresh && lsp(fresh->pdu)->remaining_seconds == 1187U);
    delayed->pump_delivery(&received, deliver, RuntimeClock::time_point{2014s});
    require(delayed->enqueue(delayed_link, 0U, frame, sent.expiry) == lab::MultiDeviceFabric::DropReason::none);
    emitted.reset();
    delayed->pump_transmit(now + 2000s, &emitted, deliver);
    received.reset();
    delayed->pump_delivery(&received, deliver, now + 2100s);
    require(!received && !emitted && delayed->dropped_frames() == 1U);
    auto invalid = channel_image;
    invalid.occupied[0].expiry.holding_nanoseconds = -1;
    require(!timed->restore_quiescent(invalid, 31U));
    invalid = channel_image;
    invalid.occupied[0].expiry.offset = static_cast<std::uint16_t>(frame.size());
    require(!timed->restore_quiescent(invalid, 31U));
  }
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
  require(purge && lsp(purge->pdu)->remaining_seconds == 0U && !sent.expiry.offset);
  require(valid_queued_lsp_expiry(frame.view(), {}));
  auto forged_purge_expiry = protocol::FrameExpiryCheckpoint{27U, 1U, 0};
  require(!valid_queued_lsp_expiry(frame.view(), forged_purge_expiry));
  const auto saved = lan.checkpoint();
  require(saved.pending && saved.pending->sequence == 4U && !saved.pending->remaining_seconds);
  const auto epoch = now + 500s;
  LevelDatabase restored_database(PduType::lsp_l1, {4U, 1024U}, circuits);
  require(restored_database.restore(database.checkpoint(now), epoch, 1200U));
  LspExchange restored(restored_database, 0U, 8U);
  require(restored.restore(saved) && restored.pending());
  const auto refused = [&](auto invalid) {
    require(!restored.restore(invalid) && restored.checkpoint().transmission.pending == saved.transmission.pending &&
        restored.checkpoint().transmission.next_ticket == saved.transmission.next_ticket &&
        restored.checkpoint().pending->sequence == saved.pending->sequence);
  };
  auto invalid = saved;
  invalid.version = 2U; refused(invalid);
  invalid = saved; invalid.database_type = PduType::lsp_l2; refused(invalid);
  invalid = saved; invalid.circuit = 1U; refused(invalid);
  invalid = saved; invalid.transmission.epoch = 7U; refused(invalid);
  invalid = saved; invalid.transmission.next_ticket = 0U; refused(invalid);
  invalid = saved; invalid.pending.reset(); refused(invalid);
  invalid = saved; invalid.pending->sequence = 0U; refused(invalid);
  invalid = saved; invalid.pending->remaining_seconds = 1U; invalid.pending->checksum = 0U; refused(invalid);
  const auto newer = encode_lsp(bytes, {PduType::lsp_l1, id, 1200U, 5U, 3U}, {});
  require(newer && restored_database.originate(*newer, epoch, 1200U, 60s) == LspInstallResult::installed &&
      restored.restore(saved));
  const auto superseded = restored.complete(8U, saved.transmission.pending, true, epoch);
  require(superseded.accepted && !superseded.current_version && restored_database.flags(id, 0U)->srm &&
      !restored.complete(8U, saved.transmission.pending, true, epoch).accepted);
  const auto resumed_send = restored.prepare(id, source, destination, 1492U, 1U, frame, *scratch, epoch);
  require(resumed_send.status == LspEmissionStatus::encoded && resumed_send.ticket == saved.transmission.next_ticket);
  restored.cancel();
  const auto idle = restored.checkpoint();
  require(!idle.pending && !idle.transmission.pending && restored.restore(idle));
}
