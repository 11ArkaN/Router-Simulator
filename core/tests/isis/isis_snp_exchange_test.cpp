// SNP output crosses completion-enabled SPSC storage and a physical link queue.
// Queue saturation, operational cancellation and superseded LSPs cannot retire
// obligations belonging to later output or a replacement configuration.

#include "router/isis_snp_exchange.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/protocol_packet_channel.hpp"

#include <array>
#include <memory>
#include <stdexcept>

void isis_snp_exchange_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS SNP exchange receipt invariant failed");
  };
  const std::array circuits{FloodCircuit{false, true, false, false}, FloodCircuit{true, true, false, false}};
  LevelDatabase database(PduType::lsp_l1, {4U, 1024U}, circuits);
  TransientAcknowledgements acknowledgements(4U);
  SnpExchange exchange(database, acknowledgements, 0U, 7U, 100U);
  auto now = RuntimeClock::time_point{100s};
  std::array<std::uint8_t, 128U> bytes{};
  const LspId id{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  const auto install = [&](std::uint32_t sequence) {
    const auto wire = encode_lsp(bytes, {PduType::lsp_l1, id, 1200U, sequence, 3U}, {});
    require(wire && database.receive(*wire, 0U, now, 1200U, 60s).install == LspInstallResult::installed);
  };
  install(1U);
  SnpContents contents;
  contents.header.type = PduType::psnp_l1;
  contents.header.source = {9U, 8U, 7U, 6U, 5U, 4U};
  contents.source = {2U, 0U, 0U, 0U, 0U, 1U};
  contents.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  contents.maximum_pdu_octets = 1492U;
  auto scratch = std::make_unique<PduScratch>();
  packet::Frame frame;
  auto result = exchange.prepare(SnpEmission::partial, contents, false, frame, *scratch, now);
  require(result.status == SnpExchangeStatus::encoded && exchange.pending() && database.flags(id, 0U)->ssn);
  require(exchange.prepare(SnpEmission::partial, contents, false, frame, *scratch, now).status == SnpExchangeStatus::pending);
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const lab::LinkHandle link{0U, 1U};
  require(fabric->configure(link, {lab::node(lab::DeviceHandle{0U, 1U}), 0U, 1U},
      {lab::node(lab::DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 100ns, true));
  auto channel = std::make_unique<protocol::PacketChannel<2U, true>>();
  const auto transmit = [&](const SnpTransmission &transmission, const packet::Frame &packet, std::uint64_t epoch = 7U) {
    require(channel->try_send({{0U, 1U}, 11U, 0U, epoch, transmission.ticket}, packet));
    const auto borrowed = channel->try_receive();
    require(borrowed.has_value());
    const bool enqueued = fabric->enqueue(link, 0U, *borrowed->frame) == lab::MultiDeviceFabric::DropReason::none;
    require(channel->release(borrowed->handle, enqueued));
    const auto receipt = channel->try_completion();
    require(receipt && receipt->metadata.transmission_id == transmission.ticket);
    return exchange.complete(receipt->metadata.configuration_generation,
        receipt->metadata.transmission_id, receipt->enqueued, now);
  };
  std::size_t filled{};
  while (filled < PacketPool::capacity && fabric->enqueue(link, 0U, frame) == lab::MultiDeviceFabric::DropReason::none)
    ++filled;
  require(filled > 0U && filled < PacketPool::capacity);
  auto receipt = transmit(result, frame);
  require(receipt.accepted && !receipt.retired && !receipt.superseded && database.flags(id, 0U)->ssn);
  const auto drain = [&](std::size_t turns) {
    for (std::size_t index{}; index < turns; ++index) {
      fabric->pump_transmit(now);
      now += 1ms;
      fabric->pump_delivery(nullptr, +[](void *, const lab::MultiDeviceFabric::Delivery &) {}, now);
    }
    require(fabric->available_packets() == PacketPool::capacity);
  };
  drain(filled + 3U);
  result = exchange.prepare(SnpEmission::partial, contents, false, frame, *scratch, now);
  require(result.status == SnpExchangeStatus::encoded);
  receipt = transmit(result, frame);
  require(receipt.accepted && receipt.retired == 1U && !database.flags(id, 0U)->ssn);
  drain(3U);
  exchange.request_complete();
  contents.header.type = PduType::csnp_l1;
  const auto old = exchange.prepare(SnpEmission::complete, contents, false, frame, *scratch, now);
  const auto old_frame = frame;
  require(old.status == SnpExchangeStatus::encoded);
  exchange.cancel();
  exchange.request_complete();
  result = exchange.prepare(SnpEmission::complete, contents, false, frame, *scratch, now);
  require(result.status == SnpExchangeStatus::encoded && result.ticket > old.ticket);
  require(!transmit(old, old_frame).accepted && exchange.pending());
  require(transmit(result, frame).accepted && !exchange.pending());
  drain(5U);
  install(2U);
  contents.header.type = PduType::psnp_l1;
  result = exchange.prepare(SnpEmission::partial, contents, false, frame, *scratch, now);
  require(result.status == SnpExchangeStatus::encoded);
  install(3U);
  receipt = transmit(result, frame);
  require(receipt.accepted && receipt.superseded == 1U && !receipt.retired && database.flags(id, 0U)->ssn);
  drain(3U);
  result = exchange.prepare(SnpEmission::partial, contents, false, frame, *scratch, now);
  require(result.status == SnpExchangeStatus::encoded && transmit(result, frame).retired == 1U);
  drain(3U);
  const SnpEntry purge{0U, {7U, 7U, 7U, 7U, 7U, 7U, 0U, 0U}, 5U, 10U};
  require(acknowledgements.admit(0U, purge).status == AcknowledgementAdmission::queued);
  result = exchange.prepare(SnpEmission::transient_acknowledgement, contents, false, frame, *scratch, now);
  require(result.status == SnpExchangeStatus::encoded && acknowledgements.size() == 1U);
  require(transmit(result, frame).retired == 1U && acknowledgements.size() == 0U);
  drain(3U);
  SnpExchange lan(database, acknowledgements, 1U, 7U, 100U);
  require(lan.prepare(SnpEmission::partial, contents, true, frame, *scratch, now).status == SnpExchangeStatus::role_forbidden);
  contents.header.type = PduType::csnp_l1;
  lan.request_complete();
  require(lan.prepare(SnpEmission::complete, contents, false, frame, *scratch, now).status == SnpExchangeStatus::role_forbidden);
  require(lan.prepare(SnpEmission::complete, contents, true, frame, *scratch, now).status == SnpExchangeStatus::encoded);
  lan.cancel();
  exchange.request_complete();
  result = exchange.prepare(SnpEmission::complete, contents, false, frame, *scratch, now);
  require(result.status == SnpExchangeStatus::encoded && database.circuit(0U, false, false, false) &&
      !exchange.replace_epoch(7U) && exchange.replace_epoch(8U));
  require(!transmit(result, frame).accepted && !exchange.pending());
  drain(3U);
  require(exchange.prepare(SnpEmission::complete, contents, false, frame, *scratch, now).status == SnpExchangeStatus::ineligible);
}
