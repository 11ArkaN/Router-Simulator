// A level owner preserves real egress obligations through Down, new epochs
// and bounded admission failure. Independent levels keep separate Waiting
// deadlines and synchronous origination notifications on the control shard.

#include "router/isis_level_process.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/protocol_packet_channel.hpp"

#include <array>
#include <algorithm>
#include <memory>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <string>

void isis_level_process_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS level process ownership invariant failed at " + std::to_string(location.line()));
  };
  struct Events { std::array<std::size_t, 4U> counts{}; } events;
  const LevelObserver observer{&events, +[](void *opaque, const LevelEvent &event) noexcept {
    ++static_cast<Events *>(opaque)->counts[static_cast<std::size_t>(event.kind)];
  }};
  const std::array circuits{LevelCircuitConfiguration{false, 7U}, LevelCircuitConfiguration{true, 7U}};
  bool invalid_retention_rejected{};
  try {
    LevelProcess invalid(PduType::lsp_l1, {1U, 1024U}, circuits, 1U, 128U, 1200U, 65536s, 60s);
  } catch (const std::invalid_argument &) { invalid_retention_rejected = true; }
  require(invalid_retention_rejected);
  bool invalid_dynamic_budget_rejected{};
  try {
    LevelProcess invalid(PduType::lsp_l1, {1U, 1024U}, {}, 0U, 0U,
        1200U, 60s, 60s, 1U);
  } catch (const std::invalid_argument &) { invalid_dynamic_budget_rejected = true; }
  require(invalid_dynamic_budget_rejected);
  LevelProcess initially_empty(PduType::lsp_l1, {1U, 1024U}, {}, 1U, 0U,
      1200U, 60s, 60s, 1U);
  require(initially_empty.admit_circuit({false, 1U}, 128U).index == 0U);

  LevelProcess level(PduType::lsp_l1, {1U, 1024U}, circuits, 1U, 128U, 1200U, 60s, 60s, 3U);
  LevelProcess other(PduType::lsp_l2, {1U, 1024U}, circuits, 1U, 128U, 1200U, 60s, 60s);
  auto now = RuntimeClock::time_point{100s};
  const LspId id{1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U};
  const auto wire = [&](std::uint8_t fragment, std::uint32_t sequence, std::uint16_t lifetime) {
    auto key = id;
    key.back() = fragment;
    std::array<std::uint8_t, 128U> bytes{};
    const auto encoded = encode_lsp(bytes, {PduType::lsp_l1, key, lifetime, sequence, 3U}, {});
    require(encoded.has_value());
    return std::vector<std::uint8_t>(encoded->begin(), encoded->end());
  };
  const auto retained = wire(0U, 1U, 1200U);
  require(level.originate(retained, now, OriginPurgeReason::none, {}).status == LevelStatus::missing_observer && !level.database().size());
  require(level.originate(retained, now, OriginPurgeReason::none, observer).install == LspInstallResult::installed);
  require(level.circuit(0U, 7U, false, true, false, false, observer) == LevelStatus::applied &&
      level.circuit(1U, 7U, true, true, false, false, observer) == LevelStatus::applied);
  require(level.database().flags(id, 0U)->srm && level.database().flags(id, 1U)->srm);
  require(level.circuit(0U, 7U, true, true, false, false, observer) == LevelStatus::needs_down);
  require(level.receive_lsp(0U, 6U, retained, now, observer).status == LevelStatus::stale_epoch);
  SnpContents contents;
  contents.header.type = PduType::csnp_l1;
  contents.header.source = {9U, 8U, 7U, 6U, 5U, 4U};
  contents.source = {2U, 0U, 0U, 0U, 0U, 1U};
  contents.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  contents.maximum_pdu_octets = 1492U;
  auto scratch = std::make_unique<PduScratch>();
  packet::Frame frame;
  SnpTransmission old;
  {
    auto output = level.outputs(0U, 7U);
    require(output.has_value());
    old = output->snp.prepare(SnpEmission::complete, contents, output->designated, frame, *scratch, now);
    require(old.status == SnpExchangeStatus::encoded);
  }
  // Cold admission must preserve a pending encoded CSNP and its exact ticket.
  require(level.admit_circuit({false, 0U}, 128U).status == LevelStatus::invalid_configuration);
  require(level.admit_circuit({false, 9U}, 0U).status == LevelStatus::invalid_configuration);
  require(level.admit_circuit({false, 9U}, std::numeric_limits<std::size_t>::max()).status ==
      LevelStatus::invalid_configuration);
  require(!level.database().circuit_state(2U) && level.database().flags(id, 0U)->srm);
  const auto admitted = level.admit_circuit({false, 9U}, 128U);
  require(admitted.status == LevelStatus::applied && admitted.index == 2U);
  require(std::ranges::equal(level.database().database().find(id, now)->pdu.bytes, retained));
  require(!level.outputs(2U, 9U) && !level.database().flags(id, 2U)->eligible &&
      !level.database().flags(id, 2U)->srm && !level.database().flags(id, 2U)->ssn);
  require(level.admit_circuit({false, 10U}, 128U).status == LevelStatus::capacity);
  require(other.admit_circuit({false, 9U}, 128U).status == LevelStatus::capacity);
  require(level.circuit(2U, 9U, false, true, false, true, observer) == LevelStatus::applied &&
      level.database().flags(id, 2U)->srm);
  require(level.outputs(0U, 7U)->snp.prepare(SnpEmission::complete, contents, false,
      frame, *scratch, now).status == SnpExchangeStatus::pending);
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const lab::LinkHandle link{0U, 1U};
  require(fabric->configure(link, {lab::node(lab::DeviceHandle{0U, 1U}), 0U, 1U},
      {lab::node(lab::DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 100ns, true));
  auto channel = std::make_unique<protocol::PacketChannel<2U, true>>();
  struct Receipt { std::uint64_t epoch{}, ticket{}; bool enqueued{}; };
  const auto queue = [&](SnpTransmission transmission, std::uint64_t epoch) {
    require(channel->try_send({{0U, 1U}, 11U, 0U, epoch, transmission.ticket}, frame));
    const auto borrowed = channel->try_receive();
    require(borrowed.has_value());
    const bool enqueued = fabric->enqueue(link, 0U, *borrowed->frame) == lab::MultiDeviceFabric::DropReason::none;
    require(channel->release(borrowed->handle, enqueued));
    const auto result = channel->try_completion();
    require(result.has_value());
    return Receipt{result->metadata.configuration_generation, result->metadata.transmission_id, result->enqueued};
  };
  const auto admitted_receipt = queue(old, 7U);
  require(admitted_receipt.enqueued && level.outputs(0U, 7U)->snp.complete(
      admitted_receipt.epoch, admitted_receipt.ticket, true, now).accepted);
  // A later reservation still follows the ordinary cancellation/epoch path.
  level.outputs(0U, 7U)->snp.request_complete();
  old = level.outputs(0U, 7U)->snp.prepare(SnpEmission::complete, contents, false,
      frame, *scratch, now);
  require(old.status == SnpExchangeStatus::encoded);
  const auto delayed = queue(old, 7U);
  require(delayed.enqueued);
  require(level.circuit(0U, 7U, false, false, false, false, observer) == LevelStatus::applied &&
      !level.outputs(0U, 7U) && !level.database().flags(id, 0U)->srm);
  require(level.circuit(0U, 7U, false, true, false, true, observer) == LevelStatus::stale_epoch);
  require(level.circuit(0U, 8U, false, true, false, false, observer) == LevelStatus::applied);
  {
    auto output = level.outputs(0U, 8U);
    const auto next = output->snp.prepare(SnpEmission::complete, contents, false, frame, *scratch, now);
    require(next.status == SnpExchangeStatus::encoded && next.ticket != old.ticket);
    require(!output->snp.complete(delayed.epoch, delayed.ticket, delayed.enqueued, now).accepted);
    const auto receipt = queue(next, 8U);
    require(receipt.enqueued && output->snp.complete(receipt.epoch, receipt.ticket, receipt.enqueued, now).accepted);
  }
  const auto missing = wire(1U, 1U, 1200U);
  require(level.receive_lsp(0U, 8U, missing, now, observer).status == LevelStatus::capacity && level.waiting());
  require(level.waiting_deadline() == now + 60s && !other.waiting());
  require(level.receive_lsp(0U, 8U, missing, now + 20s, observer).status == LevelStatus::capacity &&
      level.waiting_deadline() == now + 80s);
  require(events.counts[static_cast<std::size_t>(LevelEventKind::overload_entered)] == 1U);
  require(level.decision_unavailable(now + 30s, observer) && level.waiting_deadline() == now + 80s);
  require(level.receive_lsp(0U, 8U, retained, now + 40s, observer).status == LevelStatus::applied &&
      level.database().flags(id, 0U)->ssn);
  require(!level.service_waiting(now + 79s, true, observer));
  require(!level.service_waiting(now + 80s, false, observer) && level.waiting() && !level.waiting_deadline());
  require(level.service_waiting(now + 81s, true, observer) && !level.waiting());
  now += 81s;
  const auto purge = wire(1U, 9U, 0U);
  require(level.receive_lsp(0U, 8U, purge, now, observer).status == LevelStatus::applied &&
      level.transient_acknowledgements() == 1U && level.database().size() == 1U);
  const auto another = wire(2U, 9U, 0U);
  require(level.receive_lsp(0U, 8U, another, now, observer).status == LevelStatus::capacity && !level.waiting());
  require(level.receive_lsp(1U, 7U, another, now, observer).status == LevelStatus::unsupported_lan_acknowledgement);
  require(level.circuit(0U, 8U, false, false, false, false, observer) == LevelStatus::applied &&
      !level.transient_acknowledgements() && !level.database().flags(id, 0U)->ssn);
  SnpTransmission lan;
  {
    auto output = level.outputs(1U, 7U);
    require(output->snp.prepare(SnpEmission::complete, contents, output->designated,
        frame, *scratch, now).status == SnpExchangeStatus::role_forbidden);
  }
  require(level.circuit(1U, 7U, true, true, true, false, observer) == LevelStatus::applied);
  {
    auto output = level.outputs(1U, 7U);
    lan = output->snp.prepare(SnpEmission::complete, contents, output->designated, frame, *scratch, now);
    require(lan.status == SnpExchangeStatus::encoded);
  }
  require(level.circuit(1U, 7U, true, true, false, false, observer) == LevelStatus::applied);
  require(!level.outputs(1U, 7U)->snp.complete(7U, lan.ticket, true, now).accepted);
  const auto local_purge = wire(0U, 2U, 0U);
  require(level.originate(local_purge, now, OriginPurgeReason::lifetime_expired, observer).status == LevelStatus::invalid_configuration);
  require(level.originate(local_purge, now, OriginPurgeReason::initiated, observer).install == LspInstallResult::installed);
  require(!level.retire_purge(id, now + 1199s, observer) && level.retire_purge(id, now + 1200s, observer));
  require(!level.database().size());
  now += 1200s;
  const auto active = wire(0U, 3U, 1200U);
  require(level.originate(active, now, OriginPurgeReason::none, observer).install == LspInstallResult::installed);
  const auto expired = wire(0U, 3U, 0U);
  require(level.originate(expired, now + 1200s, OriginPurgeReason::lifetime_expired, observer).install == LspInstallResult::installed);
  require(!level.retire_purge(id, now + 1259s, observer) && level.retire_purge(id, now + 1260s, observer));
  const auto near_end = RuntimeClock::time_point::max() - 1s;
  require(other.decision_unavailable(near_end, observer) && other.waiting_deadline() == RuntimeClock::time_point::max());
  require(!other.service_waiting(near_end, true, observer) &&
      other.service_waiting(RuntimeClock::time_point::max(), true, observer));
}
